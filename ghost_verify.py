# This code is written in the export style of PyUIBuilder: https://pyuibuilder.com
# Ghost Verify - a file hash checker for the Ghost Developer Studio ship workflow.
# Pure Python standard library (tkinter + hashlib). No installs, no
# accounts, and no network except the one fetch the user asks for.
#
# Run:  python3 ghost_verify.py [file]            (GUI)
#       python3 ghost_verify.py --info FILE       (JSON profile)
#       python3 ghost_verify.py --check FILE HASH (exit 0 = match)
#       python3 ghost_verify.py --sums FOLDER     (SHA256SUMS text)
#       python3 ghost_verify.py --batch SUMS FOLDER (exit 0 = all match)
#       python3 ghost_verify.py --audit FOLDER URL  (exit 0 = site matches)
#       python3 ghost_verify.py --ledger [N]        (hash-chained history)
# Every APK and package the studio ships carries a SHA-256 in its ship
# note. Drop the file in here, paste the expected hash, get a verdict.

import hashlib
import json
import os
import queue
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.parse
import urllib.request
import zipfile
import zlib
from tkinter import filedialog, messagebox, simpledialog

# GhostUx tokens (same palette as Ghost Browser)
BG = "#121214"
SURFACE = "#242428"
ACCENT = "#6716F3"
ACCENT_SOFT = "#9D6BFF"
TEXT1 = "#F2F2F5"
TEXT2 = "#A7A7B3"
GOOD = "#3FB96B"
GOOD_BG = "#12291A"
BAD = "#E5534B"
BAD_BG = "#331B19"

CHUNK = 1024 * 1024

RECENT_PATH = os.path.join(os.path.expanduser("~"), ".ghost-verify.json")


def load_recent():
    """Recent verified files, most recent first. Display-free."""
    try:
        with open(RECENT_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return [p for p in data.get("recent", []) if isinstance(p, str)][:5]
    except Exception:
        return []


def save_recent(paths):
    try:
        with open(RECENT_PATH, "w", encoding="utf-8") as fh:
            json.dump({"recent": paths[:5]}, fh)
    except Exception:
        pass


LEDGER_PATH = os.path.join(os.path.expanduser("~"), ".ghost-verify.db")


def _ledger_db(path=None):
    db = sqlite3.connect(path or LEDGER_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS entries(
        id INTEGER PRIMARY KEY, ts TEXT, name TEXT, sha256 TEXT,
        size INTEGER, package TEXT, version_name TEXT, version_code TEXT,
        signer TEXT, prev_hash TEXT, entry_hash TEXT)""")
    return db


def _entry_hash(prev, ts, name, sha256, size, package, version_code, signer):
    canon = "|".join([prev or "", ts, name, sha256, str(size),
                      package or "", str(version_code or ""), signer or ""])
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def ledger_add(prof, path=None, ts=None):
    """Record one verified file in the hash-chained ledger.

    Returns (entry_hash, warnings, recorded). Re-verifying a file
    whose name+hash+signer are already recorded is a no-op
    (recorded=False). The one warning that matters: an APK whose
    package was previously seen under a DIFFERENT signer — the
    wrong-keystore build, caught from history. Display-free.
    """
    ts = ts or time.strftime("%Y-%m-%dT%H:%M:%S")
    apk = prof.get("apk") or {}
    name, sha = prof["name"], prof["sha256"]
    package = apk.get("package", "") or ""
    signer = prof.get("signer") or ""
    db = _ledger_db(path)
    try:
        dupe = db.execute(
            "SELECT entry_hash FROM entries WHERE name=? AND sha256=? AND signer=?",
            (name, sha, signer)).fetchone()
        if dupe:
            return dupe[0], [], False
        warnings = []
        if package and signer:
            past = db.execute(
                "SELECT DISTINCT signer FROM entries WHERE package=? AND signer<>''",
                (package,)).fetchall()
            past_signers = {r[0] for r in past}
            if past_signers and signer not in past_signers:
                warnings.append(
                    f"signer changed for {package}: history has "
                    f"{sorted(past_signers)[0][:16]}…, this file has {signer[:16]}…")
        row = db.execute("SELECT entry_hash FROM entries ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else ""
        eh = _entry_hash(prev, ts, name, sha, prof["size"], package,
                         apk.get("version_code", ""), signer)
        db.execute(
            "INSERT INTO entries(ts,name,sha256,size,package,version_name,"
            "version_code,signer,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, name, sha, prof["size"], package, apk.get("version_name", ""),
             str(apk.get("version_code", "")), signer, prev, eh))
        db.commit()
        return eh, warnings, True
    finally:
        db.close()


def ledger_verify_chain(path=None):
    """Recompute the whole chain. Returns (ok, entries, bad_id)."""
    db = _ledger_db(path)
    try:
        rows = db.execute(
            "SELECT id,ts,name,sha256,size,package,version_code,signer,"
            "prev_hash,entry_hash FROM entries ORDER BY id").fetchall()
        prev = ""
        for r in rows:
            if r[8] != prev:
                return False, len(rows), r[0]
            if _entry_hash(r[8], r[1], r[2], r[3], r[4], r[5], r[6], r[7]) != r[9]:
                return False, len(rows), r[0]
            prev = r[9]
        return True, len(rows), None
    finally:
        db.close()


def ledger_recent(limit=50, path=None):
    db = _ledger_db(path)
    try:
        return db.execute(
            "SELECT ts,name,sha256,size,package,version_name,version_code,signer "
            "FROM entries ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        db.close()


def icon_png_bytes(size=48):
    """A tiny studio ghost, drawn pixel by pixel: a white ghost with
    two violet eyes on the GhostUx background. Original mark, drawn
    for this app. Returns PNG bytes. Display-free."""
    bgc = (0x12, 0x12, 0x14)
    body = (0xF2, 0xF2, 0xF5)
    eye = (0x67, 0x16, 0xF3)
    rows = []
    cx = size / 2.0
    for y in range(size):
        row = bytearray()
        row.append(0)  # PNG filter: none
        for x in range(size):
            px = bgc
            in_x = size * 0.28 < x < size * 0.72
            head = in_x and y > size * 0.22 and ((x - cx) ** 2 + (y - size * 0.42) ** 2) < (size * 0.21) ** 2
            torso = in_x and size * 0.38 < y < size * 0.74
            foot_wave = in_x and size * 0.74 <= y < size * 0.82 and ((x // max(size // 8, 1)) % 2 == 0)
            if head or torso or foot_wave:
                px = body
                for ex in (cx - size * 0.09, cx + size * 0.09):
                    if (x - ex) ** 2 + (y - size * 0.42) ** 2 < (size * 0.045) ** 2:
                        px = eye
            row += bytes(px)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def hash_file(path, progress=None):
    """Return (sha256_hex, sha512_hex, md5_hex, size_bytes) for a file.

    All three hashes come from a single read pass. progress, if given,
    is called with a 0..1 fraction as the file is read. Kept
    display-free on purpose so it can be tested headlessly.
    """
    sha = hashlib.sha256()
    sha512 = hashlib.sha512()
    md5 = hashlib.md5()
    size = os.path.getsize(path)
    done = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            sha.update(block)
            sha512.update(block)
            md5.update(block)
            done += len(block)
            if progress is not None and size:
                progress(done / size)
    return sha.hexdigest(), sha512.hexdigest(), md5.hexdigest(), size


def parse_sums(text):
    """Parse sha256sum-format lines into (filename, hex) pairs.

    Handles the standard forms: '<hash>  <name>' and '<hash> *<name>'
    (the * marks binary mode). Blank lines and # comments are skipped.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            continue
        name = parts[1].lstrip("*").strip()
        out.append((name, parts[0].lower()))
    return out


# ------------------------------------------------------------ APK inspection
# An APK's AndroidManifest.xml is binary XML (AXML). This is a small
# read-only parser for just the fields a ship check needs: package,
# versionName, versionCode, min/target SDK. Pure stdlib, display-free.

def _read_pool(data, off):
    count, _style_count, flags, strings_start = struct.unpack_from("<IIII", data, off + 8)
    utf8 = bool(flags & 0x100)
    base = off + strings_start
    out = []
    for i in range(count):
        rel = struct.unpack_from("<I", data, off + 28 + i * 4)[0]
        pos = base + rel
        if utf8:
            n = data[pos]
            pos += 1
            if n & 0x80:
                pos += 1
            blen = data[pos]
            pos += 1
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | data[pos]
                pos += 1
            out.append(data[pos:pos + blen].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if n & 0x8000:
                n2 = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                n = ((n & 0x7FFF) << 16) | n2
            out.append(data[pos:pos + n * 2].decode("utf-16-le", "replace"))
    return out


def apk_info(path):
    """Return {package, version_name, version_code, min_sdk, target_sdk}
    for an APK, or None if the file is not a readable APK."""
    try:
        with zipfile.ZipFile(path) as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return None
            data = zf.read("AndroidManifest.xml")
        if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
            return None
        pool = None
        info = {}
        off = 8
        while off + 8 <= len(data):
            ctype, _hsize, csize = struct.unpack_from("<HHI", data, off)
            if csize <= 0:
                break
            if ctype == 0x0001:  # string pool
                pool = _read_pool(data, off)
            elif ctype == 0x0102 and pool is not None:  # start element
                name_idx = struct.unpack_from("<I", data, off + 20)[0]
                elem = pool[name_idx] if name_idx < len(pool) else ""
                attr_start, _attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
                attrs_at = off + 16 + attr_start
                attrs = {}
                for a in range(attr_count):
                    ao = attrs_at + a * 20
                    if ao + 20 > len(data):
                        break
                    _ns, aname_idx, raw_idx = struct.unpack_from("<III", data, ao)
                    dtype = data[ao + 15]
                    avalue = struct.unpack_from("<I", data, ao + 16)[0]
                    aname = pool[aname_idx] if aname_idx < len(pool) else ""
                    if raw_idx != 0xFFFFFFFF and raw_idx < len(pool):
                        attrs[aname] = pool[raw_idx]
                    elif dtype == 0x03 and avalue < len(pool):  # STRING
                        attrs[aname] = pool[avalue]
                    elif dtype == 0x10:  # INT_DEC
                        attrs[aname] = avalue
                    elif dtype == 0x12:  # BOOLEAN
                        attrs[aname] = bool(avalue)
                if elem == "manifest":
                    info["package"] = attrs.get("package", "")
                    info["version_name"] = str(attrs.get("versionName", ""))
                    info["version_code"] = attrs.get("versionCode", "")
                elif elem == "uses-sdk":
                    info["min_sdk"] = attrs.get("minSdkVersion", "")
                    info["target_sdk"] = attrs.get("targetSdkVersion", "")
                elif elem == "uses-permission":
                    info.setdefault("permissions", []).append(str(attrs.get("name", "")))
                if "package" in info and "min_sdk" in info and elem == "application":
                    break
            off += csize
        return info if "package" in info else None
    except Exception:
        return None


def _lp(data, off):
    """Read one uint32-length-prefixed field; return (bytes, next_off)."""
    n = struct.unpack_from("<I", data, off)[0]
    return data[off + 4:off + 4 + n], off + 4 + n


def signer_fingerprint(path):
    """SHA-256 of the APK's signer certificate, from the APK Signing
    Block (v2, or v3 if v2 is absent). None when there is no signing
    block to read. Display-free; checked against apksigner in tests.
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
        # End of central directory: scan the tail for the EOCD record.
        tail = blob[-65558:]
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd < 0:
            return None
        cd_off = struct.unpack_from("<I", tail, eocd + 16)[0]
        # Signing block footer sits right before the central directory.
        if blob[cd_off - 16:cd_off] != b"APK Sig Block 42":
            return None
        block_size = struct.unpack_from("<Q", blob, cd_off - 24)[0]
        start = cd_off - block_size - 8
        if struct.unpack_from("<Q", blob, start)[0] != block_size:
            return None
        end = cd_off - 24
        blocks = {}
        off = start + 8
        while off + 12 <= end:
            plen = struct.unpack_from("<Q", blob, off)[0]
            pid = struct.unpack_from("<I", blob, off + 8)[0]
            blocks[pid] = blob[off + 12:off + 8 + plen]
            off += 8 + plen
        value = blocks.get(0x7109871a) or blocks.get(0xF05368C0)  # v2, else v3
        if value is None:
            return None
        signers, _ = _lp(value, 0)
        signer, _ = _lp(signers, 0)
        signed_data, rest = _lp(signer, 0)
        _digests, rest2 = _lp(signed_data, 0)
        certs, _ = _lp(signed_data, rest2)
        cert, _ = _lp(certs, 0)
        return hashlib.sha256(cert).hexdigest()
    except Exception:
        return None


def apk_contents(path):
    """What's inside the APK: entry count, dex files, native ABIs,
    uncompressed total, and the entry names. Display-free."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
        names = [i.filename for i in infos]
        abis = sorted({n.split("/")[1] for n in names
                       if n.startswith("lib/") and n.count("/") >= 2})
        return {"entries": len(names),
                "dex": sorted(n for n in names if n.endswith(".dex")),
                "abis": abis,
                "uncompressed": sum(i.file_size for i in infos),
                "files": names}
    except Exception:
        return None


def file_profile(path):
    """Everything Ghost Verify knows about one file, in one dict."""
    sha, sha512, md5, size = hash_file(path)
    prof = {"path": path, "name": os.path.basename(path), "sha256": sha,
            "sha512": sha512, "md5": md5, "size": size,
            "apk": apk_info(path), "signer": None}
    if prof["apk"]:
        prof["signer"] = signer_fingerprint(path)
        prof["apk"]["signer"] = prof["signer"] or ""
    return prof


def compare_profiles(old, new):
    """Release-over-release verdicts between two file_profiles.

    Display-free. Keys: package_match, version (old/new name+code),
    direction ('upgrade' | 'same' | 'downgrade' | 'unknown'),
    signer ('same' | 'different' | 'unknown'), perms_added,
    perms_removed, size_delta.
    """
    oa, na = old.get("apk"), new.get("apk")
    out = {"size_delta": new["size"] - old["size"],
           "perms_added": [], "perms_removed": []}
    if not oa or not na:
        out.update({"package_match": None, "direction": "unknown",
                    "signer": "unknown", "version": None})
        return out
    out["package_match"] = oa.get("package") == na.get("package")
    out["version"] = (oa.get("version_name", ""), oa.get("version_code", ""),
                      na.get("version_name", ""), na.get("version_code", ""))
    try:
        oc, nc = int(oa["version_code"]), int(na["version_code"])
        out["direction"] = "upgrade" if nc > oc else ("same" if nc == oc else "downgrade")
    except (TypeError, ValueError):
        out["direction"] = "unknown"
    if old.get("signer") and new.get("signer"):
        out["signer"] = "same" if old["signer"] == new["signer"] else "different"
    else:
        out["signer"] = "unknown"
    op = set(oa.get("permissions", []))
    np_ = set(na.get("permissions", []))
    out["perms_added"] = sorted(np_ - op)
    out["perms_removed"] = sorted(op - np_)
    return out


def fetch_to_temp(url, progress=None, cap=200 * 1024 * 1024):
    """Download url to a temp file and return its path.

    The one network action in the tool, and it only happens when the
    user pastes a URL and asks. Plain GET, no cookies, no auth.
    Display-free.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "GhostVerify/2.0"})
    fd, path = tempfile.mkstemp(prefix="ghostverify-", suffix=".bin")
    done = 0
    with urllib.request.urlopen(req, timeout=30) as resp, os.fdopen(fd, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        while True:
            block = resp.read(256 * 1024)
            if not block:
                break
            done += len(block)
            if done > cap:
                out.close()
                os.unlink(path)
                raise ValueError("remote file is larger than the 200 MB cap")
            out.write(block)
            if progress is not None and total:
                progress(done / total)
    return path


def release_report(folder):
    """Audit a release folder in one pass. Display-free.

    Returns (text, summary): verifies the folder's SHA256SUMS when
    one is present, profiles every top-level APK, and checks that
    all APKs share one signer (a folder shipping two signers is a
    folder whose builds cannot all install over each other).
    """
    lines = [f"Release report — {folder}", ""]
    summary = {"sums": None, "apks": [], "signers": set(), "problems": 0}

    sums_path = None
    for cand in ("SHA256SUMS", "SHA256SUMS.txt", "sha256sums.txt"):
        if os.path.isfile(os.path.join(folder, cand)):
            sums_path = os.path.join(folder, cand)
            break
    if sums_path:
        with open(sums_path, "r", encoding="utf-8", errors="replace") as fh:
            entries = parse_sums(fh.read())
        # A sums file sometimes lists itself (it was sitting in the
        # folder when the sums were generated). Its own entry can
        # never verify — writing the file changes it — so it is not
        # a finding; drop it.
        entries = [(n, h) for n, h in entries
                   if n != os.path.basename(sums_path)]
        results = verify_batch(folder, entries)
        counts = {"match": 0, "differ": 0, "missing": 0}
        for _n, s in results:
            counts[s] += 1
        summary["sums"] = counts
        summary["problems"] += counts["differ"] + counts["missing"]
        lines.append(f"SHA256SUMS ({os.path.basename(sums_path)}): "
                     f"{counts['match']} match · {counts['differ']} differ · "
                     f"{counts['missing']} missing (of {len(results)})")
        for name, status in results:
            if status != "match":
                lines.append(f"  ! {status.upper()}: {name}")
    else:
        lines.append("SHA256SUMS: none found in this folder")
    lines.append("")

    apk_names = sorted(f for f in os.listdir(folder)
                       if f.lower().endswith(".apk")
                       and os.path.isfile(os.path.join(folder, f)))
    for name in apk_names:
        prof = file_profile(os.path.join(folder, name))
        summary["apks"].append(prof)
        if prof["signer"]:
            summary["signers"].add(prof["signer"])
        a = prof["apk"] or {}
        lines.append(f"{name}")
        lines.append(f"  {a.get('package', '?')} v{a.get('version_name', '?')} "
                     f"(code {a.get('version_code', '?')}) · "
                     f"{len(a.get('permissions', []))} permissions · "
                     f"{prof['size']:,} bytes")
        lines.append(f"  SHA-256 {prof['sha256']}")
        lines.append(f"  Signer  {prof['signer'] or 'no v2/v3 signing block found'}")
    if not apk_names:
        lines.append("APKs: none found in this folder")
    lines.append("")

    if len(summary["signers"]) > 1:
        summary["problems"] += 1
        lines.append(f"Signer consistency: INCONSISTENT — {len(summary['signers'])} "
                     "different signers across the APKs. These builds cannot all "
                     "install over each other.")
    elif len(summary["signers"]) == 1:
        lines.append(f"Signer consistency: one signer across all APKs "
                     f"({next(iter(summary['signers']))[:16]}…)")
    lines.append("")
    lines.append("Verdict: " + ("READY — no problems found" if summary["problems"] == 0
                                 else f"{summary['problems']} problem(s) to look at"))
    return "\n".join(lines) + "\n", summary


def site_audit(folder, base_url, progress=None):
    """Compare every top-level file in folder with the copy published
    at base_url/<name>. Returns (text, summary) in release_report's
    shape. The audit covers what the folder holds; a static site
    cannot list files that are published but not present locally,
    and the report says so. Display-free."""
    base = base_url.rstrip("/") + "/"
    names = sorted(f for f in os.listdir(folder)
                   if os.path.isfile(os.path.join(folder, f)))
    lines = [f"Site audit — {folder}  vs  {base}", ""]
    counts = {"match": 0, "differ": 0, "missing": 0}
    total = max(len(names), 1)
    for i, name in enumerate(names):
        local_sha, _5, _m, _s = hash_file(os.path.join(folder, name))
        url = base + urllib.parse.quote(name)
        try:
            remote_path = fetch_to_temp(url)
            remote_sha, _5, _m, _s = hash_file(remote_path)
            os.unlink(remote_path)
            status = "match" if remote_sha == local_sha else "differ"
        except Exception:
            status = "missing"
        counts[status] += 1
        mark = {"match": "✓ MATCH  ", "differ": "✗ DIFFER ", "missing": "? NOT FOUND"}[status]
        lines.append(f"{mark} {name}")
        if progress is not None:
            progress((i + 1) / total)
    problems = counts["differ"] + counts["missing"]
    if not names:
        problems = 1
        lines.append("The folder holds no files — nothing was audited.")
    lines += ["",
              f"{counts['match']} match · {counts['differ']} differ · "
              f"{counts['missing']} not found (of {len(names)})",
              "Note: files published at the site but absent from this "
              "folder cannot be listed by a static host; the audit "
              "covers what the folder holds.",
              "",
              "Verdict: " + ("READY — the site serves exactly this folder"
                             if problems == 0 else
                             f"{problems} problem(s) to look at")]
    summary = {"sums": None, "apks": [], "signers": set(), "problems": problems}
    return "\n".join(lines) + "\n", summary


def generate_sums(folder, progress=None, exclude=None):
    """Build sha256sum-format text for every file directly in folder
    (top level only, sorted by name). `exclude` names one file to
    skip — the sums file itself when it is being written into the
    same folder, since a sums file can never contain its own hash.
    Display-free."""
    names = sorted(f for f in os.listdir(folder)
                   if os.path.isfile(os.path.join(folder, f)) and f != exclude)
    lines = []
    for i, name in enumerate(names):
        sha, _s512, _md5, _size = hash_file(os.path.join(folder, name))
        lines.append(f"{sha}  {name}")
        if progress is not None:
            progress((i + 1) / max(len(names), 1))
    return ("\n".join(lines) + "\n") if lines else ""


def verify_batch(folder, entries, progress=None):
    """Check every (filename, expected_sha256) against folder.

    Returns a list of (filename, status) where status is 'match',
    'differ', or 'missing'. Display-free; tested headlessly.
    """
    results = []
    total = max(len(entries), 1)
    for i, (name, expected) in enumerate(entries):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            results.append((name, "missing"))
        else:
            sha, _s512, _md5, _size = hash_file(path)
            results.append((name, "match" if sha == expected else "differ"))
        if progress is not None:
            progress((i + 1) / total)
    return results


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n / 1:.1f} {unit}".replace(".0", "")
        n /= 1024.0
    return f"{n} GB"


class GhostVerify(tk.Tk):
    def __init__(self, start_file=""):
        super().__init__()
        self.title("Ghost Verify 2.0 - file hash checker")
        self.geometry("660x760")
        self.minsize(580, 660)
        self.configure(bg=BG)
        try:
            self._icon = tk.PhotoImage(data=icon_png_bytes())
            self.iconphoto(True, self._icon)
        except Exception:
            pass
        self.recent = load_recent()

        self.file_var = tk.StringVar(value=start_file)
        self.expected_var = tk.StringVar()
        self.sha_var = tk.StringVar(value="-")
        self.sha512_var = tk.StringVar(value="-")
        self.md5_var = tk.StringVar(value="-")
        self.size_var = tk.StringVar(value="-")
        self.status_var = tk.StringVar(value="Pick a file to begin.")
        self.verdict_var = tk.StringVar(value="")
        self.expected_var.trace_add("write", lambda *_: self.check_verdict())

        # The hash worker never touches Tk directly (Tk is not
        # thread-safe); it posts events here and the main loop applies
        # them. Poll on a timer.
        self.events = queue.Queue()
        self.build_widgets()
        self.bind_all("<Control-o>", lambda _e: self.browse())
        self.bind_all("<Control-O>", lambda _e: self.browse())
        self.bind_all("<F5>", lambda _e: self.verify())
        self.bind_all("<Control-l>", lambda _e: self.show_session_log())
        self.bind_all("<Control-L>", lambda _e: self.show_session_log())
        self.after(60, self.poll_events)
        if start_file:
            self.after(150, self.verify)

    def poll_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    self.status_var.set(f"Hashing... {int(payload * 100)}%")
                    self.set_progress(payload)
                elif kind == "done":
                    sha, sha512, md5, size = payload
                    self.set_progress(None)
                    self.show_result(sha, sha512, md5, size)
                elif kind == "batch_progress":
                    if getattr(self, "batch_status", None) is not None:
                        self.batch_status.set(f"Checking... {int(payload * 100)}%")
                elif kind == "batch_done":
                    self.show_batch_results(payload)
                elif kind == "sums_progress":
                    self.status_var.set(f"Hashing files for SHA256SUMS... {int(payload * 100)}%")
                    self.set_progress(payload)
                elif kind == "sums_done":
                    dest, count = payload
                    self.set_progress(None)
                    self.status_var.set(f"Wrote {count} entries to {dest}")
                elif kind == "compare_done":
                    self.show_compare(payload[0], payload[1])
                elif kind == "report_done":
                    self.show_report(payload[0], payload[1])
                elif kind == "audit_done":
                    self.set_progress(None)
                    self.show_report(payload[0], payload[1])
                elif kind == "audit_progress":
                    self.set_progress(payload)
                elif kind == "fetch_progress":
                    self.status_var.set(f"Fetching... {int(payload * 100)}%")
                    self.set_progress(payload)
                elif kind == "fetch_done":
                    self.set_progress(None)
                    self.show_fetch_result(payload[0], payload[1], payload[2])
                elif kind == "error":
                    self.set_progress(None)
                    messagebox.showerror("Ghost Verify", payload)
                    self.status_var.set("Failed.")
        except queue.Empty:
            pass
        self.after(60, self.poll_events)

    # ------------------------------------------------------------ layout
    def build_widgets(self):
        pad = {"padx": 14}

        tk.Frame(self, bg=ACCENT, height=4).pack(fill="x")
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", pady=(12, 0), **pad)
        tk.Label(header, text="GHOST VERIFY", bg=BG, fg=TEXT1,
                 font=("Helvetica", 17, "bold")).pack(side="left")
        tk.Label(header, text=" 2.0 ", bg=ACCENT, fg="white",
                 font=("Helvetica", 9, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(header, text="Ghost Developer Studio", bg=BG, fg=TEXT2,
                 font=("Helvetica", 9)).pack(side="right")
        sub = tk.Label(self, text="Hash a file. Paste the expected hash. Get a verdict.  "
                                  "Shortcuts: Ctrl+O open · F5 re-verify · Ctrl+L log",
                       bg=BG, fg=TEXT2, font=("Helvetica", 9))
        sub.pack(anchor="w", pady=(2, 10), **pad)

        file_frame = tk.Frame(self, bg=BG)
        file_frame.pack(fill="x", **pad)
        entry = tk.Entry(file_frame, textvariable=self.file_var, bg=SURFACE,
                         fg=TEXT1, insertbackground=TEXT1, relief="flat",
                         font=("Courier", 10))
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        entry.bind("<Return>", lambda _e: self.verify())
        browse = tk.Button(file_frame, text="Browse", command=self.browse,
                           bg=ACCENT, fg="white", activebackground=ACCENT_SOFT,
                           relief="flat", font=("Helvetica", 10, "bold"), padx=12)
        browse.pack(side="left", padx=(8, 0))

        self.recent_frame = tk.Frame(self, bg=BG)
        self.recent_frame.pack(fill="x", pady=(6, 0), **pad)
        self.refresh_recent()

        verify_btn = tk.Button(self, text="VERIFY FILE", command=self.verify,
                               bg=ACCENT, fg="white", activebackground=ACCENT_SOFT,
                               relief="flat", font=("Helvetica", 11, "bold"), pady=6)
        verify_btn.pack(fill="x", pady=(12, 4), **pad)

        self.status = tk.Label(self, textvariable=self.status_var, bg=BG,
                               fg=TEXT2, font=("Helvetica", 9))
        self.status.pack(anchor="w", **pad)

        self.progress_outer = tk.Frame(self, bg=SURFACE, height=4)
        self.progress_outer.pack(fill="x", pady=(4, 0), **pad)
        self.progress_outer.pack_propagate(False)
        self.progress_inner = tk.Frame(self.progress_outer, bg=ACCENT)
        self.progress_inner.place(x=0, y=0, relheight=1.0, relwidth=0.0)

        results = tk.Frame(self, bg=SURFACE)
        results.pack(fill="x", pady=(10, 0), **pad)
        self.results_frame = results
        self.result_row(results, "SHA-256", self.sha_var, 0)
        self.result_row(results, "SHA-512", self.sha512_var, 1)
        self.result_row(results, "MD5", self.md5_var, 2)
        self.result_row(results, "Size", self.size_var, 3)

        # APK details appear only when the verified file is an APK.
        self.apk_pkg = tk.StringVar(value="")
        self.apk_ver = tk.StringVar(value="")
        self.apk_code = tk.StringVar(value="")
        self.apk_sdk = tk.StringVar(value="")
        self.apk_signer = tk.StringVar(value="")
        self.apk_perms = tk.StringVar(value="")
        self.current_apk = None
        apkf = tk.Frame(self, bg=SURFACE)
        self.apk_frame = apkf
        self.result_row(apkf, "Package", self.apk_pkg, 0)
        self.result_row(apkf, "Version", self.apk_ver, 1)
        self.result_row(apkf, "Code", self.apk_code, 2)
        self.result_row(apkf, "SDK", self.apk_sdk, 3)
        self.result_row(apkf, "Signer", self.apk_signer, 4)
        tk.Label(apkf, text="Perms", bg=SURFACE, fg=TEXT2,
                 font=("Helvetica", 10, "bold"), width=9, anchor="w") \
            .grid(row=5, column=0, padx=10, pady=5, sticky="w")
        tk.Label(apkf, textvariable=self.apk_perms, bg=SURFACE, fg=TEXT1,
                 font=("Courier", 9), anchor="w") \
            .grid(row=5, column=1, sticky="w")
        tk.Button(apkf, text="View", bg=BG, fg=TEXT2, relief="flat",
                  font=("Helvetica", 8), command=self.show_permissions) \
            .grid(row=5, column=2, padx=8)
        self.apk_files = tk.StringVar(value="")
        self.current_contents = None
        tk.Label(apkf, text="Files", bg=SURFACE, fg=TEXT2,
                 font=("Helvetica", 10, "bold"), width=9, anchor="w") \
            .grid(row=6, column=0, padx=10, pady=5, sticky="w")
        tk.Label(apkf, textvariable=self.apk_files, bg=SURFACE, fg=TEXT1,
                 font=("Courier", 9), anchor="w") \
            .grid(row=6, column=1, sticky="w")
        tk.Button(apkf, text="View", bg=BG, fg=TEXT2, relief="flat",
                  font=("Helvetica", 8), command=self.show_contents) \
            .grid(row=6, column=2, padx=8)

        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", pady=(10, 0), **pad)
        tk.Button(actions, text="Ship note", command=self.copy_ship_note,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left")
        tk.Button(actions, text="Batch verify",
                  command=self.start_batch,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))
        tk.Button(actions, text="Generate sums",
                  command=self.start_generate_sums,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))
        tk.Button(actions, text="Compare files",
                  command=self.start_compare,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))
        tk.Button(actions, text="Release report",
                  command=self.start_report,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))

        self.session_log = []
        self._logged_verdicts = set()
        actions2 = tk.Frame(self, bg=BG)
        actions2.pack(fill="x", pady=(8, 0), **pad)
        tk.Button(actions2, text="Fetch & compare URL",
                  command=self.start_fetch,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left")
        tk.Button(actions2, text="Paste hash",
                  command=self.paste_hash,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))
        tk.Button(actions2, text="Session log",
                  command=self.show_session_log,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))
        self.watch = None
        self.watch_btn = tk.Button(actions2, text="Watch folder",
                                   command=self.toggle_watch,
                                   bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                                   relief="flat", font=("Helvetica", 10), padx=10, pady=4)
        self.watch_btn.pack(side="left", padx=(8, 0))

        actions3 = tk.Frame(self, bg=BG)
        actions3.pack(fill="x", pady=(8, 0), **pad)
        tk.Button(actions3, text="Site audit",
                  command=self.start_audit,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left")
        tk.Button(actions3, text="Ledger",
                  command=self.show_ledger,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left", padx=(8, 0))

        exp_label = tk.Label(self, text="Expected SHA-256 (from the ship note):",
                             bg=BG, fg=TEXT2, font=("Helvetica", 10))
        exp_label.pack(anchor="w", pady=(14, 4), **pad)
        expected = tk.Entry(self, textvariable=self.expected_var, bg=SURFACE,
                            fg=TEXT1, insertbackground=TEXT1, relief="flat",
                            font=("Courier", 10))
        expected.pack(fill="x", ipady=6, **pad)

        self.banner = tk.Frame(self, bg=SURFACE)
        self.banner.pack(fill="x", pady=(12, 0), **pad)
        self.verdict = tk.Label(self.banner, textvariable=self.verdict_var,
                                bg=SURFACE, fg=TEXT2,
                                font=("Helvetica", 13, "bold"), anchor="w")
        self.verdict.pack(fill="x", padx=12, pady=9)

    def result_row(self, parent, label, var, row):
        tk.Label(parent, text=label, bg=SURFACE, fg=TEXT2,
                 font=("Helvetica", 10, "bold"), width=9, anchor="w") \
            .grid(row=row, column=0, padx=10, pady=5, sticky="w")
        tk.Label(parent, textvariable=var, bg=SURFACE, fg=TEXT1,
                 font=("Courier", 9), anchor="w", wraplength=480, justify="left") \
            .grid(row=row, column=1, sticky="w")
        tk.Button(parent, text="Copy", bg=BG, fg=TEXT2, relief="flat",
                  font=("Helvetica", 8),
                  command=lambda v=var: self.copy(v.get())) \
            .grid(row=row, column=2, padx=8)

    # ------------------------------------------------------------ UI helpers
    def set_progress(self, frac):
        if frac is None:
            self.progress_inner.place_configure(relwidth=0.0)
        else:
            self.progress_inner.place_configure(relwidth=max(0.0, min(frac, 1.0)))

    def set_banner(self, text, kind="neutral"):
        """kind: 'good' | 'bad' | 'neutral'. The verdict banner is the
        window's anchor: green tint for a match, red for a mismatch."""
        self.verdict_var.set(text)
        bg = {"good": GOOD_BG, "bad": BAD_BG}.get(kind, SURFACE)
        fg = {"good": GOOD, "bad": "#FF8A80"}.get(kind, TEXT2)
        self.banner.configure(bg=bg)
        self.verdict.configure(bg=bg, fg=fg)

    def refresh_recent(self):
        for child in self.recent_frame.winfo_children():
            child.destroy()
        existing = [p for p in self.recent if os.path.isfile(p)]
        if not existing:
            return
        tk.Label(self.recent_frame, text="Recent:", bg=BG, fg=TEXT2,
                 font=("Helvetica", 9)).pack(side="left")
        for path in existing:
            tk.Button(self.recent_frame, text=os.path.basename(path),
                      command=lambda p=path: self.open_recent(p),
                      bg=BG, fg=ACCENT_SOFT, activebackground=SURFACE,
                      relief="flat", font=("Helvetica", 9), padx=4) \
                .pack(side="left")

    def open_recent(self, path):
        self.file_var.set(path)
        self.verify()

    def add_recent(self, path):
        if not path or not os.path.isfile(path):
            return
        if os.path.basename(path).startswith("ghostverify-"):
            return  # fetched temp copies are not recents
        if path in self.recent:
            self.recent.remove(path)
        self.recent.insert(0, path)
        self.recent = self.recent[:5]
        save_recent(self.recent)
        self.refresh_recent()

    # ------------------------------------------------------------ actions
    def browse(self):
        path = filedialog.askopenfilename(title="Choose a file to verify")
        if path:
            self.file_var.set(path)
            self.verify()

    def copy(self, text):
        if text and text != "-":
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_var.set("Copied to clipboard.")

    def verify(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showwarning("Ghost Verify", "Pick a file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Ghost Verify", f"Not a file: {path}")
            return
        self.status_var.set("Hashing...")
        self.set_banner("")

        def work():
            try:
                result = hash_file(
                    path, progress=lambda f: self.events.put(("progress", f)))
                self.events.put(("done", result))
            except Exception as exc:  # unreadable file, permissions, ...
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def log_event(self, text):
        stamp = time.strftime("%H:%M:%S")
        self.session_log.append(f"[{stamp}] {text}")

    def show_result(self, sha, sha512, md5, size):
        self.sha_var.set(sha)
        self.sha512_var.set(sha512)
        self.md5_var.set(md5)
        self.size_var.set(f"{size:,} bytes ({human_size(size)})")
        self.status_var.set("Done.")
        if getattr(self, "_watch_note", None):
            self.status_var.set(f"Watch: {self._watch_note} arrived and was verified.")
            self._watch_note = None
        self.log_event(f"verified {os.path.basename(self.file_var.get().strip())}"
                       f" - {size:,} bytes - sha256 {sha}")
        self.add_recent(self.file_var.get().strip())
        self.current_apk = apk_info(self.file_var.get().strip())
        if self.current_apk:
            a = self.current_apk
            self.apk_pkg.set(a.get("package", ""))
            self.apk_ver.set(a.get("version_name", ""))
            self.apk_code.set(str(a.get("version_code", "")))
            self.apk_sdk.set(f"min {a.get('min_sdk', '?')} · target {a.get('target_sdk', '?')}")
            fp = signer_fingerprint(self.file_var.get().strip())
            a["signer"] = fp or ""
            self.apk_signer.set(fp if fp else "no v2/v3 signing block found")
            perms = a.get("permissions", [])
            self.apk_perms.set(f"{len(perms)} permission" + ("" if len(perms) == 1 else "s"))
            self.current_contents = apk_contents(self.file_var.get().strip())
            if self.current_contents:
                c = self.current_contents
                abi_txt = ", ".join(c["abis"]) if c["abis"] else "no native libs"
                self.apk_files.set(f"{c['entries']} entries · {len(c['dex'])} dex · {abi_txt}")
            else:
                self.apk_files.set("")
            self.apk_frame.pack(fill="x", pady=(10, 0), padx=14, after=self.results_frame)
        else:
            self.current_contents = None
            self.apk_frame.pack_forget()
        self.check_verdict()
        # Record in the hash-chained ledger (fetched temp copies are
        # already covered by the fetch log lines; skip them here).
        base = os.path.basename(self.file_var.get().strip())
        if not base.startswith("ghostverify-"):
            prof = {"name": base, "sha256": sha, "size": size,
                    "apk": self.current_apk,
                    "signer": (self.current_apk or {}).get("signer") or None}
            try:
                _eh, warnings, recorded = ledger_add(prof)
                if recorded:
                    self.log_event(f"ledger: recorded {base}")
                for w in warnings:
                    self.log_event(f"ledger WARNING: {w}")
                    self.status_var.set("⚠ " + w)
                    if not self.expected_var.get().strip():
                        self.set_banner("⚠  " + w, "bad")
            except Exception:
                pass  # the ledger must never break a verification

    def show_contents(self):
        if not self.current_contents:
            return
        c = self.current_contents
        win = tk.Toplevel(self)
        win.title("Ghost Verify - APK contents")
        win.geometry("560x420")
        win.configure(bg=BG)
        tk.Label(win, text=f"{c['entries']} entries · {len(c['dex'])} dex file(s) · "
                           f"ABIs: {', '.join(c['abis']) if c['abis'] else 'none'} · "
                           f"{c['uncompressed']:,} bytes uncompressed",
                 bg=BG, fg=TEXT1, font=("Helvetica", 10, "bold"), wraplength=520,
                 justify="left").pack(anchor="w", padx=12, pady=(10, 6))
        text = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                       font=("Courier", 9), wrap="none")
        text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        text.insert("1.0", "\n".join(c["files"][:500])
                    + ("\n… (list capped at 500)" if len(c["files"]) > 500 else ""))
        text.configure(state="disabled")

    # ------------------------------------------------------------ watch mode
    def toggle_watch(self):
        if self.watch:
            self.watch = None
            self.watch_btn.configure(text="Watch folder")
            self.status_var.set("Stopped watching.")
            return
        folder = filedialog.askdirectory(
            title="Choose the folder to watch (a build output folder)")
        if folder:
            self.watch_folder(folder)

    def watch_folder(self, folder):
        seen = {}
        try:
            for name in os.listdir(folder):
                p = os.path.join(folder, name)
                if os.path.isfile(p):
                    st = os.stat(p)
                    seen[name] = (st.st_size, st.st_mtime)
        except OSError:
            pass
        self.watch = {"folder": folder, "seen": seen, "candidates": {}}
        self.watch_btn.configure(text="Stop watching")
        self.status_var.set(f"Watching {folder} — new or changed files verify themselves.")
        self.log_event(f"watch started on {folder}")
        self.after(1200, self._watch_tick)

    def _watch_tick(self):
        if not self.watch:
            return
        try:
            folder = self.watch["folder"]
            current = {}
            for name in os.listdir(folder):
                if name.startswith(".") or name.endswith((".tmp", ".part", ".crdownload")):
                    continue
                p = os.path.join(folder, name)
                if os.path.isfile(p):
                    st = os.stat(p)
                    current[name] = (st.st_size, st.st_mtime)
            # State machine: `seen` holds files that are done (the
            # initial snapshot plus everything already fired on).
            # Anything else is a candidate; it fires only when its
            # size+mtime are identical on two further polls, so a
            # file still being copied never gets hashed half-way.
            fired = None
            for name, sig in current.items():
                if self.watch["seen"].get(name) == sig:
                    continue
                prev = self.watch["candidates"].get(name)
                if prev and prev[0] == sig:
                    if prev[1] >= 2:
                        fired = name
                    else:
                        self.watch["candidates"][name] = (sig, prev[1] + 1)
                else:
                    self.watch["candidates"][name] = (sig, 1)
            for name in list(self.watch["candidates"]):
                if name not in current:
                    del self.watch["candidates"][name]
            if fired:
                self.watch["seen"][fired] = current[fired]
                path = os.path.join(folder, fired)
                self.watch["candidates"].pop(fired, None)
                self.log_event(f"watch: {fired} landed in {folder}")
                self._watch_note = fired
                self.file_var.set(path)
                self.verify()
        except Exception:
            pass  # a vanished folder or file must never kill the watcher
        if self.watch:
            self.after(1200, self._watch_tick)

    def show_permissions(self):
        if not self.current_apk:
            return
        perms = self.current_apk.get("permissions", [])
        win = tk.Toplevel(self)
        win.title("Ghost Verify - permissions")
        win.geometry("520x360")
        win.configure(bg=BG)
        tk.Label(win, text=f"{self.current_apk.get('package', '')} requests "
                           f"{len(perms)} permission" + ("" if len(perms) == 1 else "s"),
                 bg=BG, fg=TEXT1, font=("Helvetica", 11, "bold")) \
            .pack(anchor="w", padx=12, pady=(10, 6))
        text = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                       font=("Courier", 10), wrap="none")
        text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        text.insert("1.0", "\n".join(perms) if perms else "(none)")
        text.configure(state="disabled")

    def copy_ship_note(self):
        sha = self.sha_var.get()
        if sha in ("", "-"):
            self.status_var.set("Verify a file first, then copy its ship note.")
            return
        name = os.path.basename(self.file_var.get().strip())
        ver = ""
        if self.current_apk:
            ver = f" v{self.current_apk.get('version_name', '')} (code {self.current_apk.get('version_code', '')})"
        note = f"{name}{ver} - {self.size_var.get()} - SHA-256 {sha}"
        if self.current_apk and self.current_apk.get("signer"):
            note += f"\nSigner SHA-256 {self.current_apk['signer']}"
        self.clipboard_clear()
        self.clipboard_append(note)
        self.status_var.set("Ship note copied: " + note)

    def start_generate_sums(self):
        folder = filedialog.askdirectory(title="Choose the folder to hash")
        if not folder:
            return
        dest = filedialog.asksaveasfilename(
            title="Save the sums file as", initialdir=folder,
            initialfile="SHA256SUMS")
        if not dest:
            return
        self.status_var.set("Hashing files for SHA256SUMS...")

        exclude = (os.path.basename(dest)
                   if os.path.dirname(os.path.abspath(dest)) == os.path.abspath(folder)
                   else None)

        def work():
            try:
                text = generate_sums(
                    folder, progress=lambda f: self.events.put(("sums_progress", f)),
                    exclude=exclude)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(text)
                self.events.put(("sums_done", (dest, text.count("\n"))))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ fetch & log
    def paste_hash(self):
        try:
            text = self.clipboard_get().strip().lower()
        except tk.TclError:
            text = ""
        if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
            self.expected_var.set(text)
            self.status_var.set("Expected hash pasted from clipboard.")
        else:
            self.status_var.set("The clipboard does not hold a SHA-256 hash.")

    def start_fetch(self):
        url = simpledialog.askstring(
            "Fetch & compare",
            "Paste the URL of the published copy (for example the file\n"
            "on the downloads site). It is downloaded to a temp file,\n"
            "hashed, and compared with the file currently loaded.",
            parent=self)
        if not url:
            return
        prev_sha = self.sha_var.get()
        self.status_var.set("Fetching...")

        def work():
            try:
                path = fetch_to_temp(
                    url.strip(),
                    progress=lambda f: self.events.put(("fetch_progress", f)))
                self.events.put(("fetch_done", (file_profile(path), prev_sha, url.strip())))
            except Exception as exc:
                self.events.put(("error", f"Fetch failed: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def show_fetch_result(self, prof, prev_sha, url):
        fetched_sha = prof["sha256"]
        self.file_var.set(prof["path"])
        self.show_result(prof["sha256"], prof["sha512"], prof["md5"], prof["size"])
        if prev_sha and prev_sha != "-":
            if prev_sha == fetched_sha:
                self.set_banner("✓  The published copy MATCHES the local file", "good")
                self.log_event(f"fetched {url} - MATCHES the local file")
            else:
                self.set_banner("✗  The published copy DIFFERS from the local file", "bad")
                self.log_event(f"fetched {url} - DIFFERS from the local file "
                               f"(remote sha256 {fetched_sha})")
        else:
            self.status_var.set("Fetched copy loaded. Verify a local file first to compare next time.")
            self.log_event(f"fetched {url} - sha256 {fetched_sha}")

    def show_session_log(self):
        win = tk.Toplevel(self)
        win.title("Ghost Verify - session log")
        win.geometry("680x400")
        win.configure(bg=BG)
        tk.Label(win, text="Everything verified in this session. Copy it into the release record.",
                 bg=BG, fg=TEXT2, font=("Helvetica", 9)) \
            .pack(anchor="w", padx=12, pady=(10, 6))
        text = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                       font=("Courier", 9), wrap="word")
        text.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        text.insert("1.0", "\n".join(self.session_log) if self.session_log
                    else "(nothing verified yet this session)")
        text.configure(state="disabled")

        def copy_log():
            self.clipboard_clear()
            self.clipboard_append("\n".join(self.session_log))
            self.status_var.set("Session log copied.")

        tk.Button(win, text="Copy log", command=copy_log, bg=ACCENT, fg="white",
                  activebackground=ACCENT_SOFT, relief="flat",
                  font=("Helvetica", 10, "bold"), padx=12, pady=4) \
            .pack(anchor="w", padx=12, pady=(0, 12))

    # ------------------------------------------------------------ release report
    def start_report(self):
        folder = filedialog.askdirectory(
            title="Choose the release folder to audit")
        if not folder:
            return
        self.status_var.set("Auditing the release folder...")

        def work():
            try:
                text, summary = release_report(folder)
                self.events.put(("report_done", (text, summary)))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def show_report(self, text, summary):
        self.status_var.set("Report ready.")
        self.log_event(f"report: {summary['problems']} problem(s), "
                       f"{len(summary['apks'])} APK(s) profiled")
        win = tk.Toplevel(self)
        win.title("Ghost Verify - release report")
        win.geometry("680x460")
        win.configure(bg=BG)
        verdict = ("READY — no problems found" if summary["problems"] == 0
                   else f"{summary['problems']} problem(s) to look at")
        tk.Label(win, text=verdict, bg=BG,
                 fg=GOOD if summary["problems"] == 0 else BAD,
                 font=("Helvetica", 12, "bold")) \
            .pack(anchor="w", padx=12, pady=(12, 6))
        body = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                       font=("Courier", 9), wrap="word")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        body.insert("1.0", text)
        body.configure(state="disabled")

        def copy_report():
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_var.set("Release report copied.")

        tk.Button(win, text="Copy report", command=copy_report, bg=ACCENT,
                  fg="white", activebackground=ACCENT_SOFT, relief="flat",
                  font=("Helvetica", 10, "bold"), padx=12, pady=4) \
            .pack(anchor="w", padx=12, pady=(0, 12))

    # ------------------------------------------------------------ audit & ledger
    def start_audit(self):
        folder = filedialog.askdirectory(
            title="Choose the LOCAL release folder")
        if not folder:
            return
        base = simpledialog.askstring(
            "Site audit",
            "Base URL where this folder is published\n"
            "(for example https://downloads.ghostdeveloperstudio.com/browser/):",
            parent=self)
        if not base:
            return
        self.status_var.set("Auditing the published copies...")

        def work():
            try:
                text, summary = site_audit(
                    folder, base.strip(),
                    progress=lambda f: self.events.put(("audit_progress", f)))
                self.events.put(("audit_done", (text, summary)))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def show_ledger(self):
        ok, count, bad = ledger_verify_chain()
        rows = ledger_recent(50)
        win = tk.Toplevel(self)
        win.title("Ghost Verify - history ledger")
        win.geometry("700x440")
        win.configure(bg=BG)
        chain_txt = (f"Hash chain intact · {count} entries" if ok
                     else f"CHAIN BROKEN at entry {bad} · {count} entries")
        tk.Label(win, text=chain_txt, bg=BG, fg=GOOD if ok else BAD,
                 font=("Helvetica", 11, "bold")).pack(anchor="w", padx=12, pady=(12, 2))
        tk.Label(win, text="Every verified file, remembered. An APK whose package "
                           "appears under a new signer is flagged the moment it is verified.",
                 bg=BG, fg=TEXT2, font=("Helvetica", 9)) \
            .pack(anchor="w", padx=12, pady=(0, 6))
        text = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                       font=("Courier", 9), wrap="none")
        text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        lines = []
        for ts, name, sha, size, package, vn, vc, signer in rows:
            who = f"{package} v{vn} (code {vc})" if package else name
            lines.append(f"{ts}  {who}")
            lines.append(f"    sha {sha[:24]}…  signer {(signer or '—')[:16]}"
                         f"{'…' if signer else ''}  {size:,} bytes")
        text.insert("1.0", "\n".join(lines) if lines else "(ledger is empty)")
        text.configure(state="disabled")

    # ------------------------------------------------------------ compare mode
    def start_compare(self):
        old = filedialog.askopenfilename(
            title="Choose the OLD release (the one already shipped)",
            filetypes=[("Android packages", "*.apk"), ("All files", "*.*")])
        if not old:
            return
        new = filedialog.askopenfilename(
            title="Choose the NEW release (the candidate)",
            filetypes=[("Android packages", "*.apk"), ("All files", "*.*")])
        if not new:
            return
        self.status_var.set("Comparing releases...")

        def work():
            try:
                self.events.put(("compare_done",
                                 (file_profile(old), file_profile(new))))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def show_compare(self, old, new):
        cmp_ = compare_profiles(old, new)
        self.status_var.set("Comparison ready.")
        win = tk.Toplevel(self)
        win.title("Ghost Verify - release comparison")
        win.geometry("640x430")
        win.configure(bg=BG)
        tk.Label(win, text=f"{old['name']}  →  {new['name']}", bg=BG, fg=TEXT1,
                 font=("Helvetica", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))
        body = tk.Frame(win, bg=SURFACE)
        body.pack(fill="x", padx=12)

        def row(r, label, value, color=TEXT1):
            tk.Label(body, text=label, bg=SURFACE, fg=TEXT2,
                     font=("Helvetica", 10, "bold"), width=11, anchor="w") \
                .grid(row=r, column=0, padx=10, pady=5, sticky="w")
            tk.Label(body, text=value, bg=SURFACE, fg=color,
                     font=("Helvetica", 10), anchor="w", wraplength=470,
                     justify="left").grid(row=r, column=1, sticky="w")

        d = cmp_["size_delta"]
        if cmp_["package_match"] is None:
            same = old["sha256"] == new["sha256"]
            row(0, "Files", "IDENTICAL — same SHA-256" if same else "DIFFERENT files",
                GOOD if same else BAD)
            row(1, "Size", f"{old['size']:,}  →  {new['size']:,} bytes  ({'+' if d >= 0 else ''}{d:,})")
            row(2, "SHA (1st)", old["sha256"])
            row(3, "SHA (2nd)", new["sha256"])
        else:
            row(0, "Package",
                new["apk"].get("package", "") + ("  (same)" if cmp_["package_match"] else "  — DIFFERENT from the old release"),
                GOOD if cmp_["package_match"] else BAD)
            if cmp_["version"]:
                on, oc, nn, nc = cmp_["version"]
                arrow = {"upgrade": "▲ upgrade", "same": "= same code — Android will treat this as the same version",
                         "downgrade": "▼ DOWNGRADE — a lower code will not install over the old one",
                         "unknown": "?"}[cmp_["direction"]]
                row(1, "Version", f"v{on} (code {oc})  →  v{nn} (code {nc})   {arrow}",
                    GOOD if cmp_["direction"] == "upgrade" else (TEXT1 if cmp_["direction"] == "same" else BAD))
            signer_txt = {"same": f"SAME signer ({(new.get('signer') or '')[:16]}…) — installs over the old release",
                          "different": "DIFFERENT signer — this build will NOT install over the old one",
                          "unknown": "could not be read on one side"}[cmp_["signer"]]
            row(2, "Signer", signer_txt, GOOD if cmp_["signer"] == "same" else BAD)
            pa, pr = cmp_["perms_added"], cmp_["perms_removed"]
            if pa or pr:
                bits = []
                if pa: bits.append("added: " + ", ".join(p.replace("android.permission.", "") for p in pa))
                if pr: bits.append("removed: " + ", ".join(p.replace("android.permission.", "") for p in pr))
                row(3, "Perms", " · ".join(bits), TEXT1)
            else:
                row(3, "Perms", "unchanged", GOOD)
            row(4, "Size", f"{old['size']:,}  →  {new['size']:,} bytes  ({'+' if d >= 0 else ''}{d:,})")
            row(5, "New SHA", new["sha256"])

        def copy_new_note():
            na = new.get("apk") or {}
            ver = (f" v{na.get('version_name', '')} (code {na.get('version_code', '')})"
                   if na else "")
            note = (f"{new['name']}{ver} - "
                    f"{new['size']:,} bytes - SHA-256 {new['sha256']}")
            if new.get("signer"):
                note += f"\nSigner SHA-256 {new['signer']}"
            self.clipboard_clear()
            self.clipboard_append(note)
            self.status_var.set("New release ship note copied.")

        tk.Button(win, text="Copy ship note for the NEW release",
                  command=copy_new_note, bg=ACCENT, fg="white",
                  activebackground=ACCENT_SOFT, relief="flat",
                  font=("Helvetica", 10, "bold"), padx=12, pady=5) \
            .pack(anchor="w", padx=12, pady=(12, 0))

    # ------------------------------------------------------------ batch mode
    def start_batch(self):
        sums = filedialog.askopenfilename(
            title="Choose the SHA256SUMS file",
            filetypes=[("Sums files", "SHA256SUMS* *.sha256 *.txt"), ("All files", "*.*")])
        if not sums:
            return
        folder = filedialog.askdirectory(title="Choose the folder to verify")
        if not folder:
            return
        try:
            with open(sums, "r", encoding="utf-8", errors="replace") as fh:
                entries = parse_sums(fh.read())
        except Exception as exc:
            messagebox.showerror("Ghost Verify", f"Could not read the sums file: {exc}")
            return
        if not entries:
            messagebox.showwarning("Ghost Verify",
                                   "No SHA-256 entries found in that file.")
            return
        self.open_batch_window(sums, folder, len(entries))

        def work():
            try:
                results = verify_batch(
                    folder, entries,
                    progress=lambda f: self.events.put(("batch_progress", f)))
                self.events.put(("batch_done", results))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def open_batch_window(self, sums, folder, count):
        win = tk.Toplevel(self)
        win.title("Ghost Verify - batch results")
        win.geometry("620x420")
        win.configure(bg=BG)
        tk.Label(win, text=f"{count} files from {os.path.basename(sums)}  vs  {folder}",
                 bg=BG, fg=TEXT2, font=("Helvetica", 9)) \
            .pack(anchor="w", padx=12, pady=(10, 4))
        self.batch_status = tk.StringVar(value="Checking...")
        tk.Label(win, textvariable=self.batch_status, bg=BG, fg=TEXT1,
                 font=("Helvetica", 11, "bold")) \
            .pack(anchor="w", padx=12, pady=(0, 6))
        self.batch_text = tk.Text(win, bg=SURFACE, fg=TEXT1, relief="flat",
                                  font=("Courier", 10), wrap="none")
        self.batch_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def show_batch_results(self, results):
        marks = {"match": "✓ MATCH  ", "differ": "✗ DIFFER ", "missing": "? MISSING"}
        lines = []
        counts = {"match": 0, "differ": 0, "missing": 0}
        for name, status in results:
            counts[status] += 1
            lines.append(f"{marks[status]} {name}")
        if getattr(self, "batch_text", None) is not None:
            self.batch_text.delete("1.0", "end")
            self.batch_text.insert("1.0", "\n".join(lines))
            self.batch_status.set(
                f"{counts['match']} match · {counts['differ']} differ · "
                f"{counts['missing']} missing  (of {len(results)})")

    def check_verdict(self):
        expected = self.expected_var.get().strip().lower()
        actual = self.sha_var.get().strip().lower()
        if not expected or actual in ("", "-"):
            if self.verdict_var.get():
                self.set_banner("")
            return
        if expected == actual:
            self.set_banner("✓  MATCH — this is the file from the ship note", "good")
            key = (actual, expected, "match")
            if key not in self._logged_verdicts:
                self._logged_verdicts.add(key)
                self.log_event(f"verdict MATCH for sha256 {actual}")
        elif actual.startswith(expected) or expected.startswith(actual[:16]):
            self.set_banner("…  partial hash — keep pasting")
        else:
            self.set_banner("✗  NO MATCH — not the file from the ship note", "bad")
            key = (actual, expected, "nomatch")
            if key not in self._logged_verdicts:
                self._logged_verdicts.add(key)
                self.log_event(f"verdict NO MATCH: expected {expected}, got {actual}")


def cli(argv):
    """Scriptable mode. Returns an exit code, or None to open the GUI.

    --info FILE          JSON profile (hashes, size, APK fields, signer)
    --check FILE HASH    prints MATCH / NO MATCH; exit 0 only on match
    --sums FOLDER        SHA256SUMS text for the folder's top level
    --batch SUMS FOLDER  per-file verdicts; exit 0 only if all match
    --audit FOLDER URL   published copies vs the folder; exit 0 if all match
    --ledger [N]         the hash-chained history ledger (last N entries)
    --info and --check record what they verify into the ledger.
    Exit 2 is a usage or file error in every mode.
    """
    if not argv or argv[0] not in ("--info", "--check", "--sums", "--batch",
                                   "--ledger", "--audit"):
        return None
    mode, args = argv[0], argv[1:]
    try:
        if mode == "--info" and len(args) == 1:
            prof = file_profile(args[0])
            _eh, warnings, _rec = ledger_add(prof)
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
            print(json.dumps(prof, indent=2, default=str))
            return 0
        if mode == "--check" and len(args) == 2:
            prof = file_profile(args[0])
            _eh, warnings, _rec = ledger_add(prof)
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
            sha = prof["sha256"]
            ok = sha == args[1].strip().lower()
            print(("MATCH " if ok else "NO MATCH ") + sha)
            return 0 if ok else 1
        if mode == "--ledger" and len(args) <= 1:
            n = int(args[0]) if args else 20
            ok, count, bad = ledger_verify_chain()
            print(f"chain: {'intact' if ok else f'BROKEN at entry {bad}'} · {count} entries")
            for ts, name, sha, size, package, vn, vc, signer in ledger_recent(n):
                who = f"{package} v{vn} (code {vc})" if package else name
                print(f"{ts}  {who}  sha {sha[:16]}…  signer {(signer or '—')[:16]}")
            return 0 if ok else 1
        if mode == "--audit" and len(args) == 2:
            text, summary = site_audit(args[0], args[1])
            sys.stdout.write(text)
            return 0 if summary["problems"] == 0 else 1
        if mode == "--sums" and len(args) == 1:
            sys.stdout.write(generate_sums(args[0]))
            return 0
        if mode == "--batch" and len(args) == 2:
            with open(args[0], "r", encoding="utf-8", errors="replace") as fh:
                entries = parse_sums(fh.read())
            if not entries:
                print("no SHA-256 entries in the sums file", file=sys.stderr)
                return 2
            marks = {"match": "MATCH  ", "differ": "DIFFER ", "missing": "MISSING"}
            results = verify_batch(args[1], entries)
            for name, status in results:
                print(f"{marks[status]} {name}")
            return 0 if all(s == "match" for _n, s in results) else 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(__doc__ or "usage: ghost_verify.py [--info FILE | --check FILE HASH | "
                     "--sums FOLDER | --batch SUMS FOLDER | FILE]", file=sys.stderr)
    return 2


def main():
    code = cli(sys.argv[1:])
    if code is not None:
        sys.exit(code)
    start = sys.argv[1] if len(sys.argv) > 1 else ""
    app = GhostVerify(start)
    app.mainloop()


if __name__ == "__main__":
    main()
