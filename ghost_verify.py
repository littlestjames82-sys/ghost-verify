# This code is written in the export style of PyUIBuilder: https://pyuibuilder.com
# Ghost Verify - a file hash checker for the Ghost Developer Studio ship workflow.
# Pure Python standard library (tkinter + hashlib). No installs, no network.
#
# Run:  python3 ghost_verify.py [file]
# Every APK and package the studio ships carries a SHA-256 in its ship
# note. Drop the file in here, paste the expected hash, get a verdict.

import hashlib
import os
import queue
import struct
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import zipfile
from tkinter import filedialog, messagebox, simpledialog

# GhostUx tokens (same palette as Ghost Browser)
BG = "#121214"
SURFACE = "#242428"
ACCENT = "#6716F3"
ACCENT_SOFT = "#9D6BFF"
TEXT1 = "#F2F2F5"
TEXT2 = "#A7A7B3"
GOOD = "#3FB96B"
BAD = "#E5534B"

CHUNK = 1024 * 1024


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
    req = urllib.request.Request(url, headers={"User-Agent": "GhostVerify/1.5"})
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


def generate_sums(folder, progress=None):
    """Build sha256sum-format text for every file directly in folder
    (top level only, sorted by name). Display-free."""
    names = sorted(f for f in os.listdir(folder)
                   if os.path.isfile(os.path.join(folder, f)))
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
        self.title("Ghost Verify 1.5 - file hash checker")
        self.geometry("660x680")
        self.minsize(580, 600)
        self.configure(bg=BG)

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
        self.after(60, self.poll_events)
        if start_file:
            self.after(150, self.verify)

    def poll_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    self.status_var.set(f"Hashing... {int(payload * 100)}%")
                elif kind == "done":
                    sha, sha512, md5, size = payload
                    self.show_result(sha, sha512, md5, size)
                elif kind == "batch_progress":
                    if getattr(self, "batch_status", None) is not None:
                        self.batch_status.set(f"Checking... {int(payload * 100)}%")
                elif kind == "batch_done":
                    self.show_batch_results(payload)
                elif kind == "sums_progress":
                    self.status_var.set(f"Hashing files for SHA256SUMS... {int(payload * 100)}%")
                elif kind == "sums_done":
                    dest, count = payload
                    self.status_var.set(f"Wrote {count} entries to {dest}")
                elif kind == "compare_done":
                    self.show_compare(payload[0], payload[1])
                elif kind == "fetch_progress":
                    self.status_var.set(f"Fetching... {int(payload * 100)}%")
                elif kind == "fetch_done":
                    self.show_fetch_result(payload[0], payload[1], payload[2])
                elif kind == "error":
                    messagebox.showerror("Ghost Verify", payload)
                    self.status_var.set("Failed.")
        except queue.Empty:
            pass
        self.after(60, self.poll_events)

    # ------------------------------------------------------------ layout
    def build_widgets(self):
        pad = {"padx": 14}

        title = tk.Label(self, text="GHOST VERIFY", bg=BG, fg=TEXT1,
                         font=("Helvetica", 17, "bold"))
        title.pack(anchor="w", pady=(14, 0), **pad)
        sub = tk.Label(self, text="Hash a file. Paste the expected hash. Get a verdict.",
                       bg=BG, fg=TEXT2, font=("Helvetica", 10))
        sub.pack(anchor="w", pady=(0, 10), **pad)

        file_frame = tk.Frame(self, bg=BG)
        file_frame.pack(fill="x", **pad)
        entry = tk.Entry(file_frame, textvariable=self.file_var, bg=SURFACE,
                         fg=TEXT1, insertbackground=TEXT1, relief="flat",
                         font=("Courier", 10))
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        browse = tk.Button(file_frame, text="Browse", command=self.browse,
                           bg=ACCENT, fg="white", activebackground=ACCENT_SOFT,
                           relief="flat", font=("Helvetica", 10, "bold"), padx=12)
        browse.pack(side="left", padx=(8, 0))

        verify_btn = tk.Button(self, text="VERIFY FILE", command=self.verify,
                               bg=ACCENT, fg="white", activebackground=ACCENT_SOFT,
                               relief="flat", font=("Helvetica", 11, "bold"), pady=6)
        verify_btn.pack(fill="x", pady=(12, 4), **pad)

        self.status = tk.Label(self, textvariable=self.status_var, bg=BG,
                               fg=TEXT2, font=("Helvetica", 9))
        self.status.pack(anchor="w", **pad)

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
        tk.Button(actions, text="Compare APKs",
                  command=self.start_compare,
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

        exp_label = tk.Label(self, text="Expected SHA-256 (from the ship note):",
                             bg=BG, fg=TEXT2, font=("Helvetica", 10))
        exp_label.pack(anchor="w", pady=(14, 4), **pad)
        expected = tk.Entry(self, textvariable=self.expected_var, bg=SURFACE,
                            fg=TEXT1, insertbackground=TEXT1, relief="flat",
                            font=("Courier", 10))
        expected.pack(fill="x", ipady=6, **pad)

        self.verdict = tk.Label(self, textvariable=self.verdict_var, bg=BG,
                                font=("Helvetica", 14, "bold"))
        self.verdict.pack(anchor="w", pady=(10, 0), **pad)

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
        self.verdict_var.set("")

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
        self.log_event(f"verified {os.path.basename(self.file_var.get().strip())}"
                       f" - {size:,} bytes - sha256 {sha}")
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
            self.apk_frame.pack(fill="x", pady=(10, 0), padx=14, after=self.results_frame)
        else:
            self.apk_frame.pack_forget()
        self.check_verdict()

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

        def work():
            try:
                text = generate_sums(
                    folder, progress=lambda f: self.events.put(("sums_progress", f)))
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
                self.verdict_var.set("✓  The published copy MATCHES the local file")
                self.verdict.configure(fg=GOOD)
                self.log_event(f"fetched {url} - MATCHES the local file")
            else:
                self.verdict_var.set("✗  The published copy DIFFERS from the local file")
                self.verdict.configure(fg=BAD)
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

        if cmp_["package_match"] is None:
            row(0, "Package", "At least one file is not a readable APK", BAD)
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
        d = cmp_["size_delta"]
        row(4, "Size", f"{old['size']:,}  →  {new['size']:,} bytes  ({'+' if d >= 0 else ''}{d:,})")
        row(5, "New SHA", new["sha256"])

        def copy_new_note():
            note = (f"{new['name']} v{new['apk'].get('version_name', '')} "
                    f"(code {new['apk'].get('version_code', '')}) - "
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
            self.verdict_var.set("")
            return
        if expected == actual:
            self.verdict_var.set("✓  MATCH — this is the file from the ship note")
            self.verdict.configure(fg=GOOD)
            key = (actual, expected, "match")
            if key not in self._logged_verdicts:
                self._logged_verdicts.add(key)
                self.log_event(f"verdict MATCH for sha256 {actual}")
        elif actual.startswith(expected) or expected.startswith(actual[:16]):
            self.verdict_var.set("…  partial hash — keep pasting")
            self.verdict.configure(fg=TEXT2)
        else:
            self.verdict_var.set("✗  NO MATCH — not the file from the ship note")
            self.verdict.configure(fg=BAD)
            key = (actual, expected, "nomatch")
            if key not in self._logged_verdicts:
                self._logged_verdicts.add(key)
                self.log_event(f"verdict NO MATCH: expected {expected}, got {actual}")


def main():
    start = sys.argv[1] if len(sys.argv) > 1 else ""
    app = GhostVerify(start)
    app.mainloop()


if __name__ == "__main__":
    main()
