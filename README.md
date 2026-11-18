# Ghost Verify

A file hash checker for the Ghost Developer Studio ship workflow, built
in the export style of [PyUI Builder](https://pyuibuilder.com) — visual
builder layout, clean generated-style Python, event handlers as methods.

Pure Python standard library (`tkinter` + `hashlib`). No installs, no
accounts, and no network — except the one fetch you explicitly ask
for (below), which is a plain GET with no cookies and no auth.

## Why it exists

Every APK and package the studio ships carries a SHA-256 in its ship
note, and the standing rule is: pull the file back and hash-match it
before calling it delivered. Ghost Verify makes that a 10-second job
instead of a terminal trip.

## Run

```sh
python3 ghost_verify.py            # then Browse to a file
python3 ghost_verify.py file.apk   # start with a file loaded
```

1. Pick a file (or pass it on the command line).
2. It shows SHA-256, SHA-512, MD5, and size from a single read pass,
   with one-tap copy buttons.
3. Paste the expected SHA-256 from the ship note: live verdict —
   **MATCH** (green), **NO MATCH** (red), or "keep pasting" while the
   hash is still partial.
4. **Copy ship note** puts a ready-to-paste line on the clipboard:
   `name - size - SHA-256 <hash>`, the format the studio's ship notes use.
5. **Batch mode** verifies a whole folder against a `SHA256SUMS` file
   (the format the release branches carry): pick the sums file, pick
   the folder, get per-file MATCH / DIFFER / MISSING with counts.
   **Generate SHA256SUMS** does the reverse: hash every file in a
   folder into a sums file of your own.
6. **APK inspection:** verify an `.apk` and it also reads the binary
   manifest (a small built-in AXML parser, no aapt needed) and shows
   package, versionName, versionCode, and min/target SDK — the
   "is this really the build the note describes?" check. The ship
   note for an APK includes its version and code automatically.
7. **APK trust pack:** the signer certificate's SHA-256, read from
   the APK Signing Block (v2, or v3 when v2 is absent) — the
   fingerprint that decides whether a build can install over the
   previous one — and the full permissions list with a count, read
   from the same manifest. Both were verified field-by-field against
   `apksigner` and `aapt` output on real studio APKs. The ship note
   for an APK gains a second line with the signer fingerprint.
8. **Compare APKs:** pick the shipped release and the candidate and
   get the release-over-release verdicts in one window: package
   match, version direction (a downgrade or a different signer is
   called out in red, because both refuse to install over the old
   build), permissions added and removed by name, size delta, and
   the new build's SHA-256 — plus a button that copies the new
   release's ship note.
9. **Fetch & compare:** paste the URL of the published copy (the
   downloads-site file, say) and it downloads to a temp file, hashes
   it, and verdicts against the local file — the pull-back check,
   without a terminal. Capped at 200 MB. **Paste hash** fills the
   expected-hash field from the clipboard when it holds a SHA-256.
   The **session log** records every verification and verdict with
   timestamps and copies out as a ready-made release record.
10. **The interface itself:** a full-width verdict banner that tints
    green on a match and red on a mismatch, a slim progress bar
    under the status line, a Recent row with the last five verified
    files (persisted in `~/.ghost-verify.json`, one click reopens
    and re-verifies), keyboard shortcuts (Ctrl+O open, Enter in the
    file field verifies, F5 re-verifies, Ctrl+L opens the log), and
    an original ghost app icon drawn in code — no image files.

Hashing runs on a background thread with a progress readout, so big
files never freeze the window. The worker never touches the window
directly; it posts events the main loop applies (Tk is not
thread-safe, and the first smoke test here proved why that matters).

## Notes

- GhostUx palette: `#121214` background, `#242428` surface, `#6716F3`
  violet accent — same tokens as Ghost Browser.
- `hash_file()` is display-free and can be imported and tested
  headlessly: `from ghost_verify import hash_file`.
