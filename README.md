# Ghost Verify

A file hash checker for the Ghost Developer Studio ship workflow, built
in the export style of [PyUI Builder](https://pyuibuilder.com) — visual
builder layout, clean generated-style Python, event handlers as methods.

Pure Python standard library (`tkinter` + `hashlib`). No installs, no
network, no accounts.

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
2. It shows SHA-256, MD5, and size, with one-tap copy buttons.
3. Paste the expected SHA-256 from the ship note: live verdict —
   **MATCH** (green), **NO MATCH** (red), or "keep pasting" while the
   hash is still partial.

Hashing runs on a background thread with a progress readout, so big
files never freeze the window.

## Notes

- GhostUx palette: `#121214` background, `#242428` surface, `#6716F3`
  violet accent — same tokens as Ghost Browser.
- `hash_file()` is display-free and can be imported and tested
  headlessly: `from ghost_verify import hash_file`.
