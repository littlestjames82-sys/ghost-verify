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
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

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
        self.title("Ghost Verify 1.1 - file hash checker")
        self.geometry("660x520")
        self.minsize(580, 480)
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
        self.result_row(results, "SHA-256", self.sha_var, 0)
        self.result_row(results, "SHA-512", self.sha512_var, 1)
        self.result_row(results, "MD5", self.md5_var, 2)
        self.result_row(results, "Size", self.size_var, 3)

        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", pady=(10, 0), **pad)
        tk.Button(actions, text="Copy ship note", command=self.copy_ship_note,
                  bg=SURFACE, fg=TEXT1, activebackground=ACCENT,
                  relief="flat", font=("Helvetica", 10), padx=10, pady=4) \
            .pack(side="left")
        tk.Button(actions, text="Batch: verify folder vs SHA256SUMS",
                  command=self.start_batch,
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

    def show_result(self, sha, sha512, md5, size):
        self.sha_var.set(sha)
        self.sha512_var.set(sha512)
        self.md5_var.set(md5)
        self.size_var.set(f"{size:,} bytes ({human_size(size)})")
        self.status_var.set("Done.")
        self.check_verdict()

    def copy_ship_note(self):
        sha = self.sha_var.get()
        if sha in ("", "-"):
            self.status_var.set("Verify a file first, then copy its ship note.")
            return
        name = os.path.basename(self.file_var.get().strip())
        note = f"{name} - {self.size_var.get()} - SHA-256 {sha}"
        self.clipboard_clear()
        self.clipboard_append(note)
        self.status_var.set("Ship note copied: " + note)

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
        elif actual.startswith(expected) or expected.startswith(actual[:16]):
            self.verdict_var.set("…  partial hash — keep pasting")
            self.verdict.configure(fg=TEXT2)
        else:
            self.verdict_var.set("✗  NO MATCH — not the file from the ship note")
            self.verdict.configure(fg=BAD)


def main():
    start = sys.argv[1] if len(sys.argv) > 1 else ""
    app = GhostVerify(start)
    app.mainloop()


if __name__ == "__main__":
    main()
