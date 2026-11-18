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
    """Return (sha256_hex, md5_hex, size_bytes) for a file.

    progress, if given, is called with a 0..1 fraction as the file is
    read. Kept display-free on purpose so it can be tested headlessly.
    """
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    size = os.path.getsize(path)
    done = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            sha.update(block)
            md5.update(block)
            done += len(block)
            if progress is not None and size:
                progress(done / size)
    return sha.hexdigest(), md5.hexdigest(), size


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n / 1:.1f} {unit}".replace(".0", "")
        n /= 1024.0
    return f"{n} GB"


class GhostVerify(tk.Tk):
    def __init__(self, start_file=""):
        super().__init__()
        self.title("Ghost Verify - file hash checker")
        self.geometry("640x430")
        self.minsize(560, 400)
        self.configure(bg=BG)

        self.file_var = tk.StringVar(value=start_file)
        self.expected_var = tk.StringVar()
        self.sha_var = tk.StringVar(value="-")
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
                    sha, md5, size = payload
                    self.show_result(sha, md5, size)
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
        self.result_row(results, "MD5", self.md5_var, 1)
        self.result_row(results, "Size", self.size_var, 2)

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
                 font=("Courier", 9), anchor="w") \
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

    def show_result(self, sha, md5, size):
        self.sha_var.set(sha)
        self.md5_var.set(md5)
        self.size_var.set(f"{size:,} bytes ({human_size(size)})")
        self.status_var.set("Done.")
        self.check_verdict()

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
