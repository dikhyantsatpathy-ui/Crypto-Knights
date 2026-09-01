#!/usr/bin/env python3
"""
================================================================
  GHOSTHELPER - your on-screen interview copilot
  (win32)  (tkinter)
================================================================
The window YOU can see, read and type into -- but that NEVER shows
up on a screen share (Discord / Zoom / OBS / full-screen capture).

HOW IT WORKS
  * It is a totally normal, readable tkinter window (scrollable,
    resizable, you can open/close/focus/type in it freely).
  * SetWindowDisplayAffinity(0x11) = WDA_EXCLUDEFROMCAPTURE marks it
    so every capture/recording/share pipeline excludes the window,
    WHILE it stays 100% visible and usable on YOUR monitor.
  * -topmost keeps it floating above everything so it's easy to read.
  * Looks like an ordinary chat/AI panel during a live call.

USAGE
  python helper.py                     -> starts the copilot window
  python helper.py --show-on-capture    -> test: lets Discord see it
  python helper.py --no-topmost         -> don't float it on top

Controls (inside the window)
  [Hide]   -> exclude this window from captures (the default state)
  [Show]   -> let captures see it (for testing / when not in a call)
  [On top] -> float above all windows        [Off top] -> normal z-order
  [Clear]  -> wipe the notes panel
  Copy/paste any answer or cheat-sheet in, keep it pinned, and go.
================================================================
"""
import ctypes
import tkinter as tk
from tkinter import scrolledtext

user32 = ctypes.windll.user32
WDA_NONE = 0x00000000
WDA_EXCLUDEFROMCAPTURE = 0x00000011


class GhostHelper:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GHOSTHELPER \u00b7 nudge panel")
        self.root.geometry("600x480")
        self.root.minsize(380, 260)

        # ---- window style: normal + readable + floating on top ----
        self.root.attributes("-topmost", True)
        self.root.configure(bg="#1e1e2e")

        # ---- a "browser-ish" toolbar so it reads like an app ----
        bar = tk.Frame(self.root, bg="#11111b", pady=4)
        bar.pack(side=tk.TOP, fill=tk.X)
        tk.Label(bar, text="\U0001F9D0 GHOSTHELPER",
                 bg="#11111b", fg="#89b4fa", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=8)
        tk.Button(bar, text="\U0001F6D1 Hide", bg="#f38ba8", fg="black",
                  font=("Segoe UI", 9, "bold"), command=self._hide_from_capture).pack(side=tk.LEFT, padx=2)
        tk.Button(bar, text="Show", bg="#a6e3a1", fg="black",
                  font=("Segoe UI", 9, "bold"), command=self._show_on_capture).pack(side=tk.LEFT, padx=2)
        tk.Button(bar, text="On top", bg="#89b4fa", fg="black",
                  font=("Segoe UI", 9, "bold"), command=self._pin_top).pack(side=tk.LEFT, padx=2)
        tk.Button(bar, text="Off top", bg="#cba6f7", fg="black",
                  font=("Segoe UI", 9, "bold"), command=self._unpin_top).pack(side=tk.LEFT, padx=2)
        tk.Button(bar, text="Clear", bg="#fab387", fg="black",
                  font=("Segoe UI", 9, "bold"), command=self._clear).pack(side=tk.LEFT, padx=2)

        # ---- the notes / answer panel ----
        self.text = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, font=("Consolas", 12),
            bg="#1e1e2e", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief=tk.FLAT, padx=12, pady=12)
        self.text.pack(expand=True, fill=tk.BOTH)
        self.text.insert(tk.END,
            "Paste your interview cheat-sheet here.\n\n"
            "This window is VISIBLE to you but EXCLUDED from screen "
            "capture - so Discord/Zoom/OBS/share recordings will not "
            "show it. It floats on top and behaves like a normal app.\n\n"
            "Tip: keep it small and off to the side during a live call.")

        # ---- grab the native HWND and make it capture-invisible ----
        self.root.update_idletasks()
        self.hwnd = user32.GetParent(self.root.winfo_id())
        self._hide_from_capture()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- capture visibility ----
    def _hide_from_capture(self):
        """Exclude this window from every capture/share pipeline."""
        if self.hwnd:
            user32.SetWindowDisplayAffinity(self.hwnd, WDA_EXCLUDEFROMCAPTURE)
            self._set_status("capture-excluded (hidden in shares)")

    def _show_on_capture(self):
        """Let captures see this window (for testing / non-call use)."""
        if self.hwnd:
            user32.SetWindowDisplayAffinity(self.hwnd, WDA_NONE)
            self._set_status("capture-visible (shows in shares)")

    # ---- z-order ----
    def _pin_top(self):
        self.root.attributes("-topmost", True)
        self._set_status("floating on top")

    def _unpin_top(self):
        self.root.attributes("-topmost", False)
        self._set_status("normal z-order")

    def _clear(self):
        self.text.delete("1.0", tk.END)

    def _set_status(self, msg):
        self.root.title(f"GHOSTHELPER \u00b7 {msg}")

    def _on_close(self):
        # restore capture visibility cleanly on exit, then quit
        if self.hwnd:
            user32.SetWindowDisplayAffinity(self.hwnd, WDA_NONE)
        self.root.destroy()


def main():
    import sys
    args = sys.argv[1:]
    a = GhostHelper()
    if "--show-on-capture" in args:      # start visible to shares
        a._show_on_capture()
    if "--no-topmost" in args:           # start not floating
        a._unpin_top()
    a.root.mainloop()


if __name__ == "__main__":
    main()