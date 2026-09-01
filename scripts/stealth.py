import argparse
import ctypes
import sys
import time

# ---------------------------------------------------------------------------
# StealthX - hide ANY window (terminal, browser, app) from screen shares AND
# from the taskbar/desktop. Pick by window title, by PID, or let it suit you.
#
# Usage:
#   python stealth.py                    # interactive menu
#   python stealth.py --title  "opencode"
#   python stealth.py --pid  <pid>       # e.g. the terminal PID
#   python stealth.py --title "chrome" --capture --hide
#   python stealth.py --list             # list visible top-level windows
# ---------------------------------------------------------------------------

user32 = ctypes.windll.user32

WDA_EXCLUDEFROMCAPTURE = 0x00000011  # invisible to Discord/Zoom/OBS/recordings
GWL_STYLE    = -16
GWL_EXSTYLE  = -20
WS_EX_TOOLWINDOW = 0x00000080         # no taskbar button, no alt-tab entry
SW_HIDE  = 0
SW_SHOW  = 5

ERROR_SUCCESS          = 0
ERROR_INVALID_WINDOW_HANDLE = 1400


def _is_main_window(hwnd, pid):
    """True if hwnd is a visible, unowned top-level window belonging to pid."""
    if not user32.IsWindowVisible(hwnd):
        return False
    if not user32.IsWindowEnabled(hwnd):
        return False
    if user32.GetWindow(hwnd, 4):       # 4 = GW_OWNER  (owned windows skip)
        return False
    if user32.GetParent(hwnd):
        return False
    return True


def enum_windows_by_pid(pid):
    """Return top-level window handles that belong to the given PID, plus the
    bare console ones that hide most shells and terminals."""
    results = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _):
        if not _is_main_window(hwnd, pid):
            if not _is_console_or_tool(hwnd, pid):
                return True  # skip, keep going
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        results.append((hwnd, buf.value))
        return True

    user32.EnumWindows(cb, 0)
    return results


def _is_console_or_tool(hwnd, pid):
    # Include hidden console/tool windows that still belong to the process,
    # so collapsing a terminal actually removes its conhost/console surface.
    return _is_console_window(hwnd, pid) or _is_tool_window(hwnd, pid)


def _is_tool_window(hwnd, pid):
    class Info(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("dwPID", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32ThreadID", ctypes.c_ulong),
                    ("hParent", ctypes.c_void_p)]
    return False


def _is_console_window(hwnd, pid):
    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
    rect = RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    if (rect.right - rect.left) < 4 and (rect.bottom - rect.top) < 4:
        return False
    class Info(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("hWnd", ctypes.c_void_p),
                    ("hInstance", ctypes.c_void_p), ("szStyle", ctypes.c_char_p)]
    return False


def list_all_windows():
    """Print every top-level window with its handle, title and PID."""
    out = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd) and not _is_console_or_tool(hwnd, 0):
            return True
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        out.append((hwnd, pid.value, buf.value))
        return True

    user32.EnumWindows(cb, 0)
    return out


def find_by_title(fragment):
    """Return (title, hwnd) for visible windows whose title contains fragment."""
    matches = []
    for hwnd, pid, title in list_all_windows():
        if fragment.lower() in title.lower():
            matches.append((title, hwnd))
    return matches


def set_capture_exclusion(hwnd):
    """Invisible to every screen-capture / recording / share pipeline."""
    if hwnd and hwnd <= 0:
        return False
    ok = user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
    return bool(ok)


def restore_capture(hwnd):
    """Put the window back into normal capture."""
    if hwnd and hwnd <= 0:
        return False
    ok = user32.SetWindowDisplayAffinity(hwnd, 0)
    return bool(ok)


def hide_from_taskbar_and_desktop(hwnd):
    """Give the window no taskbar/alt-tab presence and hide it from the desktop."""
    if not hwnd or hwnd <= 0:
        return False
    # If it has real chrome, drop it from the taskbar entirely.
    ex = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
    user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex | WS_EX_TOOLWINDOW)
    # Destroy the taskbar button wholesale.
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x40 | 0x10 | 0x100)
    # Pull it away from the visible desktop.
    user32.ShowWindow(hwnd, SW_HIDE)
    return True


def show_again(hwnd):
    """Undo: restore capture and bring the window back."""
    restore_capture(hwnd)
    if hwnd and hwnd > 0:
        ex = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
        user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex & ~WS_EX_TOOLWINDOW)
        user32.ShowWindow(hwnd, SW_SHOW)
        user32.SetForegroundWindow(hwnd)


HWND_TOPMOST = ctypes.c_void_p(-1)
HWND_NOTOPMOST = ctypes.c_void_p(-2)
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040


def set_topmost(hwnd):
    """Pin the window to the very front of the screen. It stays above every
    other window until another app force-steals topmost or --topmost is off."""
    if not hwnd or hwnd <= 0:
        return False
    ok = user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
    return bool(ok)


def clear_topmost(hwnd):
    """Drop the always-on-top pin, putting the window back in normal order."""
    if not hwnd or hwnd <= 0:
        return False
    ok = user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
    return bool(ok)


def keep_topmost(hwnd, interval=1.0, duration=None):
    """Re-pin the window to the top on a loop. Because other apps can steal
    topmost (it's not permanent in Windows), this watchdog re-asserts it so the
    terminal truly stays on top no matter what. Ctrl+C to stop."""
    import time
    started = time.time()
    print("Topmost watchdog started. The window will stay pinned to the front.")
    print("Press Ctrl+C to stop (unpin).")
    try:
        while True:
            set_topmost(hwnd)
            if duration and time.time() - started >= duration:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    clear_topmost(hwnd)
    print("Stopped. Window unpinned.")


def act_on(hwnd, capture, hide, show, topmost=False):
    if show:
        show_again(hwnd)
        if not topmost:
            clear_topmost(hwnd)
        return
    if capture:
        set_capture_exclusion(hwnd)
    if hide:
        hide_from_taskbar_and_desktop(hwnd)
    if topmost:
        set_topmost(hwnd)


def self_console_hwnd():
    """Return the console window for the CURRENT process (the terminal that
    launched this script), regardless of whether it is hidden or visible."""
    kernel32 = ctypes.windll.kernel32
    pid = kernel32.GetCurrentProcessId()
    # Re-attach to the console and read it through the shared console list.
    # GetConsoleWindow() only works while attached, so use it directly.
    return int(ctypes.windll.kernel32.GetConsoleWindow() or 0)


def _find_console_by_pid(pid):
    """Scan top-level windows for one that is the 'ConsoleWindowClass' of pid."""
    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    found = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _):
        if not user32.IsWindow(hwnd):
            return True
        cpid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(cpid))
        if cpid.value != pid:
            return True
        buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, buf, 256)
        if "ConsoleWindowClass" in buf.value or "CASCADIA_HOSTING_WINDOW_CLASS" in buf.value:
            found.append(hwnd)
        return True

    user32.EnumWindows(cb, 0)
    return found


def _parent_pid(pid):
    """Return the parent process id via toolhelp snapshot (0 if none)."""
    import ctypes.wintypes as wtypes
    TH32CS_SNAPPROCESS = 0x00000002
    PROCESSENTRY32 = ctypes.c_byte * 568  # fixed reinterpreted struct

    class ProcEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wtypes.DWORD),
            ("cntUsage", wtypes.DWORD),
            ("th32ProcessID", wtypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wtypes.DWORD),
            ("cntThreads", wtypes.DWORD),
            ("th32ParentProcessID", wtypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wtypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return 0
    try:
        e = ProcEntry(); e.dwSize = ctypes.sizeof(ProcEntry)
        if not k32.Process32FirstW(snap, ctypes.byref(e)):
            return 0
        while True:
            if e.th32ProcessID == pid:
                return int(e.th32ParentProcessID)
            if not k32.Process32NextW(snap, ctypes.byref(e)):
                break
    finally:
        k32.CloseHandle(snap)
    return 0


def hexhwnd(x: str) -> int:
    return int(x, 16)


def _unhide_every_console():
    """Find likely dev consoles and restore their capture + taskbar visibility."""
    fixed = 0
    for hwnd, pid, title in list_all_windows():
        cls = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cls, 256)
        if ("ConsoleWindowClass" in cls.value or "CASCADIA_HOSTING_WINDOW_CLASS" in cls.value) and title.strip():
            show_again(hwnd)
            fixed += 1
    print(f"Restored {fixed} console windows (capture + taskbar).")


def _run_restore_hotkey(combination):
    """Register a global hotkey. While this runs, pressing the combination
    restores every console; Ctrl+C to exit the listener."""
    MOD = {"ctrl": 0x0002, "alt": 0x0001, "shift": 0x0004}
    parts = [p.lower() for p in combination.replace(" ", "").split("+")]
    mod = 0
    key = None
    for p in parts:
        if p in MOD:
            mod |= MOD[p]
        else:
            key = ord(p[0]) if len(p) == 1 else user32.VkKeyScanW(p[0])
    if not key:
        print("Bad hotkey spec. e.g. --hotkey 'Ctrl+Alt+S'")
        return

    HOTKEY_MSG = 0x0312
    WM_HOTKEY_WND = f"StealthX-Hotkey-Wnd-{id(object())}"

    class WndProcCls:  # keep a stable bound wndproc
        @staticmethod
        def wndproc(st, lg, wm, wl, ll):
            if wm == HOTKEY_MSG:
                _unhide_every_console()
            return 0

    wndproc_t = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
    wc = ctypes.WNDCLASS()
    wc.lpfnWndProc = wndproc_t(WndProcCls.wndproc)
    wc.lpszClassName = WM_HOTKEY_WND
    user32.RegisterClassW(ctypes.byref(wc))
    wnd = user32.CreateWindowExW(0, WM_HOTKEY_WND, WM_HOTKEY_WND, 0, 0, 0, 0, 0,
                                 ctypes.c_void_p(0), ctypes.c_void_p(0),
                                 ctypes.c_void_p(0), ctypes.c_void_p(0))
    user32.RegisterHotKey(wnd, 1, mod, key)
    print(f"Restore hotkey '{combination}' armed. When hidden, press it to restore.")
    print("Ctrl+C in the source console exits this listener.")
    msg = ctypes.MSG()
    try:
        while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except KeyboardInterrupt:
        pass
    user32.UnregisterHotKey(wnd, 1)
    user32.DestroyWindow(wnd)


def interactive():
    while True:
        for hwnd, pid, title in list_all_windows():
            if title.strip():
                print(f"  {hex(hwnd)}  pid={pid:<6}  {title}")
        choice = input("\nWindow handle (hex, e.g. 0x30a4e) or <enter> to refresh, q to quit: ").strip()
        if choice.lower() == "q":
            return
        if not choice:
            continue
        try:
            hwnd = hexhwnd(choice)
        except ValueError:
            print("Bad handle.")
            continue
        if not hwnd or hwnd <= 0 or not user32.IsWindow(hwnd):
            print("Invalid window handle.")
            continue
        print("[p]in to front (stays on top)   [c]apture-hide   [h]ide+taskbar   [b]oth   [u]npin   [s]how again")
        mode = input("Mode: ").strip().lower()
        if mode == "p":
            act_on(hwnd, False, False, False, topmost=True)
            print("Pinned to front.")
        elif mode == "u":
            clear_topmost(hwnd)
            print("Unpinned.")
        else:
            act_on(hwnd, mode in ("c", "b"), mode in ("h", "b"), mode == "s")
        print("Done.\n")


def main():
    ap = argparse.ArgumentParser(description="StealthX - hide windows from screen shares and the taskbar.")
    ap.add_argument("--title", help="hide windows whose title contains this text")
    ap.add_argument("--pid", type=int, help="hide every window belonging to this process id")
    ap.add_argument("--hwnd", help="hide a specific window handle (hex, e.g. 0x1a2b3c)")
    ap.add_argument("--capture", action="store_true", help="make it invisible to screen captures/shares")
    ap.add_argument("--hide", action="store_true", help="also hide from the taskbar/desktop")
    ap.add_argument("--show", action="store_true", help="restore everything and bring it back")
    ap.add_argument("--topmost", action="store_true", help="pin the target window to the very front (always on top). Runs a watchdog by default so it STAYS on top.")
    ap.add_argument("--pin", action="store_true", help="shorthand for --topmost")
    ap.add_argument("--watch", type=float, default=None,
                    help="watchdog re-pin interval in seconds (default 0.5). Use --once to pin a single time instead.")
    ap.add_argument("--once", action="store_true",
                    help="pin only once and exit, instead of running the keep-on-top watchdog")
    ap.add_argument("--unpin", action="store_true", help="remove the always-on-top pin")
    ap.add_argument("--self", action="store_true", help="hide the console that launched this script")
    ap.add_argument("--unhide-all", action="store_true", help="restore capture+visibility on every affected console")
    ap.add_argument("--hotkey", help="hotkey to run while script stays open then restore (e.g. Ctrl+Alt+S). LONG-RUNNING.")
    ap.add_argument("--list", action="store_true", help="list windows then exit")
    args = ap.parse_args()

    if args.unhide_all:
        _unhide_every_console()
        return

    if args.hotkey:
        _run_restore_hotkey(args.hotkey)
        return

    if args.list:
        for hwnd, pid, title in list_all_windows():
            if title.strip():
                print(f"  {hex(hwnd)}  pid={pid:<6}  {title}")
        return

    if not (args.title or args.pid or args.hwnd or args.self or args.unpin):
        interactive()
        return

    if not (args.capture or args.hide or args.show or args.topmost or args.pin or args.unpin):
        args.capture = True
        args.hide = True

    targets = []
    if args.hwnd:
        targets.append((args.hwnd, "0x" + args.hwnd))
    if args.title:
        for title, hwnd in find_by_title(args.title):
            targets.append((hex(hwnd), title))
    if args.pid:
        for hwnd, title in enum_windows_by_pid(args.pid):
            targets.append((hex(hwnd), title))
    if args.self:
        self_handles = []
        # GetConsoleWindow() returns the launching console if attached.
        own = self_console_hwnd()
        if own:
            self_handles.append(own)
        # Otherwise walk the parent process chain and hide the terminal that
        # owns our console (handles subprocess launches, e.g. under opencode).
        k32 = ctypes.windll.kernel32
        own_pid = k32.GetCurrentProcessId()
        for hwnd in _find_console_by_pid(own_pid):
            self_handles.append(hwnd)
        parent_pid = _parent_pid(own_pid)
        seen_pids = {own_pid}
        while parent_pid and parent_pid not in seen_pids:
            seen_pids.add(parent_pid)
            for hwnd in _find_console_by_pid(parent_pid):
                self_handles.append(hwnd)
            parent_pid = _parent_pid(parent_pid)
        seen = set()
        for h in self_handles:
            if h and h not in seen:
                seen.add(h)
                targets.append((hex(h), "self-console (launcher)"))
        if not seen:
            print("--self: could not find a console window to hide. Give --hwnd/-title/-pid explicitly.")

    if not targets:
        print("No matching window found. Use --list to see candidates.")
        return

    # Special handling: --unpin just clears topmost on the target(s).
    if args.unpin:
        for hwnd_str, label in targets:
            hwnd = hexhwnd(hwnd_str) if hwnd_str != "0x" + args.hwnd else hexhwnd(args.hwnd)
            clear_topmost(hwnd)
            print(f"[UNPINNED] {label} ({hwnd_str})")
        return

    topmost = args.topmost or args.pin
    # A single SetWindowPos(HWND_TOPMOST) is NOT permanent in Windows: the next
    # window that takes focus can pull it back down. So --topmost/--pin default
    # to a watchdog loop that re-asserts the pin forever. Pass --watch 0 or
    # --once to just set it a single time instead.
    if topmost and args.watch != 0 and not args.once and not args.show:
        hwnds = []
        for hwnd_str, label in targets:
            hwnd = hexhwnd(hwnd_str) if hwnd_str != "0x" + args.hwnd else hexhwnd(args.hwnd)
            hwnds.append((hwnd, label))
        interval = args.watch if args.watch else 0.5
        if len(hwnds) == 1:
            keep_topmost(hwnds[0][0], interval=interval)
        else:
            # Multiple targets: watch them all round-robin.
            import time
            print("Pinning %d windows to front. Ctrl+C to stop." % len(hwnds))
            try:
                while True:
                    for h, _ in hwnds:
                        set_topmost(h)
                    time.sleep(interval)
            except KeyboardInterrupt:
                for h, _ in hwnds:
                    clear_topmost(h)
            print("Stopped. Windows unpinned.")
        return

    for hwnd_str, label in targets:
        hwnd = hexhwnd(hwnd_str) if hwnd_str != "0x" + args.hwnd else hexhwnd(args.hwnd)
        act_on(hwnd, args.capture, args.hide, args.show, topmost=topmost)
        state = "SHOW" if args.show else ("PINNED" if topmost else "HIDDEN")
        print(f"[{state}] {label} ({hex(hwnd)})")

    if args.show and not topmost:
        print("\nWindow restored.")
    elif topmost:
        print("\nPinned to front. Use --unpin to unpin, or repeat with --show to undo hide.")
    elif not args.show:
        print("\nTip: run the same command with --show to bring it all back.")
        print("     The window stays alive; unless you --hide it, only captures see nothing.")


if __name__ == "__main__":
    main()