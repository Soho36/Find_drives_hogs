#!/usr/bin/env python3
"""
Drive space hog finder.

Walks the whole drive ONCE (read-only, never follows junctions/symlinks/reparse points),
then reports:
  1. Top-level breakdown of the drive (and how much space the scan could not see)
  2. The biggest folders, drilled down to where the space actually lives
  3. The biggest individual files
  4. Known cleanup opportunities (caches, temp, Windows.old, ...) with a safe-to-clean total

Run as Administrator for complete numbers (Windows, ProgramData, other users' profiles).
"""

import argparse
import ctypes
import heapq
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
GB = 1024 ** 3
MB = 1024 ** 2
DOMINANT_CHILD_RATIO = 0.6   # if big subfolders hold >=60% of a folder, report them instead of the folder
SPLIT_LEVELS = 2             # directory levels walked in the main thread; deeper subtrees run in the pool


class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for name in ("BLUE", "CYAN", "GREEN", "YELLOW", "RED", "BOLD", "DIM", "RESET"):
            setattr(cls, name, "")


# (regex on lower-cased full path, category, recommendation, safe_to_clean)
FOLDER_RULES: List[Tuple[str, str, str, bool]] = [
    (r"\\appdata\\local\\temp$", "Temp Files", "Delete contents (skip files in use)", True),
    (r"^[a-z]:\\windows\\temp$", "Temp Files", "Delete contents, or run Disk Cleanup as admin", True),
    (r"\\appdata\\local\\crashdumps$", "Crash Dumps", "Safe to delete", True),
    (r"^[a-z]:\\windows\.old$", "Old Windows Install", "Disk Cleanup > 'Previous Windows installation(s)'", True),
    (r"^[a-z]:\\\$windows\.~(bt|ws)$", "Windows Upgrade Leftovers", "Disk Cleanup > 'Windows Update Cleanup'", True),
    (r"^[a-z]:\\windows\\softwaredistribution\\download$", "Windows Update Cache", "Disk Cleanup > 'Windows Update Cleanup'", True),
    (r"^[a-z]:\\windows\\winsxs$", "Component Store (WinSxS)",
     "DISM /Online /Cleanup-Image /StartComponentCleanup (size is inflated by hard links)", False),
    (r"^[a-z]:\\windows\\installer$", "Windows Installer Cache", "Do NOT delete by hand; PatchCleaner can prune orphans", False),
    (r"^[a-z]:\\programdata\\package cache$", "Installer Package Cache", "Only removable via uninstall/repair; leave alone", False),
    (r"\\appdata\\local\\pip\\cache$", "Developer Cache", "pip cache purge", True),
    (r"\\appdata\\local\\npm-cache$", "Developer Cache", "npm cache clean --force", True),
    (r"\\\.gradle\\caches$", "Developer Cache", "Safe; re-downloaded on demand", True),
    (r"\\\.m2\\repository$", "Developer Cache", "Safe; re-downloaded on demand", True),
    (r"\\\.nuget\\packages$", "Developer Cache", "dotnet nuget locals all --clear", True),
    (r"\\\.cache\\(huggingface|torch|pip|uv|codex-runtimes)$", "Developer / ML Cache", "Safe; re-downloaded on demand", True),
    (r"\\\.ollama\\models$", "LLM Models", "ollama rm <model> for unused ones", False),
    (r"\\\.codex$", "Codex Sessions & Binaries", "Clean old sessions/.tmp inside", False),
    (r"\\appdata\\local\\jetbrains\\[^\\]+\\(caches|index|log|splash)$", "IDE Cache / Logs",
     "File > Invalidate Caches, or delete when the IDE is closed", True),
    (r"\\appdata\\roaming\\metaquotes\\terminal\\[^\\]+\\(bases|tester|logs)$", "Trading Data Cache",
     "Tick/tester cache; MT5 re-downloads on demand", True),
    (r"\\user data\\[^\\]+\\(cache|code cache|gpucache)$", "Browser Cache", "Clear from browser settings", True),
    (r"\\appdata\\local\\docker(\\wsl)?$", "Docker Desktop", "docker system prune -a; or move the disk image", False),
    (r"\\appdata\\local\\packages\\[^\\]*(ubuntu|debian|kali|suse)[^\\]*\\localstate$", "WSL Distro",
     "wsl --export/--import to another drive, or wsl --unregister", False),
    (r"\\steamapps$", "Steam Library", "Uninstall unused games or move the library to another drive", False),
    (r"\\downloads$", "Downloads", "Review and delete/move old installers and archives", False),
    (r"\\(viber|telegram)[^\\]*$", "Chat Media", "Clean old downloaded media", False),
    (r"^[a-z]:\\program files( \(x86\))?\\[^\\]+$", "Installed Program / Game",
     "Uninstall if unused, or reinstall onto another drive", False),
]
FOLDER_RULES_COMPILED = [(re.compile(p), c, r, s) for p, c, r, s in FOLDER_RULES]

# lower-cased file name -> (category, recommendation)
FILE_NAME_RULES: Dict[str, Tuple[str, str]] = {
    "hiberfil.sys": ("Hibernation File", "powercfg /h /type reduced  (or  /h off) in an admin shell"),
    "pagefile.sys": ("Paging File", "Move it to another drive: System Properties > Advanced > Performance > Virtual memory"),
    "swapfile.sys": ("Swap File", "Managed by Windows; follows the pagefile setting"),
    "memory.dmp": ("Crash Dump", "Safe to delete"),
}
FILE_EXT_RULES: Dict[str, Tuple[str, str]] = {
    ".vhdx": ("Virtual Disk", "VM/WSL disk; compact it or move to another drive"),
    ".vmdk": ("Virtual Disk", "VM disk; compact it or move to another drive"),
    ".vdi": ("Virtual Disk", "VM disk; compact it or move to another drive"),
    ".iso": ("Disk Image", "Delete if no longer needed"),
    ".zip": ("Archive", "Delete or move if already extracted"),
    ".7z": ("Archive", "Delete or move if already extracted"),
    ".rar": ("Archive", "Delete or move if already extracted"),
    ".pst": ("Mail Archive", "Move to another drive"),
    ".ost": ("Mail Cache", "Outlook cache; can be rebuilt"),
    ".dmp": ("Crash Dump", "Safe to delete"),
    ".etl": ("Trace Log", "Usually safe to delete"),
    ".log": ("Log File", "Usually safe to delete/rotate when the app is closed"),
}


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------

def format_size(n: int) -> str:
    if n >= GB:
        return f"{n / GB:7.2f} GB"
    return f"{n / MB:7.1f} MB"


def norm(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").lower()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def shorten(path: str, width: int) -> str:
    return path if len(path) <= width else "..." + path[-(width - 3):]


def is_under(path_l: str, ancestor_l: str) -> bool:
    return path_l.startswith(ancestor_l + "\\")


# ----------------------------------------------------------------------------------------------
# scanning
# ----------------------------------------------------------------------------------------------

class Scanner:
    def __init__(self, min_bytes: int, top_files: int, excluded: Set[str]):
        self.min_bytes = min_bytes
        self.excluded = excluded  # lower-cased full paths that are never entered
        self.top_files = top_files
        self.dir_sizes: Dict[str, int] = {}          # only dirs >= min_bytes are recorded
        self.dir_children: Dict[str, List[str]] = {}  # only children >= min_bytes are recorded
        self.file_heap: List[Tuple[int, str]] = []
        self.lock = threading.Lock()
        self.files_seen = 0
        self.errors = 0

    def _push_file(self, heap: List[Tuple[int, str]], size: int, path: str) -> None:
        if len(heap) < self.top_files:
            heapq.heappush(heap, (size, path))
        elif size > heap[0][0]:
            heapq.heapreplace(heap, (size, path))

    def _walk(self, path: str, heap: List[Tuple[int, str]], stats: List[int]) -> int:
        """Recursively size `path`. stats = [files_seen, errors] for this worker."""
        total = 0
        big_children: List[str] = []
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue  # junction / symlink / cloud placeholder: never follow
                        if entry.is_dir(follow_symlinks=False):
                            if norm(entry.path) in self.excluded:
                                continue
                            sub = self._walk(entry.path, heap, stats)
                            total += sub
                            if sub >= self.min_bytes:
                                big_children.append(entry.path)
                        else:
                            total += st.st_size
                            stats[0] += 1
                            self._push_file(heap, st.st_size, entry.path)
                    except OSError:
                        stats[1] += 1
        except OSError:
            stats[1] += 1
        if total >= self.min_bytes:
            self.dir_sizes[path] = total
            self.dir_children[path] = big_children
        return total

    def _run_unit(self, path: str) -> int:
        heap: List[Tuple[int, str]] = []
        stats = [0, 0]
        size = self._walk(path, heap, stats)
        with self.lock:
            for item in heap:
                self._push_file(self.file_heap, *item)
            self.files_seen += stats[0]
            self.errors += stats[1]
        return size

    def _split(self, path: str, levels: int, units: List[str], skeleton: Dict[str, List[str]],
               own_files: Dict[str, int]) -> None:
        """Walk the first few levels in the main thread; hand deeper subtrees to the pool."""
        skeleton[path] = []
        own_files[path] = 0
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if norm(entry.path) in self.excluded:
                                continue
                            skeleton[path].append(entry.path)
                            if levels > 1:
                                self._split(entry.path, levels - 1, units, skeleton, own_files)
                            else:
                                units.append(entry.path)
                        else:
                            own_files[path] += st.st_size
                            self.files_seen += 1
                            self._push_file(self.file_heap, st.st_size, entry.path)
                    except OSError:
                        self.errors += 1
        except OSError:
            self.errors += 1

    def scan(self, root: str, workers: int) -> Dict[str, int]:
        """Returns sizes of the root's direct children (dirs by size, plus loose files total)."""
        units: List[str] = []
        skeleton: Dict[str, List[str]] = {}
        own_files: Dict[str, int] = {}
        self._split(root, SPLIT_LEVELS, units, skeleton, own_files)

        unit_sizes: Dict[str, int] = {}
        done = threading.Event()

        def progress() -> None:
            spinner = "|/-\\"
            i = 0
            while not done.wait(0.25):
                sys.stderr.write(f"\r  scanning... {self.files_seen:>10,} files {spinner[i % 4]}")
                sys.stderr.flush()
                i += 1

        if sys.stderr.isatty():
            threading.Thread(target=progress, daemon=True).start()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for path, size in zip(units, pool.map(self._run_unit, units)):
                unit_sizes[path] = size
        done.set()
        if sys.stderr.isatty():
            sys.stderr.write("\r" + " " * 50 + "\r")

        # aggregate the skeleton bottom-up
        def total_of(path: str) -> int:
            if path in unit_sizes:
                return unit_sizes[path]
            total = own_files.get(path, 0)
            big = []
            for child in skeleton.get(path, []):
                sub = total_of(child)
                total += sub
                if sub >= self.min_bytes:
                    big.append(child)
            if total >= self.min_bytes:
                self.dir_sizes[path] = total
                self.dir_children[path] = big
            return total

        total_of(root)
        result = {c: self.dir_sizes.get(c, unit_sizes.get(c, 0)) for c in skeleton.get(root, [])}
        # small top-level folders may not be in dir_sizes; recompute so the breakdown is accurate
        for c in skeleton.get(root, []):
            if c not in result or result[c] == 0:
                result[c] = unit_sizes.get(c, 0) or self.dir_sizes.get(c, 0)
        result["<loose files in root>"] = own_files.get(root, 0)
        return result


# ----------------------------------------------------------------------------------------------
# analysis
# ----------------------------------------------------------------------------------------------

def drill_down(scanner: Scanner, path: str, out: List[Tuple[int, str]]) -> None:
    """Emit the most specific folder that still holds most of the space."""
    size = scanner.dir_sizes.get(path, 0)
    if size < scanner.min_bytes:
        return
    kids = scanner.dir_children.get(path, [])
    # If the big subfolders account for most of this folder, the folder is just a container:
    # report what is inside instead. Otherwise the space is in loose files/small folders here.
    if kids and sum(scanner.dir_sizes.get(k, 0) for k in kids) >= DOMINANT_CHILD_RATIO * size:
        for k in kids:
            drill_down(scanner, k, out)
        return
    out.append((size, path))


def classify_folders(scanner: Scanner) -> List[Tuple[int, str, str, str, bool]]:
    """Match known cleanup locations; outermost match wins so nothing is double-counted."""
    matches: List[Tuple[int, str, str, str, bool]] = []
    for path, size in sorted(scanner.dir_sizes.items(), key=lambda kv: len(kv[0])):
        pl = norm(path)
        for rx, cat, rec, safe in FOLDER_RULES_COMPILED:
            if rx.search(pl):
                if not any(is_under(pl, norm(m[1])) or pl == norm(m[1]) for m in matches):
                    matches.append((size, path, cat, rec, safe))
                break
    matches.sort(key=lambda m: m[0], reverse=True)
    return matches


def classify_file(path: str) -> Optional[Tuple[str, str]]:
    name = os.path.basename(path).lower()
    if name in FILE_NAME_RULES:
        return FILE_NAME_RULES[name]
    return FILE_EXT_RULES.get(os.path.splitext(name)[1])


def size_color(size: int, safe: bool = False) -> str:
    s = format_size(size)
    if safe:
        return f"{Colors.GREEN}{s}{Colors.RESET}"
    if size >= 5 * GB:
        return f"{Colors.RED}{Colors.BOLD}{s}{Colors.RESET}"
    if size >= 1 * GB:
        return f"{Colors.YELLOW}{s}{Colors.RESET}"
    return s


def bar(fraction: float, width: int = 20) -> str:
    filled = max(0, min(width, round(fraction * width)))
    return "#" * filled + "." * (width - filled)


# ----------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Find the biggest space consumers on a drive (default C:).")
    parser.add_argument("--drive", default="C", help="Drive letter to scan (default: C)")
    parser.add_argument("--path", help="Scan this folder instead of the whole drive")
    parser.add_argument("--min-size-mb", type=int, default=250, help="Minimum folder size to report (default: 250)")
    parser.add_argument("--top-dirs", type=int, default=25, help="How many big folders to list (default: 25)")
    parser.add_argument("--top-files", type=int, default=20, help="How many big files to list (default: 20)")
    parser.add_argument("--threads", type=int, default=8, help="Scan threads (default: 8)")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATH",
                        help="Folder to skip entirely (repeatable). 'AVG sandbox' is always skipped: its "
                             "virtualized copies report sizes far beyond the real disk usage.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    else:
        os.system("")  # enables ANSI escape processing in older Windows consoles
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    drive = args.drive.upper().rstrip(":\\/")
    root = os.path.abspath(args.path) if args.path else f"{drive}:\\"
    if not os.path.isdir(root):
        sys.exit(f"Not a folder: {root}")

    total, used, free = shutil.disk_usage(f"{drive}:\\")
    free_pct = free / total * 100
    critical = free_pct < 10 or free < 5 * GB
    status = Colors.RED if critical else Colors.YELLOW if free_pct < 20 else Colors.GREEN

    line = "=" * 100
    print(f"\n{Colors.BOLD}{Colors.CYAN}{line}\n  DRIVE {drive}: SPACE HOG FINDER   (scanning {root}){'':>10}\n{line}{Colors.RESET}")
    print(f"  Total {format_size(total)}   Used {format_size(used)} ({used / total * 100:.1f}%)   "
          f"Free {status}{format_size(free)} ({free_pct:.1f}%){Colors.RESET}")
    if critical:
        print(f"  {Colors.RED}{Colors.BOLD}[!] Free space is dangerously low!{Colors.RESET}")
    if not is_admin():
        print(f"  {Colors.YELLOW}[i] Not running as Administrator: Windows, ProgramData and other users' "
              f"folders may be undercounted.{Colors.RESET}")
    print()

    started = time.time()
    excluded_paths = [os.path.join(f"{drive}:\\", "AVG sandbox")] + [os.path.abspath(e) for e in args.exclude]
    excluded_present = [e for e in excluded_paths if os.path.isdir(e)]
    scanner = Scanner(args.min_size_mb * MB, max(args.top_files * 3, 60), {norm(e) for e in excluded_paths})
    top_level = scanner.scan(root, max(1, args.threads))
    elapsed = time.time() - started
    print(f"  Scanned {scanner.files_seen:,} files in {elapsed:.0f}s "
          f"({scanner.errors:,} inaccessible entries skipped).\n")

    scanned_total = sum(top_level.values())
    for e in excluded_present:
        print(f"  {Colors.DIM}[i] Skipped: {e}" + ("  (AVG sandbox: clear it in AVG > Sandbox settings)"
              if norm(e).endswith("avg sandbox") else "") + f"{Colors.RESET}")
    if excluded_present:
        print()

    # 1. top-level breakdown ------------------------------------------------------------
    print(f"{Colors.BOLD}1) Where the space lives (top level of {root}){Colors.RESET}")
    base = used if not args.path else max(scanned_total, 1)
    for path, size in sorted(top_level.items(), key=lambda kv: kv[1], reverse=True)[:12]:
        if size < 50 * MB:
            continue
        label = os.path.basename(path) or path if not path.startswith("<") else path
        print(f"  {size_color(size)}  {size / base * 100:5.1f}%  {bar(size / base)}  {label}")
    if not args.path:
        hidden = used - scanned_total
        if hidden > 2 * GB:
            print(f"  {Colors.DIM}{format_size(hidden)}  not visible to this scan (shadow copies / System Volume "
                  f"Information / locked or protected files). Check: vssadmin list shadowstorage{Colors.RESET}")
    print()

    # 2. biggest folders ------------------------------------------------------------------
    hogs: List[Tuple[int, str]] = []
    for child in [c for c in top_level if not c.startswith("<")]:
        drill_down(scanner, child, hogs)
    hogs.sort(reverse=True)
    print(f"{Colors.BOLD}2) Biggest folders (drilled down to where the data actually is){Colors.RESET}")
    if not hogs:
        print(f"  {Colors.GREEN}Nothing above {args.min_size_mb} MB.{Colors.RESET}")
    known = {norm(m[1]): m for m in classify_folders(scanner)}
    for size, path in hogs[:args.top_dirs]:
        note = ""
        for kp, m in known.items():
            if norm(path) == kp or is_under(norm(path), kp) or is_under(kp, norm(path)):
                note = f"  {Colors.DIM}<- {m[2]}{Colors.RESET}"
                break
        print(f"  {size_color(size)}  {path}{note}")
    print()

    # 3. biggest files -------------------------------------------------------------------
    print(f"{Colors.BOLD}3) Biggest files{Colors.RESET}")
    for size, path in sorted(scanner.file_heap, reverse=True)[:args.top_files]:
        info = classify_file(path)
        note = f"  {Colors.DIM}<- {info[0]}: {info[1]}{Colors.RESET}" if info else ""
        print(f"  {size_color(size)}  {path}{note}")
    print()

    # 4. cleanup opportunities ------------------------------------------------------------
    matches = classify_folders(scanner)
    print(f"{Colors.BOLD}4) Known cleanup opportunities{Colors.RESET}")
    if not matches:
        print("  None of the known cache/temp/leftover locations exceed the size threshold.")
    for size, path, cat, rec, safe in matches:
        tag = f"{Colors.GREEN}[safe]  {Colors.RESET}" if safe else "[review]"
        print(f"  {size_color(size, safe)}  {tag} {cat:<26} {shorten(path, 60)}")
        print(f"  {'':>11}           {Colors.DIM}-> {rec}{Colors.RESET}")

    safe_total = sum(m[0] for m in matches if m[4])
    print(f"\n{Colors.BOLD}Summary{Colors.RESET}")
    print(f"  {Colors.GREEN}Safe to clean (no overlap counted twice){Colors.RESET}: {format_size(safe_total)}")
    print(f"  {Colors.CYAN}Big folders listed above{Colors.RESET}              : {format_size(sum(s for s, _ in hogs[:args.top_dirs]))}")
    print(f"\n{Colors.DIM}Tips: --min-size-mb 100 for finer detail, --path C:\\Users\\<you> to zoom into one "
          f"folder, --no-color when piping to a file.{Colors.RESET}\n")


if __name__ == "__main__":
    main()
