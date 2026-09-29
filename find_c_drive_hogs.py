#!/usr/bin/env python3
"""
C: Drive High-Value Space Target Analyzer
Identifies and categorizes large folders/files on Drive C: that can be safely cleaned,
moved, or uninstalled, while strictly skipping core Windows OS directories and NTFS junctions.
"""

import os
import sys
import stat
import shutil
import argparse
import re
from typing import List, Dict, Optional, Tuple, Set

FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Safe skip list (do not scan or touch core system directories)
SYSTEM_DIR_NAMES = {
    "windows",
    "system volume information",
    "$winreagent",
    "$sysreset",
    "$recycle.bin",
    "config.msi",
    "recovery",
    "perflogs",
    "msocache",
}

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes for accurate visual length calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", text)

def pad_visible(text: str, width: int, align: str = "left") -> str:
    """Pad string considering visible characters only (ignoring ANSI codes)."""
    vis_len = len(strip_ansi(text))
    pad_needed = max(0, width - vis_len)
    if align == "right":
        return (" " * pad_needed) + text
    return text + (" " * pad_needed)

def is_junction_or_symlink(path: str) -> bool:
    """Return True if path is an NTFS junction, symlink, or reparse point."""
    try:
        s = os.lstat(path)
        attrs = getattr(s, "st_file_attributes", 0)
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, PermissionError):
        return False

def get_directory_size(path: str, max_depth: int = 15) -> int:
    """
    Recursively computes physical directory size in bytes.
    Skips NTFS junctions and handles permission errors safely.
    """
    if max_depth <= 0 or is_junction_or_symlink(path):
        return 0

    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
                    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        total += get_directory_size(entry.path, max_depth - 1)
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass
    return total

def format_size(bytes_val: int) -> str:
    """Format bytes into human-readable string."""
    gb = bytes_val / (1024 ** 3)
    if gb >= 1.0:
        return f"{gb:6.2f} GB"
    mb = bytes_val / (1024 ** 2)
    return f"{mb:6.1f} MB"

class TargetItem:
    def __init__(self, path: str, size: int, category: str, recommendation: str, safe_to_delete: bool = False):
        self.path = path
        self.size = size
        self.category = category
        self.recommendation = recommendation
        self.safe_to_delete = safe_to_delete

def scan_user_profiles(drive_letter: str, min_size_bytes: int) -> List[TargetItem]:
    targets: List[TargetItem] = []
    accounted_prefixes: Set[str] = set()
    users_root = f"{drive_letter}:\\Users"

    if not os.path.exists(users_root):
        return targets

    try:
        user_dirs = [
            f.path for f in os.scandir(users_root)
            if f.is_dir(follow_symlinks=False) and not is_junction_or_symlink(f.path)
            and f.name.lower() not in ("public", "default", "all users")
        ]
    except (PermissionError, OSError):
        return targets

    for u_path in user_dirs:
        # 1. Pip Cache
        pip_cache = os.path.join(u_path, "AppData", "Local", "pip", "cache")
        if os.path.exists(pip_cache):
            size = get_directory_size(pip_cache)
            if size >= min_size_bytes:
                targets.append(TargetItem(
                    path=pip_cache,
                    size=size,
                    category="Developer Cache",
                    recommendation="Run 'pip cache purge' in terminal",
                    safe_to_delete=True
                ))
                accounted_prefixes.add(os.path.join(u_path, "AppData", "Local", "pip").lower())

        # 2. PyCharm / JetBrains Caches & Logs
        jb_root = os.path.join(u_path, "AppData", "Local", "JetBrains")
        if os.path.exists(jb_root):
            try:
                for entry in os.scandir(jb_root):
                    if entry.is_dir(follow_symlinks=False) and not is_junction_or_symlink(entry.path):
                        for sub_name in ["index", "splash", "caches", "log"]:
                            sub_dir = os.path.join(entry.path, sub_name)
                            if os.path.exists(sub_dir):
                                sz = get_directory_size(sub_dir)
                                if sz >= 100 * 1024 * 1024:
                                    targets.append(TargetItem(
                                        path=sub_dir,
                                        size=sz,
                                        category="IDE Cache / Logs",
                                        recommendation="PyCharm File > Invalidate Caches, or clean logs",
                                        safe_to_delete=True
                                    ))
                accounted_prefixes.add(jb_root.lower())
            except (PermissionError, OSError):
                pass

        # 3. MetaTrader (MetaQuotes) Data, Bases & Tester
        mq_terminals = os.path.join(u_path, "AppData", "Roaming", "MetaQuotes", "Terminal")
        if os.path.exists(mq_terminals):
            try:
                for t_entry in os.scandir(mq_terminals):
                    if t_entry.is_dir(follow_symlinks=False) and not is_junction_or_symlink(t_entry.path):
                        for sub_name in ["bases", "Tester", "logs"]:
                            sub_p = os.path.join(t_entry.path, sub_name)
                            if os.path.exists(sub_p):
                                sz = get_directory_size(sub_p)
                                if sz >= min_size_bytes:
                                    targets.append(TargetItem(
                                        path=sub_p,
                                        size=sz,
                                        category="Trading Data Cache",
                                        recommendation="Safe to delete tick data/tester cache (MT5 re-downloads on demand)",
                                        safe_to_delete=True
                                    ))
                accounted_prefixes.add(os.path.join(u_path, "AppData", "Roaming", "MetaQuotes").lower())
            except (PermissionError, OSError):
                pass

        # 4. Codex & Agent Caches
        codex_cache = os.path.join(u_path, ".cache", "codex-runtimes")
        if os.path.exists(codex_cache):
            sz = get_directory_size(codex_cache)
            if sz >= min_size_bytes:
                targets.append(TargetItem(
                    path=codex_cache,
                    size=sz,
                    category="Sandbox Runtime Cache",
                    recommendation="Safe to delete codex-runtimes folder",
                    safe_to_delete=True
                ))
                accounted_prefixes.add(codex_cache.lower())

        codex_sessions = os.path.join(u_path, ".codex")
        if os.path.exists(codex_sessions):
            sz = get_directory_size(codex_sessions)
            if sz >= min_size_bytes:
                targets.append(TargetItem(
                    path=codex_sessions,
                    size=sz,
                    category="Codex Sessions & Binaries",
                    recommendation="Clean old .tmp or sessions within .codex",
                    safe_to_delete=False
                ))
                accounted_prefixes.add(codex_sessions.lower())

        # 5. User Temp Folder
        u_temp = os.path.join(u_path, "AppData", "Local", "Temp")
        if os.path.exists(u_temp):
            sz = get_directory_size(u_temp)
            if sz >= min_size_bytes:
                targets.append(TargetItem(
                    path=u_temp,
                    size=sz,
                    category="Temp Files",
                    recommendation="Safe to delete temporary files",
                    safe_to_delete=True
                ))
                accounted_prefixes.add(u_temp.lower())

        # 6. Catch-all scan for AppData, Documents, and Downloads
        scan_roots = [
            (os.path.join(u_path, "AppData", "Local"), "Local App Data / Cache"),
            (os.path.join(u_path, "AppData", "Roaming"), "Roaming App Data"),
            (os.path.join(u_path, "Documents"), "User Documents / Media"),
            (os.path.join(u_path, "Downloads"), "User Downloads"),
        ]

        for s_root, cat_label in scan_roots:
            if not os.path.exists(s_root) or is_junction_or_symlink(s_root):
                continue
            try:
                for entry in os.scandir(s_root):
                    if entry.is_dir(follow_symlinks=False) and not is_junction_or_symlink(entry.path):
                        norm_p = entry.path.lower()
                        # Avoid duplicating folders whose sub-components were already reported
                        if norm_p in accounted_prefixes or any(norm_p.startswith(p + "\\") for p in accounted_prefixes):
                            continue
                        sz = get_directory_size(entry.path)
                        if sz >= min_size_bytes:
                            rec = "Investigate: move large data to secondary drive or uninstall"
                            if "download" in entry.name.lower():
                                rec = "Clean up downloaded files or move to secondary drive"
                            elif "viber" in entry.name.lower() or "telegram" in entry.name.lower():
                                rec = "Downloaded chat media; clean old media or move to secondary drive"
                            elif "ninjatrader" in entry.name.lower():
                                rec = "Trading DB/historical tick data; move or clean old DB/logs"
                            elif "maxthon" in entry.name.lower():
                                rec = "Browser profile/cache; clear history & cache within browser"
                            targets.append(TargetItem(
                                path=entry.path,
                                size=sz,
                                category=cat_label,
                                recommendation=rec,
                                safe_to_delete=False
                            ))
            except (PermissionError, OSError):
                pass

    return targets

def scan_root_targets(drive_letter: str, min_size_bytes: int) -> List[TargetItem]:
    targets = []
    root = f"{drive_letter}:\\"

    # Root files like pagefile.sys, hiberfil.sys
    pagefile = os.path.join(root, "pagefile.sys")
    if os.path.exists(pagefile):
        try:
            sz = os.lstat(pagefile).st_size
            targets.append(TargetItem(
                path=pagefile,
                size=sz,
                category="Virtual Memory (Paging File)",
                recommendation="Move Windows pagefile to secondary drive (e.g. I:) in System Properties",
                safe_to_delete=False
            ))
        except (PermissionError, OSError):
            pass

    # Root non-system folders
    try:
        for entry in os.scandir(root):
            if entry.name.lower() in SYSTEM_DIR_NAMES or entry.name.lower() in ("users", "program files", "program files (x86)", "programdata"):
                continue
            if entry.is_dir(follow_symlinks=False) and not is_junction_or_symlink(entry.path):
                sz = get_directory_size(entry.path)
                if sz >= min_size_bytes:
                    targets.append(TargetItem(
                        path=entry.path,
                        size=sz,
                        category="Root Directory",
                        recommendation="User/app directory on C:; move to another drive if possible",
                        safe_to_delete=False
                    ))
    except (PermissionError, OSError):
        pass

    return targets

def scan_program_files(drive_letter: str, min_size_bytes: int = 1024 * 1024 * 1024) -> List[TargetItem]:
    targets = []
    for pf_name in ["Program Files", "Program Files (x86)"]:
        pf_path = f"{drive_letter}:\\{pf_name}"
        if not os.path.exists(pf_path):
            continue
        try:
            for entry in os.scandir(pf_path):
                if entry.name.lower() in ("common files", "windows nt", "windows defender", "windows media player", "microsoft"):
                    continue
                if entry.is_dir(follow_symlinks=False) and not is_junction_or_symlink(entry.path):
                    sz = get_directory_size(entry.path)
                    if sz >= min_size_bytes:
                        targets.append(TargetItem(
                            path=entry.path,
                            size=sz,
                            category="Installed Program / Game",
                            recommendation="Uninstall if unused or reinstall onto secondary drive",
                            safe_to_delete=False
                        ))
        except (PermissionError, OSError):
            pass
    return targets

def get_drive_stats(drive_letter: str) -> Tuple[int, int, int]:
    total, used, free = shutil.disk_usage(f"{drive_letter}:\\")
    return total, used, free

def main():
    parser = argparse.ArgumentParser(description="Find high-value disk space consumers on Drive C: (or specified drive).")
    parser.add_argument("--drive", default="C", help="Drive letter to check (default: C)")
    parser.add_argument("--min-size-mb", type=int, default=250, help="Minimum directory size in MB to report (default: 250 MB)")
    parser.add_argument("--include-apps", action="store_true", default=True, help="Include large installed programs in Program Files (>1GB)")
    parser.add_argument("--no-apps", action="store_false", dest="include_apps", help="Exclude Program Files")
    args = parser.parse_args()

    drive = args.drive.upper().rstrip(":\\")
    min_bytes = args.min_size_mb * 1024 * 1024

    print(f"\n{Colors.BOLD}{Colors.CYAN}==================================================================================================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}                                      DRIVE {drive}: HIGH-VALUE SPACE CONSUMER ANALYZER                                            {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}==================================================================================================================================={Colors.RESET}\n")

    total, used, free = get_drive_stats(drive)
    free_pct = (free / total) * 100
    used_pct = (used / total) * 100

    status_color = Colors.GREEN
    if free_pct < 10.0 or (free / (1024**3)) < 5.0:
        status_color = Colors.RED
    elif free_pct < 20.0:
        status_color = Colors.YELLOW

    print(f"Drive {drive}:\\ Status:")
    print(f"  • Total Capacity : {format_size(total)}")
    print(f"  • Used Space     : {format_size(used)} ({used_pct:.1f}%)")
    print(f"  • Free Space     : {status_color}{format_size(free)} ({free_pct:.1f}%){Colors.RESET}")

    if free_pct < 10.0 or (free / (1024**3)) < 5.0:
        print(f"\n{Colors.RED}{Colors.BOLD}[!] CRITICAL WARNING: Free space is dangerously low!{Colors.RESET}")

    print(f"\nScanning for high-value targets (> {args.min_size_mb} MB)...", end="", flush=True)

    targets: List[TargetItem] = []
    targets.extend(scan_user_profiles(drive, min_bytes))
    targets.extend(scan_root_targets(drive, min_bytes))
    if args.include_apps:
        targets.extend(scan_program_files(drive, 1024 * 1024 * 1024))

    print(" Done.\n")

    if not targets:
        print(f"{Colors.GREEN}No large targets found above {args.min_size_mb} MB.{Colors.RESET}\n")
        return

    # Sort descending by size
    targets.sort(key=lambda x: x.size, reverse=True)

    safe_cleanable_bytes = sum(t.size for t in targets if t.safe_to_delete)
    total_targeted_bytes = sum(t.size for t in targets)

    col_size = 11
    col_cat = 26
    col_path = 48
    col_rec = 45

    header = (
        pad_visible("Size", col_size, "right") + " | " +
        pad_visible("Category", col_cat) + " | " +
        pad_visible("Target Path", col_path) + " | " +
        "Recommended Action"
    )
    separator = "-" * (col_size + col_cat + col_path + col_rec + 9)

    print(f"{Colors.BOLD}{header}{Colors.RESET}")
    print(separator)

    for t in targets:
        raw_size_str = format_size(t.size)
        if t.safe_to_delete:
            size_colored = f"{Colors.GREEN}{raw_size_str}{Colors.RESET}"
        elif t.size >= 3 * (1024**3):
            size_colored = f"{Colors.RED}{Colors.BOLD}{raw_size_str}{Colors.RESET}"
        elif t.size >= 1 * (1024**3):
            size_colored = f"{Colors.YELLOW}{raw_size_str}{Colors.RESET}"
        else:
            size_colored = raw_size_str

        size_cell = pad_visible(size_colored, col_size, "right")
        cat_cell = pad_visible(t.category, col_cat)

        path_disp = t.path
        if len(path_disp) > (col_path - 2):
            path_disp = "..." + path_disp[-(col_path - 5):]
        path_cell = pad_visible(path_disp, col_path)

        print(f"{size_cell} | {cat_cell} | {path_cell} | {t.recommendation}")

    print(separator)
    print(f"\n{Colors.BOLD}Summary of Potential Gains:{Colors.RESET}")
    print(f"  • {Colors.GREEN}Instantly Safe to Clean/Purge{Colors.RESET} : {format_size(safe_cleanable_bytes)}")
    print(f"  • {Colors.CYAN}Total High-Value Targets Found{Colors.RESET} : {format_size(total_targeted_bytes)}")
    print("\nTip: Run with `--min-size-mb 100` to inspect smaller folders.")
    print("     Run with `--no-apps` to skip Program Files.")
    print()

if __name__ == "__main__":
    main()
