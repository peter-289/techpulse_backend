#!/usr/bin/env python3
"""
Cross-Platform System Optimizer
================================
A unified tool for disk cleanup, process management, and cache clearing
across Windows, macOS, and Linux systems.

Author: System Optimizer
Version: 1.0.0
"""

import os
import sys
import shutil
import platform
import subprocess
import psutil
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: CROSS-PLATFORM COMPATIBILITY LAYER
# ═══════════════════════════════════════════════════════════════════════════════

class PlatformManager:
    """
    Handles OS detection and platform-specific command mapping.

    WHY THIS MATTERS:
    Different operating systems use different commands, paths, and APIs.
    Windows uses 'taskkill', macOS/Linux use 'kill'. Windows paths use \\
    while Unix uses /. This abstraction layer lets us write one codebase
    that adapts to any OS automatically.

    PERKS:
    - Single script works everywhere
    - Easy to extend for new platforms
    - Centralized OS-specific logic prevents scattered conditionals
    """

    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.is_macos = self.system == "darwin"
        self.is_linux = self.system == "linux"

    def get_home_dir(self) -> Path:
        """Returns the user's home directory in a cross-platform way."""
        return Path.home()

    def get_temp_dir(self) -> Path:
        """Returns system temp directory."""
        return Path(os.environ.get('TEMP', '/tmp') if self.is_windows else '/tmp')

    def run_command(self, command: List[str], shell: bool = False) -> Tuple[int, str, str]:
        """
        Execute a system command safely and return (returncode, stdout, stderr).

        PERK: Using subprocess instead of os.system() prevents shell injection
        and gives us structured output instead of raw text.
        """
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                shell=shell,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out after 30 seconds"
        except Exception as e:
            return -1, "", str(e)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: DISK SCANNER & CLEANER
# ═══════════════════════════════════════════════════════════════════════════════

class DiskScanner:
    """
    Scans directories and allows selective deletion of folders.

    WHY THIS MATTERS:
    Manual cleanup is tedious and error-prone. This provides a numbered
    menu system so users can quickly identify and remove large/unwanted
    folders without navigating deep directory trees.

    PERKS:
    - Visual size representation (human-readable GB/MB/KB)
    - Numbered selection prevents typos in paths
    - Size calculation helps prioritize what to delete
    - Confirmation prompt prevents accidental deletion
    """

    def __init__(self, platform_mgr: PlatformManager):
        self.pm = platform_mgr
        self.scanned_items: List[Dict] = []

    def get_folder_size(self, path: Path) -> int:
        """
        Recursively calculate total size of a directory.

        WHY WE USE WALK INSTEAD OF DU:
        - Pure Python = cross-platform without external dependencies
        - Can handle permission errors gracefully
        - Provides progress opportunity (could add tqdm later)

        PERK: Returns bytes for accurate sorting, formatted later for display.
        """
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += self.get_folder_size(Path(entry.path))
        except (PermissionError, OSError):
            pass  # Skip folders we can't access
        return total

    def format_size(self, size_bytes: int) -> str:
        """Convert bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def scan_directory(self, root_path: str, max_depth: int = 1) -> List[Dict]:
        """
        Scan a directory and return items with sizes.

        max_depth=1 means only immediate children (top-level folders).
        This keeps the menu manageable - scanning recursively through
        entire drives would be overwhelming and slow.

        PERKS:
        - Sorted by size (largest first) so biggest space hogs are visible
        - Skips hidden files by default (cleaner UI)
        - Gracefully handles permission errors
        """
        root = Path(root_path).expanduser().resolve()
        self.scanned_items = []

        if not root.exists():
            print(f"[ERROR] Path does not exist: {root}")
            return []

        print(f"\n[SCANNING] Analyzing: {root}")
        print("=" * 60)

        try:
            entries = list(root.iterdir())
        except PermissionError:
            print("[ERROR] Permission denied. Try running as administrator/root.")
            return []

        for entry in entries:
            if entry.name.startswith('.') and entry.name != '..':
                continue  # Skip hidden files

            try:
                if entry.is_dir(follow_symlinks=False):
                    size = self.get_folder_size(entry)
                    self.scanned_items.append({
                        'path': entry,
                        'name': entry.name,
                        'size': size,
                        'type': 'directory'
                    })
                elif entry.is_file(follow_symlinks=False):
                    size = entry.stat().st_size
                    self.scanned_items.append({
                        'path': entry,
                        'name': entry.name,
                        'size': size,
                        'type': 'file'
                    })
            except (PermissionError, OSError):
                continue

        # Sort by size descending (largest first)
        self.scanned_items.sort(key=lambda x: x['size'], reverse=True)
        return self.scanned_items

    def display_menu(self) -> None:
        """Display numbered menu of scanned items."""
        if not self.scanned_items:
            print("No items found.")
            return

        print(f"\n{'#':<4} {'Type':<10} {'Size':<12} {'Name'}")
        print("-" * 70)

        for idx, item in enumerate(self.scanned_items, 1):
            icon = "📁" if item['type'] == 'directory' else "📄"
            size_str = self.format_size(item['size'])
            name = item['name'][:40] + "..." if len(item['name']) > 40 else item['name']
            print(f"{idx:<4} {icon:<10} {size_str:<12} {name}")

        print(f"\nTotal items: {len(self.scanned_items)}")
        total_size = sum(item['size'] for item in self.scanned_items)
        print(f"Combined size: {self.format_size(total_size)}")

    def delete_item(self, selection: int) -> bool:
        """
        Delete item by menu number with confirmation.

        SAFETY FEATURES:
        - Confirmation prompt prevents accidents
        - Try-except catches locked files / permission issues
        - Returns success/failure for logging

        PERK: Using shutil.rmtree() for dirs and unlink() for files
        is more reliable than os.remove() for nested structures.
        """
        if not (1 <= selection <= len(self.scanned_items)):
            print("[ERROR] Invalid selection number.")
            return False

        item = self.scanned_items[selection - 1]
        path = item['path']
        size_str = self.format_size(item['size'])

        print(f"\n[WARNING] You are about to delete:")
        print(f"  Path: {path}")
        print(f"  Size: {size_str}")
        print(f"  Type: {item['type']}")

        confirm = input("\nType 'DELETE' to confirm (or anything else to cancel): ")

        if confirm.strip().upper() != 'DELETE':
            print("[CANCELLED] Deletion aborted.")
            return False

        try:
            if item['type'] == 'directory':
                shutil.rmtree(path)
            else:
                path.unlink()
            print(f"[SUCCESS] Deleted: {path}")
            return True
        except PermissionError:
            print(f"[ERROR] Permission denied. File/folder may be in use.")
            print("[TIP] Close any programs using this file, or run as admin.")
        except Exception as e:
            print(f"[ERROR] Failed to delete: {e}")

        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: SYSTEM RESOURCE MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

class ResourceMonitor:
    """
    Displays RAM usage and high-resource processes.

    WHY THIS MATTERS:
    Before cleaning, you need to know what's consuming resources.
    This identifies memory hogs and CPU-intensive processes that
    might be slowing your system.

    PERKS:
    - Uses psutil (cross-platform system monitoring)
    - Color-coded thresholds (green/yellow/red)
    - Shows process names, not just PIDs
    - Can identify processes to terminate before cleanup
    """

    def __init__(self, platform_mgr: PlatformManager):
        self.pm = platform_mgr

    def get_ram_usage(self) -> Dict:
        """
        Get detailed RAM statistics.

        METRICS EXPLAINED:
        - total: Physical RAM installed
        - available: RAM free for new programs (includes cached)
        - percent: Percentage currently used
        - used: RAM actively in use
        - free: Completely unused RAM

        PERK: 'available' is more useful than 'free' on Linux/macOS
        because it includes cache that can be freed instantly.
        """
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used,
            'free': mem.free
        }

    def format_bytes(self, bytes_val: int) -> str:
        """Convert bytes to GB for display."""
        return f"{bytes_val / (1024**3):.2f} GB"

    def color_percent(self, percent: float) -> str:
        """Return colored percentage string for terminal display."""
        if percent >= 90:
            return f"\033[91m{percent:.1f}%\033[0m"  # Red
        elif percent >= 70:
            return f"\033[93m{percent:.1f}%\033[0m"  # Yellow
        else:
            return f"\033[92m{percent:.1f}%\033[0m"  # Green

    def display_ram(self) -> None:
        """Display RAM usage with visual bar."""
        ram = self.get_ram_usage()

        print("\n" + "=" * 60)
        print("MEMORY (RAM) USAGE")
        print("=" * 60)

        # Visual bar (50 chars wide)
        bar_width = 50
        filled = int((ram['percent'] / 100) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        color = "\033[92m" if ram['percent'] < 70 else "\033[93m" if ram['percent'] < 90 else "\033[91m"
        reset = "\033[0m"

        print(f"[{color}{bar}{reset}] {self.color_percent(ram['percent'])}")
        print(f"  Total:     {self.format_bytes(ram['total'])}")
        print(f"  Used:      {self.format_bytes(ram['used'])}")
        print(f"  Available: {self.format_bytes(ram['available'])}")
        print(f"  Free:      {self.format_bytes(ram['free'])}")

        if ram['percent'] > 90:
            print("\n[WARNING] RAM usage is critically high! Consider closing applications.")
        elif ram['percent'] > 75:
            print("\n[NOTICE] RAM usage is elevated. Cleanup recommended.")

    def get_high_resource_processes(self, top_n: int = 10) -> List[Dict]:
        """
        Find processes consuming the most memory and CPU.

        SORTING LOGIC:
        We use a composite score: memory_percent * 0.6 + cpu_percent * 0.4
        This balances both metrics rather than focusing on just one.

        PERKS:
        - Skips system processes (PID < 100) to focus on user apps
        - Handles processes that terminate during scan gracefully
        - Shows both memory and CPU for complete picture
        """
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
            try:
                info = proc.info
                # Skip system processes and low-impact ones
                if info['pid'] < 100 or (info['memory_percent'] or 0) < 0.1:
                    continue

                # Composite score for ranking
                mem = info['memory_percent'] or 0
                cpu = info['cpu_percent'] or 0
                score = (mem * 0.6) + (cpu * 0.4)

                processes.append({
                    'pid': info['pid'],
                    'name': info['name'] or 'Unknown',
                    'memory_percent': mem,
                    'cpu_percent': cpu,
                    'score': score
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by composite score descending
        processes.sort(key=lambda x: x['score'], reverse=True)
        return processes[:top_n]

    def display_processes(self) -> None:
        """Display high-resource processes in a table."""
        procs = self.get_high_resource_processes(15)

        print("\n" + "=" * 80)
        print("HIGH RESOURCE PROCESSES (Top 15)")
        print("=" * 80)
        print(f"{'PID':<10} {'Process Name':<30} {'Memory %':<12} {'CPU %':<10}")
        print("-" * 80)

        for proc in procs:
            name = proc['name'][:28] + ".." if len(proc['name']) > 30 else proc['name']
            mem_color = "\033[91m" if proc['memory_percent'] > 10 else "\033[0m"
            cpu_color = "\033[91m" if proc['cpu_percent'] > 50 else "\033[0m"
            reset = "\033[0m"

            print(f"{proc['pid']:<10} {name:<30} "
                  f"{mem_color}{proc['memory_percent']:.1f}%{reset:<6} "
                  f"{cpu_color}{proc['cpu_percent']:.1f}%{reset}")

        print("\n[TIP] High memory processes are candidates for closing before cleanup.")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: CACHE CLEANER
# ═══════════════════════════════════════════════════════════════════════════════

class CacheCleaner:
    """
    Clears browser and application caches across platforms.

    WHY THIS MATTERS:
    Browsers accumulate GBs of cache over time. Apps store temp files
    that persist forever. This frees disk space and can fix performance
    issues caused by corrupted cache.

    PERKS:
    - Targets common cache locations for all major browsers
    - Cross-platform path resolution
    - Safe deletion (only cache/temp files, not bookmarks/passwords)
    - Reports space freed

    SAFETY NOTE:
    Only deletes cache/temp directories. Bookmarks, passwords, and
    user data are NEVER touched.
    """

    def __init__(self, platform_mgr: PlatformManager):
        self.pm = platform_mgr
        self.home = platform_mgr.get_home_dir()
        self.freed_space = 0
        self.items_cleared = 0

    def get_browser_cache_paths(self) -> Dict[str, List[Path]]:
        """
        Define cache paths for major browsers on each OS.

        BROWSERS SUPPORTED:
        - Chrome/Chromium (all platforms)
        - Firefox (all platforms)
        - Safari (macOS)
        - Edge (Windows/macOS)
        - Opera (all platforms)

        PERK: Using Path objects ensures correct path separators
        regardless of which OS the script runs on.
        """
        paths = {
            'Chrome': [],
            'Firefox': [],
            'Safari': [],
            'Edge': [],
            'Opera': [],
            'System': []
        }

        if self.pm.is_windows:
            # Windows paths use LOCALAPPDATA for browser data
            local_appdata = Path(os.environ.get('LOCALAPPDATA', ''))
            roaming = Path(os.environ.get('APPDATA', ''))

            paths['Chrome'] = [
                local_appdata / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
                local_appdata / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache",
            ]
            paths['Edge'] = [
                local_appdata / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
                local_appdata / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache",
            ]
            paths['Firefox'] = [
                roaming / "Mozilla" / "Firefox" / "Profiles",
            ]
            paths['Opera'] = [
                roaming / "Opera Software" / "Opera Stable" / "Cache",
            ]
            paths['System'] = [
                Path(os.environ.get('TEMP', 'C:/Windows/Temp')),
                local_appdata / "Temp",
            ]

        elif self.pm.is_macos:
            # macOS uses Library/Application Support
            paths['Chrome'] = [
                self.home / "Library" / "Caches" / "Google" / "Chrome" / "Default" / "Cache",
                self.home / "Library" / "Caches" / "Google" / "Chrome" / "Default" / "Code Cache",
            ]
            paths['Safari'] = [
                self.home / "Library" / "Caches" / "com.apple.Safari",
                self.home / "Library" / "Caches" / "com.apple.WebKit.PluginProcess",
            ]
            paths['Firefox'] = [
                self.home / "Library" / "Caches" / "Firefox" / "Profiles",
            ]
            paths['Edge'] = [
                self.home / "Library" / "Caches" / "Microsoft Edge" / "Default" / "Cache",
            ]
            paths['Opera'] = [
                self.home / "Library" / "Caches" / "com.operasoftware.Opera",
            ]
            paths['System'] = [
                self.home / "Library" / "Caches",
                "/Library/Caches",
                "/System/Library/Caches",
            ]

        elif self.pm.is_linux:
            # Linux uses .config and .cache in home
            paths['Chrome'] = [
                self.home / ".cache" / "google-chrome" / "Default" / "Cache",
                self.home / ".cache" / "google-chrome" / "Default" / "Code Cache",
                self.home / ".cache" / "chromium" / "Default" / "Cache",
            ]
            paths['Firefox'] = [
                self.home / ".cache" / "mozilla" / "firefox",
            ]
            paths['Opera'] = [
                self.home / ".cache" / "opera",
            ]
            paths['Edge'] = [
                self.home / ".cache" / "microsoft-edge" / "Default" / "Cache",
            ]
            paths['System'] = [
                self.home / ".cache",
                "/var/cache",
                "/tmp",
            ]

        return paths

    def get_folder_size_safe(self, path: Path) -> int:
        """Get size, returning 0 if path doesn't exist."""
        if not path.exists():
            return 0
        try:
            total = 0
            for entry in os.scandir(path):
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += self.get_folder_size_safe(Path(entry.path))
            return total
        except (PermissionError, OSError):
            return 0

    def clear_directory(self, path: Path) -> Tuple[int, int]:
        """
        Clear contents of a directory without deleting the directory itself.

        WHY NOT DELETE THE WHOLE FOLDER?
        Browsers recreate cache folders with specific permissions.
        Clearing contents preserves the folder structure while removing data.

        RETURNS: (items_deleted, bytes_freed)
        """
        if not path.exists():
            return 0, 0

        items = 0
        freed = 0

        try:
            for entry in os.scandir(path):
                try:
                    if entry.is_file(follow_symlinks=False):
                        freed += entry.stat().st_size
                        os.remove(entry.path)
                        items += 1
                    elif entry.is_dir(follow_symlinks=False):
                        freed += self.get_folder_size_safe(Path(entry.path))
                        shutil.rmtree(entry.path)
                        items += 1
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

        return items, freed

    def clear_browser_caches(self) -> None:
        """
        Main method to clear all identified caches.

        WORKFLOW:
        1. Identify which browsers are installed (path exists)
        2. Calculate space used before deletion
        3. Clear each cache directory
        4. Report total space freed

        PERKS:
        - Only processes existing browser installations
        - Reports per-browser and total savings
        - Gracefully handles browsers that are currently running
        """
        print("\n" + "=" * 60)
        print("CACHE CLEANER")
        print("=" * 60)

        cache_paths = self.get_browser_cache_paths()
        total_freed = 0
        total_items = 0

        for browser, paths in cache_paths.items():
            browser_found = False
            browser_freed = 0
            browser_items = 0

            for path in paths:
                if path.exists():
                    browser_found = True
                    # Handle Firefox profiles directory specially
                    if 'Profiles' in str(path) and path.is_dir():
                        for profile in path.iterdir():
                            if profile.is_dir():
                                cache_dir = profile / "cache2"
                                if cache_dir.exists():
                                    items, freed = self.clear_directory(cache_dir)
                                    browser_items += items
                                    browser_freed += freed
                    else:
                        items, freed = self.clear_directory(path)
                        browser_items += items
                        browser_freed += freed

            if browser_found:
                size_str = self.format_size(browser_freed)
                print(f"  ✓ {browser:<12} Cleared {browser_items} items, freed {size_str}")
                total_freed += browser_freed
                total_items += browser_items
            else:
                print(f"  ○ {browser:<12} Not installed or no cache found")

        self.freed_space = total_freed
        self.items_cleared = total_items

        print(f"\n[TOTAL] Cleared {total_items} items, freed {self.format_size(total_freed)}")

    def format_size(self, size_bytes: int) -> str:
        """Convert bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: MAIN APPLICATION CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════════

class SystemOptimizer:
    """
    Main controller that orchestrates all optimization modules.

    DESIGN PATTERN:
    Uses composition to bring together independent modules.
    Each class has a single responsibility (SRP), making the code
    maintainable and testable.

    PERKS:
    - Menu-driven interface
    - Can run individual functions or full optimization
    - Progress reporting throughout
    - Error recovery (one module failing doesn't crash others)
    """

    def __init__(self):
        self.pm = PlatformManager()
        self.scanner = DiskScanner(self.pm)
        self.monitor = ResourceMonitor(self.pm)
        self.cleaner = CacheCleaner(self.pm)

    def print_banner(self) -> None:
        """Display welcome banner with system info."""
        os_name = platform.system()
        os_version = platform.version()

        print("\n" + "█" * 70)
        print("█" + " " * 68 + "█")
        print("█" + "   CROSS-PLATFORM SYSTEM OPTIMIZER".center(68) + "█")
        print("█" + f"   OS: {os_name} {os_version}".center(68) + "█")
        print("█" + f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(68) + "█")
        print("█" + " " * 68 + "█")
        print("█" * 70)

    def show_main_menu(self) -> str:
        """Display main menu and get user choice."""
        print("\n" + "=" * 60)
        print("MAIN MENU")
        print("=" * 60)
        print("  1. Scan Disk & Clean Folders")
        print("  2. Show RAM Usage & Processes")
        print("  3. Clear Browser & App Caches")
        print("  4. Full System Optimization (Run All)")
        print("  5. Exit")
        print("=" * 60)

        choice = input("\nEnter your choice (1-5): ").strip()
        return choice

    def run_disk_cleanup(self) -> None:
        """Interactive disk scanning and cleanup workflow."""
        print("\n[DISK CLEANUP]")
        print("-" * 60)

        # Default paths per OS
        if self.pm.is_windows:
            default_path = str(Path.home())
        elif self.pm.is_macos:
            default_path = str(Path.home() / "Library" / "Caches")
        else:
            default_path = str(Path.home())

        custom = input(f"Enter path to scan [default: {default_path}]: ").strip()
        scan_path = custom if custom else default_path

        items = self.scanner.scan_directory(scan_path)

        if not items:
            print("No items to display.")
            return

        self.scanner.display_menu()

        while True:
            choice = input("\nEnter number to delete (or 'q' to quit): ").strip().lower()
            if choice == 'q':
                break

            try:
                num = int(choice)
                self.scanner.delete_item(num)
                # Refresh the menu after deletion
                items = self.scanner.scan_directory(scan_path)
                self.scanner.display_menu()
            except ValueError:
                print("Please enter a valid number or 'q'.")

    def run_resource_monitor(self) -> None:
        """Display system resource information."""
        self.monitor.display_ram()
        self.monitor.display_processes()

        print("\n[NOTE] To terminate a process, note its PID and use your OS task manager")
        print("       or run: taskkill /PID <pid> /F  (Windows)")
        print("                kill -9 <pid>          (macOS/Linux)")

    def run_cache_cleaner(self) -> None:
        """Run cache clearing with confirmation."""
        print("\n[WARNING] This will clear browser caches and temporary files.")
        print("          You may need to re-login to websites.")

        confirm = input("Continue? (yes/no): ").strip().lower()
        if confirm in ('yes', 'y'):
            self.cleaner.clear_browser_caches()
        else:
            print("[CANCELLED] Cache cleaning aborted.")

    def run_full_optimization(self) -> None:
        """Execute complete optimization sequence."""
        print("\n" + "█" * 60)
        print("█" + " FULL SYSTEM OPTIMIZATION ".center(58) + "█")
        print("█" * 60)

        # Step 1: Resource assessment
        print("\n[STEP 1/3] Assessing system resources...")
        self.monitor.display_ram()

        # Step 2: Cache cleanup
        print("\n[STEP 2/3] Clearing caches...")
        self.cleaner.clear_browser_caches()

        # Step 3: Disk analysis
        print("\n[STEP 3/3] Analyzing disk usage...")
        if self.pm.is_windows:
            scan_path = str(Path.home() / "AppData" / "Local" / "Temp")
        elif self.pm.is_macos:
            scan_path = str(Path.home() / "Library" / "Caches")
        else:
            scan_path = "/tmp"

        items = self.scanner.scan_directory(scan_path)
        if items:
            self.scanner.display_menu()
            print("\n[NOTICE] Large temp files detected above. Review and delete as needed.")

        # Summary
        print("\n" + "=" * 60)
        print("OPTIMIZATION COMPLETE")
        print("=" * 60)
        print(f"Cache freed: {self.cleaner.format_size(self.cleaner.freed_space)}")
        print("\n[TIPS FOR BETTER PERFORMANCE]")
        print("  • Restart your browser for cache changes to take full effect")
        print("  • Consider uninstalling unused applications")
        print("  • Run disk cleanup weekly for maintenance")
        print("  • Disable startup programs you don't need")

    def run(self) -> None:
        """Main application loop."""
        self.print_banner()

        # Check for required dependencies
        try:
            import psutil
        except ImportError:
            print("\n[ERROR] Required package 'psutil' is not installed.")
            print("[FIX] Run: pip install psutil")
            sys.exit(1)

        while True:
            choice = self.show_main_menu()

            if choice == '1':
                self.run_disk_cleanup()
            elif choice == '2':
                self.run_resource_monitor()
            elif choice == '3':
                self.run_cache_cleaner()
            elif choice == '4':
                self.run_full_optimization()
            elif choice == '5':
                print("\n[EXIT] Thank you for using System Optimizer!")
                break
            else:
                print("\n[ERROR] Invalid choice. Please enter 1-5.")

            input("\nPress Enter to continue...")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: COMMAND-LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

def parse_arguments():
    """
    Allow running specific functions via command line without menu.

    EXAMPLES:
        python optimizer.py --monitor          # Just show resources
        python optimizer.py --cache            # Just clear caches
        python optimizer.py --scan /path      # Scan specific path
        python optimizer.py --full             # Run everything

    PERK: Useful for automation/scheduling (cron jobs, Task Scheduler).
    """
    parser = argparse.ArgumentParser(
        description="Cross-Platform System Optimizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Launch interactive menu
  %(prog)s --monitor          Show RAM and processes only
  %(prog)s --cache            Clear caches only
  %(prog)s --scan /tmp        Scan specific directory
  %(prog)s --full             Run full optimization
        """
    )

    parser.add_argument('--monitor', action='store_true',
                        help='Display RAM usage and high-resource processes')
    parser.add_argument('--cache', action='store_true',
                        help='Clear browser and application caches')
    parser.add_argument('--scan', metavar='PATH',
                        help='Scan directory for cleanup (interactive)')
    parser.add_argument('--full', action='store_true',
                        help='Run complete optimization sequence')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')

    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    args = parse_arguments()
    optimizer = SystemOptimizer()

    # Determine execution mode based on arguments
    if args.monitor:
        optimizer.print_banner()
        optimizer.run_resource_monitor()
    elif args.cache:
        optimizer.print_banner()
        optimizer.run_cache_cleaner()
    elif args.scan:
        optimizer.print_banner()
        items = optimizer.scanner.scan_directory(args.scan)
        if items:
            optimizer.scanner.display_menu()
            # Allow single deletion via CLI
            if len(sys.argv) > 3 and sys.argv[3].isdigit():
                optimizer.scanner.delete_item(int(sys.argv[3]))
    elif args.full:
        optimizer.print_banner()
        optimizer.run_full_optimization()
    else:
        # Interactive mode (default)
        optimizer.run()
