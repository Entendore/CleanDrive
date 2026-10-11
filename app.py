#!/usr/bin/env python3
"""
Drive Cleanup Analyzer Pro v2.0 - Cross-Platform Edition
Enhanced with advanced features for comprehensive drive cleanup analysis.

New in v2.0:
  - Custom scan path (browse to any folder)
  - Exclusion patterns (skip paths matching patterns)
  - Score threshold slider for real-time filtering
  - Visual disk usage bar
  - Top largest files panel on dashboard
  - Duplicate finder: wasted space, auto-select (keep newest)
  - Save / Load scan results (JSON)
  - Scan elapsed-time timer
  - Keyboard shortcuts (Ctrl+F, Ctrl+S, Ctrl+O, Del, Esc)
  - Extension analysis tab
  - Batch deletion with progress dialog
  - Deletion history log tab
  - Bar chart visualisation (toggle Pie / Bar)
  - Size-range & date filters
  - Improved heuristics (node_modules, __pycache__, Thumbs.db …)
  - Option to scan hidden directories
  - Open-file-location from duplicate tree context menu
"""

import sys
import os
import csv
import json
import shutil
import hashlib
import subprocess
import tempfile
import platform
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QPushButton,
    QLabel, QComboBox, QGroupBox, QCheckBox, QSplitter,
    QHeaderView, QMessageBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QAbstractItemView,
    QFrame, QSpinBox, QLineEdit, QFileDialog, QMenu,
    QSlider, QProgressDialog, QSizePolicy, QShortcut, QTextEdit
)
from PySide6.QtCore import Qt, Signal, QThread, Slot, QFile, QTimer
from PySide6.QtGui import (
    QColor, QFont, QPalette, QAction, QPainter, QKeySequence
)
from PySide6.QtCharts import (
    QChartView, QPieSeries, QPieSlice, QChart,
    QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis
)

# ══════════════════════════════════════════════════════════
#  Platform Helpers
# ══════════════════════════════════════════════════════════
IS_WIN  = sys.platform == "win32"
IS_MAC  = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

def get_user_home():
    return str(Path.home())

# ══════════════════════════════════════════════════════════
#  Data Model
# ══════════════════════════════════════════════════════════
@dataclass
class FileEntry:
    path: str
    size: int
    modified: datetime
    accessed: datetime
    created: datetime
    extension: str
    category: str = ""
    relevance_score: int = 0
    reasons: list = field(default_factory=list)
    is_checked: bool = False

    def to_dict(self):
        return dict(
            path=self.path, size=self.size,
            modified=self.modified.isoformat(),
            accessed=self.accessed.isoformat(),
            created=self.created.isoformat(),
            extension=self.extension, category=self.category,
            relevance_score=self.relevance_score,
            reasons=self.reasons, is_checked=self.is_checked,
        )

    @classmethod
    def from_dict(cls, d):
        return cls(
            path=d["path"], size=d["size"],
            modified=datetime.fromisoformat(d["modified"]),
            accessed=datetime.fromisoformat(d["accessed"]),
            created=datetime.fromisoformat(d["created"]),
            extension=d["extension"], category=d.get("category", ""),
            relevance_score=d.get("relevance_score", 0),
            reasons=d.get("reasons", []),
            is_checked=d.get("is_checked", False),
        )

# ══════════════════════════════════════════════════════════
#  File Analyzer – OS-Specific Heuristics  (v2 enhanced)
# ══════════════════════════════════════════════════════════
class FileAnalyzer:
    TEMP_EXTENSIONS = {
        ".tmp", ".temp", ".bak", ".old", ".chk", ".gid", ".nch",
        ".fts", ".ilk", ".ncb", ".suo", ".err", ".out",
    }
    CACHE_EXTENSIONS = {".cache", ".thumb", ".thumbdata"}
    LOG_EXTENSIONS   = {".log", ".trace", ".evt", ".evtx"}
    DUMP_EXTENSIONS  = {".dmp", ".mdmp", ".hdmp", ".dump", ".crash"}
    INSTALLER_EXTENSIONS = {".msi", ".msp", ".dmg", ".pkg", ".deb", ".rpm", ".exe", ".iso"}
    ARCHIVE_EXTENSIONS   = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
    DEVELOPER_EXTENSIONS = {".pyc", ".pyo", ".o", ".obj", ".pdb", ".idb", ".ipch"}

    CRITICAL_PATTERNS_WIN = [
        "windows\\system32", "windows\\syswow64", "windows\\winsxs",
        "program files\\", "program files (x86)\\",
        "programdata\\microsoft\\windows",
    ]
    CRITICAL_PATTERNS_MAC = [
        "/system/library", "/library/apple/", "/usr/", "/sbin/", "/bin/",
        "/applications/", "/library/application support/",
    ]
    CRITICAL_PATTERNS_LINUX = [
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/lib/", "/lib64/", "/usr/lib/", "/etc/",
        "/boot/", "/dev/", "/proc/", "/sys/",
    ]

    OS_CACHE_PATTERNS_WIN = [
        "appdata\\local\\temp", "windows\\temp", "windows\\prefetch",
        "windows\\software distribution",
        "appdata\\local\\google\\chrome\\user data\\default\\cache",
        "appdata\\local\\microsoft\\edge\\user data\\default\\cache",
        "appdata\\local\\mozilla\\firefox\\profiles",
        "appdata\\local\\microsoft\\windows\\explorer\\thumbcache",
        "appdata\\local\\microsoft\\windows\\explorer\\iconcache",
        "appdata\\local\\pip\\cache",
    ]
    OS_CACHE_PATTERNS_MAC = [
        "/library/caches/", "/library/logs/",
        "/library/developer/xcode/deriveddata/",
        "/library/application support/",
        "/.trash/", "/private/var/folders/",
        "library/caches/google/chrome",
        "library/caches/org.mozilla.firefox",
        "library/developer/xcode/deriveddata",
    ]
    OS_CACHE_PATTERNS_LINUX = [
        "/.cache/", "/.local/share/trash/", "/.local/share/Trash/",
        "/tmp/", "/var/cache/apt/", "/var/log/",
        "/.mozilla/firefox/", "/.config/google-chrome/",
        "/.cache/pip/", "/.npm/", "/.yarn/",
    ]

    # Directory-level junk patterns (checked on the folder name inside the path)
    JUNK_DIR_NAMES = {
        "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".tox", ".nox", "bower_components", ".gradle", ".cargo",
        "venv", ".venv", "env", ".env",
    }

    def __init__(self, min_age_days=90, large_file_mb=500):
        self.min_age_days   = min_age_days
        self.large_file_mb  = large_file_mb

    def analyze(self, filepath: Path, stat: os.stat_result) -> FileEntry:
        entry = FileEntry(
            path=str(filepath), size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime),
            accessed=datetime.fromtimestamp(stat.st_atime),
            created=datetime.fromtimestamp(stat.st_ctime),
            extension=filepath.suffix.lower(),
        )
        score   = 0
        reasons = []
        now       = datetime.now()
        age_days  = max(0, (now - entry.accessed).days)
        lower_path = str(filepath).lower()
        ext        = entry.extension

        # ── Critical-path detection ──────────────────────
        is_critical = False
        if IS_WIN:   is_critical = any(p in lower_path for p in self.CRITICAL_PATTERNS_WIN)
        elif IS_MAC: is_critical = any(p in lower_path for p in self.CRITICAL_PATTERNS_MAC)
        elif IS_LINUX: is_critical = any(p in lower_path for p in self.CRITICAL_PATTERNS_LINUX)

        # ── Extension analysis ───────────────────────────
        if ext in self.TEMP_EXTENSIONS:
            score += 35; reasons.append("Temporary file extension")
        if ext in self.CACHE_EXTENSIONS:
            score += 30; reasons.append("Cache file extension")
        if ext in self.LOG_EXTENSIONS:
            score += 20; reasons.append("Log file")
            if stat.st_size > 10 * 1024 * 1024:
                score += 10; reasons.append("Large log file (>10 MB)")
        if ext in self.DUMP_EXTENSIONS:
            score += 35; reasons.append("Crash dump file")
        if ext in self.INSTALLER_EXTENSIONS and any(
            k in lower_path for k in ("download", "temp", "desktop", "downloads")
        ):
            score += 25; reasons.append("Leftover installer package")
        if ext in self.DEVELOPER_EXTENSIONS:
            score += 20; reasons.append("Build/developer artifact")
        if ext in (".thumbs.db", "thumbs.db"):
            score += 30; reasons.append("Windows thumbnail cache")

        # ── Junk-directory detection ─────────────────────
        parts = [p.lower() for p in filepath.parts]
        for jd in self.JUNK_DIR_NAMES:
            if jd in parts:
                score += 25; reasons.append(f"Inside junk directory ({jd})")
                break

        # ── OS-specific location analysis ────────────────
        cache_patterns = []
        if IS_WIN:    cache_patterns = self.OS_CACHE_PATTERNS_WIN
        elif IS_MAC:  cache_patterns = self.OS_CACHE_PATTERNS_MAC
        elif IS_LINUX: cache_patterns = self.OS_CACHE_PATTERNS_LINUX

        for pattern in cache_patterns:
            if pattern in lower_path:
                score += 30
                if "trash" in pattern or "recycle" in pattern:
                    reasons.append("In OS Trash"); score += 10
                elif "cache" in pattern or "thumbcache" in pattern or "iconcache" in pattern:
                    reasons.append("OS/Application Cache")
                elif "log" in pattern or "logs" in pattern:
                    reasons.append("OS/Application Log")
                elif "temp" in pattern or "tmp" in pattern or "var/folders" in pattern:
                    reasons.append("OS Temporary Directory")
                elif "prefetch" in pattern or "software distribution" in pattern:
                    reasons.append("Windows Update/Pre-fetch Cache")
                elif "deriveddata" in pattern:
                    reasons.append("Xcode Build Cache")
                elif "apt" in pattern:
                    reasons.append("Linux Package Manager Cache")
                elif "pip" in pattern or "npm" in pattern or "yarn" in pattern:
                    reasons.append("Language Package Manager Cache")
                break

        # ── Age analysis ─────────────────────────────────
        if age_days > 365:
            score += 15; reasons.append(f"Not accessed in {age_days} days (>1 yr)")
        elif age_days > 180:
            score += 10; reasons.append(f"Not accessed in {age_days} days (>6 mo)")
        elif age_days > self.min_age_days:
            score += 5;  reasons.append(f"Not accessed in {age_days} days")

        # ── Size analysis ────────────────────────────────
        size_mb = stat.st_size / (1024 * 1024)
        if size_mb > self.large_file_mb:
            score += 15; reasons.append(f"Very large file ({size_mb:.0f} MB)")
        elif size_mb > 100:
            score += 8;  reasons.append(f"Large file ({size_mb:.0f} MB)")

        if stat.st_size == 0:
            score += 15; reasons.append("Empty file (0 bytes)")

        # ── Critical-path penalty ────────────────────────
        if is_critical:
            score = max(0, score - 40)
            reasons.append("⚠ System path – review carefully")

        score = min(100, max(0, score))
        category = self._categorize(entry, score, reasons)

        entry.relevance_score = score
        entry.reasons         = reasons
        entry.category        = category
        entry.is_checked      = score >= 60
        return entry

    @staticmethod
    def _categorize(entry, score, reasons):
        r = " ".join(reasons).lower()
        if "trash" in r or "recycle" in r:       return "OS Trash"
        if "temporary" in r:                      return "Temporary Files"
        if "browser" in r or "chrome" in r or "firefox" in r:
                                                   return "Browser Cache"
        if "cache" in r or "thumbnail" in r:      return "OS/Application Cache"
        if "crash dump" in r:                     return "Crash Dumps"
        if "log" in r:                            return "Log Files"
        if "installer" in r:                      return "Installer Leftovers"
        if "developer" in r or "build" in r:      return "Developer Artifacts"
        if "xcode" in r:                          return "Developer Caches"
        if "junk directory" in r:                 return "Junk Directories"
        if "package manager" in r:                return "Package Manager Cache"
        if "windows update" in r or "prefetch" in r:
                                                   return "Windows Update Cache"
        if "empty" in r:                          return "Empty Files"
        if "large" in r and "not accessed" in r:  return "Old Large Files"
        if "not accessed" in r:                   return "Old Files"
        if "large" in r:                          return "Large Files"
        if score > 0:                             return "Possibly Unnecessary"
        return "Keep"

# ══════════════════════════════════════════════════════════
#  Scanner Thread (v2 – exclusions + hidden-dirs option)
# ══════════════════════════════════════════════════════════
class ScannerThread(QThread):
    progress_update = Signal(int, str)
    file_found      = Signal(object)
    scan_complete   = Signal(int)
    scan_error      = Signal(str)

    SKIP_DIRS_WIN   = {"windows", "system volume information", "$recycle.bin", "system32", "syswow64", "winsxs"}
    SKIP_DIRS_MAC   = {"system", "library", ".trash", "private", "usr", "bin", "sbin", "dev", "proc", "sys"}
    SKIP_DIRS_LINUX = {"bin", "sbin", "usr", "lib", "lib64", "boot", "dev", "proc", "sys", "run"}

    def __init__(self, drive_path, analyzer, skip_system=True,
                 exclusion_patterns=None, scan_hidden=False):
        super().__init__()
        self.drive_path        = drive_path
        self.analyzer          = analyzer
        self.skip_system       = skip_system
        self.exclusion_patterns = [p.lower().strip() for p in (exclusion_patterns or []) if p.strip()]
        self.scan_hidden       = scan_hidden
        self._running          = True

    def stop(self):
        self._running = False

    def run(self):
        scanned = 0; found = 0
        skip_dirs = set()
        if self.skip_system:
            if IS_WIN:    skip_dirs = self.SKIP_DIRS_WIN
            elif IS_MAC:  skip_dirs = self.SKIP_DIRS_MAC
            elif IS_LINUX: skip_dirs = self.SKIP_DIRS_LINUX

        try:
            for root, dirs, files in os.walk(self.drive_path, onerror=lambda _: None):
                if not self._running:
                    break

                # Filter directories
                filtered = []
                for d in dirs:
                    dl = d.lower()
                    if dl in skip_dirs:
                        continue
                    if not self.scan_hidden and d.startswith("."):
                        continue
                    full = os.path.join(root, d).lower()
                    if any(p in full for p in self.exclusion_patterns):
                        continue
                    filtered.append(d)
                dirs[:] = filtered

                for fname in files:
                    if not self._running:
                        break
                    fpath = Path(root) / fname
                    # Also check exclusion on file path
                    if any(p in str(fpath).lower() for p in self.exclusion_patterns):
                        continue
                    scanned += 1
                    try:
                        st = fpath.stat()
                        entry = self.analyzer.analyze(fpath, st)
                        if entry.relevance_score > 0:
                            found += 1
                            self.file_found.emit(entry)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                    if scanned % 200 == 0:
                        self.progress_update.emit(scanned, str(fpath)[:100])
        except Exception as e:
            self.scan_error.emit(str(e))
        self.scan_complete.emit(found)

# ══════════════════════════════════════════════════════════
#  Duplicate Finder Thread (v2 – min_size param + wasted)
# ══════════════════════════════════════════════════════════
class DuplicateFinderThread(QThread):
    duplicate_found = Signal(list)   # list of paths
    progress_update = Signal(str)
    scan_complete   = Signal(int, int)  # total_dupes, wasted_bytes

    def __init__(self, drive_path, min_size=1024, scan_hidden=False,
                 exclusion_patterns=None):
        super().__init__()
        self.drive_path         = drive_path
        self.min_size           = min_size
        self.scan_hidden        = scan_hidden
        self.exclusion_patterns = [p.lower().strip() for p in (exclusion_patterns or []) if p.strip()]
        self._running           = True

    def stop(self):
        self._running = False

    @staticmethod
    def _hash_file(path, chunk=8192):
        h = hashlib.md5()
        try:
            with open(path, "rb") as f:
                while chunk_data := f.read(chunk):
                    h.update(chunk_data)
            return h.hexdigest()
        except Exception:
            return None

    def run(self):
        size_map = defaultdict(list)
        count    = 0
        hash_map = defaultdict(list)
        hashed   = 0

        self.progress_update.emit("Phase 1/2 – grouping by size…")
        for root, dirs, files in os.walk(self.drive_path, onerror=lambda _: None):
            if not self._running:
                return
            if not self.scan_hidden:
                dirs[:] = [d for d in dirs if not d.startswith(".")]
            # exclusions
            dirs[:] = [d for d in dirs
                       if not any(p in os.path.join(root, d).lower()
                                  for p in self.exclusion_patterns)]
            for fname in files:
                if not self._running:
                    return
                fp = os.path.join(root, fname)
                if any(p in fp.lower() for p in self.exclusion_patterns):
                    continue
                try:
                    sz = os.path.getsize(fp)
                    if sz >= self.min_size:
                        size_map[sz].append(fp)
                    count += 1
                    if count % 1000 == 0:
                        self.progress_update.emit(f"Phase 1 – {count:,} files…")
                except Exception:
                    continue

        self.progress_update.emit("Phase 2/2 – hashing candidates…")
        for sz, paths in size_map.items():
            if not self._running:
                return
            if len(paths) < 2:
                continue
            for fp in paths:
                if not self._running:
                    return
                h = self._hash_file(fp)
                if h:
                    hash_map[(sz, h)].append(fp)
                hashed += 1
                if hashed % 100 == 0:
                    self.progress_update.emit(f"Phase 2 – {hashed:,} hashed…")

        total_dupes  = 0
        wasted_bytes = 0
        for key, paths in hash_map.items():
            if len(paths) > 1:
                total_dupes  += len(paths) - 1
                wasted_bytes += key[0] * (len(paths) - 1)
                self.duplicate_found.emit(paths)
        self.scan_complete.emit(total_dupes, wasted_bytes)

# ══════════════════════════════════════════════════════════
#  Disk Usage Bar (custom painted widget)
# ══════════════════════════════════════════════════════════
class DiskUsageBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        self._pct = 0.0
        self._free_str = ""
        self._used_str = ""

    def set_usage(self, total, used, free):
        self._pct = (used / total * 100) if total > 0 else 0
        self._free_str = DriveCleanerWindow._fmt(free)
        self._used_str = DriveCleanerWindow._fmt(used)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(2, 2, -2, -2)
        # bg
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#333348"))
        p.drawRoundedRect(rect, 6, 6)
        # fill
        fill_w = int(rect.width() * min(self._pct, 100) / 100)
        if self._pct > 90:
            col = QColor("#f44336")
        elif self._pct > 75:
            col = QColor("#FF9800")
        elif self._pct > 50:
            col = QColor("#FFC107")
        else:
            col = QColor("#4CAF50")
        p.setBrush(col)
        p.drawRoundedRect(rect.x(), rect.y(), fill_w, rect.height(), 6, 6)
        # text
        p.setPen(QColor("#fff"))
        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.drawText(self.rect(), Qt.AlignCenter,
                   f"{self._pct:.1f}% used ({self._used_str})  ·  {self._free_str} free")
        p.end()

# ══════════════════════════════════════════════════════════
#  Numeric Table Item
# ══════════════════════════════════════════════════════════
class NumericItem(QTableWidgetItem):
    def __init__(self, text, value):
        super().__init__(text)
        self._value = value
    def __lt__(self, other):
        if isinstance(other, NumericItem):
            return self._value < other._value
        return super().__lt__(other)

# ══════════════════════════════════════════════════════════
#  Main Window  (v2 – heavily enhanced)
# ══════════════════════════════════════════════════════════
class DriveCleanerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🧹 Drive Cleanup Analyzer Pro v2.0 ({platform.system()})")
        self.setMinimumSize(1200, 800)
        self.resize(1500, 920)

        self.scanner      = None
        self.dup_scanner  = None
        self.files_by_category = defaultdict(list)
        self.all_files         = []
        self.total_reclaimable = 0
        self.current_category  = "All"
        self.deletion_log      = []       # list of (ts, path, size, ok?)
        self.ext_data          = {}       # populated after scan
        self._scan_start_time  = 0.0
        self._score_threshold  = 0
        self._chart_mode       = "pie"    # "pie" | "bar"

        self._build_ui()
        self._populate_drives()
        self._setup_shortcuts()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_timer)

    # ══════════════════════════════════════════════════════
    #  UI Construction
    # ══════════════════════════════════════════════════════
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8); root.setSpacing(6)

        # ── Top control bar ──────────────────────────────
        top = QFrame(); top.setObjectName("topFrame")
        top_l = QVBoxLayout(top); top_l.setContentsMargins(10, 8, 10, 8)
        top_l.setSpacing(4)

        row1 = QHBoxLayout()
        self._combo_drive = QComboBox(); self._combo_drive.setMinimumWidth(220)
        self._combo_drive.currentIndexChanged.connect(self._update_drive_info)
        self._btn_browse = self._btn("📂", "#555", self._browse_path)
        self._edit_custom_path = QLineEdit()
        self._edit_custom_path.setPlaceholderText("Custom path (or leave blank to use drive above)…")
        self._edit_custom_path.setMinimumWidth(200)

        self._spin_age    = QSpinBox(); self._spin_age.setRange(1, 3650); self._spin_age.setValue(90)
        self._spin_large  = QSpinBox(); self._spin_large.setRange(10, 100000); self._spin_large.setValue(500)
        self._chk_system  = QCheckBox("Skip system"); self._chk_system.setChecked(True)
        self._chk_hidden  = QCheckBox("Scan hidden dirs")

        row1.addWidget(self._label("Drive:", True))
        row1.addWidget(self._combo_drive)
        row1.addWidget(self._btn_browse)
        row1.addWidget(self._edit_custom_path, 1)
        row1.addWidget(self._label("Age≥", True)); row1.addWidget(self._spin_age)
        row1.addWidget(self._label("Large≥MB", True)); row1.addWidget(self._spin_large)
        row1.addWidget(self._chk_system); row1.addWidget(self._chk_hidden)
        top_l.addLayout(row1)

        row2 = QHBoxLayout()
        self._edit_exclusions = QLineEdit()
        self._edit_exclusions.setPlaceholderText("Exclusion patterns (semicolon-separated, e.g. node_modules;.git;Backup)…")
        self._edit_exclusions.setMinimumWidth(300)
        self._slider_score = QSlider(Qt.Horizontal)
        self._slider_score.setRange(0, 100); self._slider_score.setValue(0)
        self._slider_score.setMaximumWidth(160)
        self._slider_score.setToolTip("Minimum relevance score to show")
        self._slider_score.valueChanged.connect(self._on_score_threshold_changed)
        self._lbl_score_thresh = self._label("Score ≥ 0")

        self._btn_scan = self._btn("🔍  Scan Drive", "#4CAF50", self.start_scan)
        self._btn_stop = self._btn("⏹  Stop", "#f44336", self.stop_scan)
        self._btn_stop.setEnabled(False)
        self._btn_dup  = self._btn("🔀  Find Duplicates", "#FF9800", self.start_duplicate_scan)
        self._btn_dup.setEnabled(False)

        row2.addWidget(self._label("Exclude:", True))
        row2.addWidget(self._edit_exclusions, 1)
        row2.addWidget(self._lbl_score_thresh)
        row2.addWidget(self._slider_score)
        row2.addWidget(self._btn_scan)
        row2.addWidget(self._btn_stop)
        row2.addWidget(self._btn_dup)
        top_l.addLayout(row2)
        root.addWidget(top)

        # ── Progress bar + timer ─────────────────────────
        ph = QHBoxLayout()
        self._progress = QProgressBar(); self._progress.setVisible(False)
        self._lbl_timer = self._label("⏱ 0:00")
        self._lbl_timer.setStyleSheet("color:#FF9800; font-size:13px; font-weight:bold;")
        ph.addWidget(self._progress, 1); ph.addWidget(self._lbl_timer)
        root.addLayout(ph)

        # ── Stats bar ────────────────────────────────────
        bar = QFrame(); bar.setObjectName("statsBar")
        bl = QHBoxLayout(bar); bl.setContentsMargins(10, 4, 10, 4)
        self._lbl_status    = self._label("Ready to scan")
        self._lbl_files     = self._label("Files: 0", accent="#4CAF50")
        self._lbl_reclaim   = self._label("Reclaimable: 0 B", accent="#FF9800")
        self._lbl_selected  = self._label("Selected: 0 B", accent="#2196F3")
        btn_sel   = self._btn("Select All",   "#555", self.select_all)
        btn_desel = self._btn("Deselect All", "#555", self.deselect_all)
        self._btn_del = self._btn("🗑  Move to Trash", "#f44336", self.move_to_trash)
        self._btn_del.setEnabled(False)
        btn_save   = self._btn("💾  Save", "#2196F3", self.save_results)
        btn_load   = self._btn("📂  Load", "#7B1FA2", self.load_results)
        btn_export = self._btn("📄  Export CSV", "#00897B", self.export_to_csv)
        for w in (self._lbl_status,): bl.addWidget(w)
        bl.addStretch()
        for w in (self._lbl_files, self._lbl_reclaim, self._lbl_selected,
                  btn_sel, btn_desel, self._btn_del, btn_save, btn_load, btn_export):
            bl.addWidget(w)
        root.addWidget(bar)

        # ── Disk usage bar ───────────────────────────────
        self._disk_bar = DiskUsageBar()
        root.addWidget(self._disk_bar)

        # ── Main splitter ────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        # Left: category tree
        cat_box = QGroupBox("Categories"); cat_l = QVBoxLayout(cat_box)
        self._tree_cat = QTreeWidget()
        self._tree_cat.setHeaderLabels(["Category", "Files", "Size"])
        self._tree_cat.setColumnWidth(0, 200); self._tree_cat.setColumnWidth(1, 60)
        self._tree_cat.itemClicked.connect(self._on_category_click)
        cat_l.addWidget(self._tree_cat)
        splitter.addWidget(cat_box)

        # Right: tabs
        tabs = QTabWidget()

        # ──── TAB 1: Dashboard ──────────────────────────
        dash_w = QWidget(); dash_l = QVBoxLayout(dash_w)

        # top row: drive info + charts
        dash_top = QSplitter(Qt.Horizontal)

        left_dash = QWidget(); left_l = QVBoxLayout(left_dash)
        left_l.setContentsMargins(0, 0, 0, 0)
        info_box = QGroupBox("Drive Info & Quick Actions")
        info_vbl = QVBoxLayout(info_box)
        self._lbl_drive_info = self._label("Scan a drive to see info", True, "#FF9800")
        info_vbl.addWidget(self._lbl_drive_info)
        self._add_quick_actions(info_vbl)
        info_vbl.addStretch()
        left_l.addWidget(info_box)
        dash_top.addWidget(left_dash)

        right_dash = QWidget(); right_l = QVBoxLayout(right_dash)
        right_l.setContentsMargins(0, 0, 0, 0)

        # chart type toggle
        chart_ctrl = QHBoxLayout()
        self._combo_chart = QComboBox()
        self._combo_chart.addItems(["🥧 Pie Chart", "📊 Bar Chart"])
        self._combo_chart.currentIndexChanged.connect(self._on_chart_mode_changed)
        chart_ctrl.addWidget(self._label("Chart:", True))
        chart_ctrl.addWidget(self._combo_chart)
        chart_ctrl.addStretch()
        right_l.addLayout(chart_ctrl)

        chart_box = QGroupBox("Space Distribution")
        chart_vbl = QVBoxLayout(chart_box)
        self._chart_view = QChartView()
        self._chart_view.setRenderHint(QPainter.Antialiasing)
        self._chart_view.setMinimumHeight(250)
        chart_vbl.addWidget(self._chart_view)
        right_l.addWidget(chart_box, 3)

        # Top largest files
        top_box = QGroupBox("🔝 Top 20 Largest Files")
        top_vbl = QVBoxLayout(top_box)
        self._table_top = QTableWidget(); self._table_top.setColumnCount(4)
        self._table_top.setHorizontalHeaderLabels(["File Path", "Size", "Score", "Category"])
        hh = self._table_top.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        self._table_top.setColumnWidth(1, 100); self._table_top.setColumnWidth(2, 55)
        self._table_top.setColumnWidth(3, 140)
        self._table_top.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table_top.setAlternatingRowColors(True)
        self._table_top.setMaximumHeight(200)
        top_vbl.addWidget(self._table_top)
        right_l.addWidget(top_box, 2)

        dash_top.addWidget(right_dash)
        dash_top.setSizes([300, 700])
        dash_l.addWidget(dash_top)
        tabs.addTab(dash_w, "📊 Dashboard")

        # ──── TAB 2: Files ──────────────────────────────
        fw = QWidget(); fl = QVBoxLayout(fw)
        filter_row = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("🔍 Filter by name, path, or extension…")
        self._search_input.textChanged.connect(self.filter_table)
        self._spin_min_size = QSpinBox(); self._spin_min_size.setRange(0, 10000000)
        self._spin_min_size.setSuffix(" KB"); self._spin_min_size.setValue(0)
        self._spin_min_size.valueChanged.connect(self.filter_table)
        self._spin_max_size = QSpinBox(); self._spin_max_size.setRange(0, 10000000)
        self._spin_max_size.setSuffix(" KB"); self._spin_max_size.setValue(0)
        self._spin_max_size.valueChanged.connect(self.filter_table)
        filter_row.addWidget(self._search_input, 1)
        filter_row.addWidget(self._label("Size ≥", True)); filter_row.addWidget(self._spin_min_size)
        filter_row.addWidget(self._label("Size ≤", True)); filter_row.addWidget(self._spin_max_size)
        fl.addLayout(filter_row)

        self._table = QTableWidget(); self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            ["Delete", "Score", "File Path", "Size", "Last Accessed", "Category", "Reasons"])
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 55); self._table.setColumnWidth(1, 55)
        self._table.setColumnWidth(3, 100); self._table.setColumnWidth(4, 130)
        self._table.setColumnWidth(5, 150)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.cellChanged.connect(self._on_cell_changed)
        fl.addWidget(self._table)
        tabs.addTab(fw, "📁 Files")

        # ──── TAB 3: Duplicates ─────────────────────────
        dw = QWidget(); dl = QVBoxLayout(dw)
        dup_ctrl = QHBoxLayout()
        self._lbl_dup_info = self._label("Run a duplicate scan to see results")
        self._btn_dup_auto = self._btn("✅ Auto-select (keep newest)", "#4CAF50",
                                        self._dup_auto_select)
        self._btn_dup_auto.setEnabled(False)
        self._btn_dup_del = self._btn("🗑  Move Checked to Trash", "#f44336",
                                       self._delete_dup_checked)
        self._btn_dup_del.setEnabled(False)
        dup_ctrl.addWidget(self._lbl_dup_info, 1)
        dup_ctrl.addWidget(self._btn_dup_auto)
        dup_ctrl.addWidget(self._btn_dup_del)
        dl.addLayout(dup_ctrl)
        self._tree_dup = QTreeWidget()
        self._tree_dup.setHeaderLabels(["File Path", "Size", "Modified"])
        self._tree_dup.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree_dup.customContextMenuRequested.connect(self._show_dup_context_menu)
        dl.addWidget(self._tree_dup)
        tabs.addTab(dw, "🔀 Duplicates")

        # ──── TAB 4: Extension Analysis ─────────────────
        ew = QWidget(); el = QVBoxLayout(ew)
        self._table_ext = QTableWidget(); self._table_ext.setColumnCount(5)
        self._table_ext.setHorizontalHeaderLabels(
            ["Extension", "File Count", "Total Size", "Avg Size", "Avg Score"])
        hh = self._table_ext.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        self._table_ext.setColumnWidth(1, 90); self._table_ext.setColumnWidth(2, 110)
        self._table_ext.setColumnWidth(3, 100); self._table_ext.setColumnWidth(4, 90)
        self._table_ext.setSortingEnabled(True)
        self._table_ext.setAlternatingRowColors(True)
        self._table_ext.setEditTriggers(QAbstractItemView.NoEditTriggers)
        el.addWidget(self._table_ext)
        tabs.addTab(ew, "📊 Extensions")

        # ──── TAB 5: Deletion History ───────────────────
        hw = QWidget(); hl = QVBoxLayout(hw)
        hist_ctrl = QHBoxLayout()
        self._lbl_hist = self._label("No deletions yet")
        btn_clear_hist = self._btn("Clear Log", "#555", self._clear_deletion_log)
        hist_ctrl.addWidget(self._lbl_hist, 1); hist_ctrl.addWidget(btn_clear_hist)
        hl.addLayout(hist_ctrl)
        self._table_hist = QTableWidget(); self._table_hist.setColumnCount(4)
        self._table_hist.setHorizontalHeaderLabels(
            ["Time", "File Path", "Size", "Result"])
        hh = self._table_hist.horizontalHeader()
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        self._table_hist.setColumnWidth(0, 150); self._table_hist.setColumnWidth(2, 100)
        self._table_hist.setColumnWidth(3, 100)
        self._table_hist.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table_hist.setAlternatingRowColors(True)
        hl.addWidget(self._table_hist)
        tabs.addTab(hw, "📋 History")

        splitter.addWidget(tabs)
        splitter.setSizes([260, 900])
        root.addWidget(splitter, 1)
        self.setStyleSheet(_STYLESHEET)

    # ── Quick-action buttons ──────────────────────────────
    def _add_quick_actions(self, layout):
        layout.addWidget(self._btn("🗑 Empty System Temp Folder", "#e91e63",
                                    self._quick_clean_temp))
        if IS_WIN:
            layout.addWidget(self._btn("🗑 Empty User Temp Folder", "#e91e63",
                                        self._quick_clean_user_temp))
            layout.addWidget(self._btn("🗑 Empty Recycle Bin", "#9C27B0",
                                        self._quick_clean_recycle_win))
            layout.addWidget(self._btn("🪟 Open Disk Cleanup", "#0288D1",
                                        self._open_disk_cleanup_win))
        elif IS_MAC:
            layout.addWidget(self._btn("🗑 Empty macOS Trash", "#9C27B0",
                                        self._quick_clean_trash_mac))
            layout.addWidget(self._btn("🧹 Clear Xcode Derived Data", "#e91e63",
                                        self._quick_clean_xcode_mac))
            layout.addWidget(self._btn("🧹 Clear System Cache", "#e91e63",
                                        self._quick_clean_caches_mac))
        elif IS_LINUX:
            layout.addWidget(self._btn("🗑 Empty Linux Trash", "#9C27B0",
                                        self._quick_clean_trash_linux))
            layout.addWidget(self._btn("🧹 Clear APT Cache", "#e91e63",
                                        self._quick_clean_apt_linux))
            layout.addWidget(self._btn("🧹 Clear DNF Cache", "#e91e63",
                                        self._quick_clean_dnf_linux))

    # ── Keyboard shortcuts ────────────────────────────────
    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self, self._focus_search)
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_results)
        QShortcut(QKeySequence("Ctrl+O"), self, self.load_results)
        QShortcut(QKeySequence("Delete"),  self, self.move_to_trash)
        QShortcut(QKeySequence("Escape"),  self, self.stop_scan)
        QShortcut(QKeySequence("Ctrl+A"),  self, self.select_all)

    def _focus_search(self):
        self._search_input.setFocus()
        self._search_input.selectAll()

    # ══════════════════════════════════════════════════════
    #  Helpers
    # ══════════════════════════════════════════════════════
    @staticmethod
    def _label(text, bold=False, accent=None):
        l = QLabel(text)
        if bold:
            f = l.font(); f.setBold(True); l.setFont(f)
        if accent:
            l.setStyleSheet(f"color:{accent}; font-size:13px;")
        return l

    @staticmethod
    def _btn(text, color, slot):
        b = QPushButton(text)
        b.setStyleSheet(
            f"QPushButton{{background:{color};color:#fff;font-weight:bold;"
            f"padding:8px 18px;border-radius:5px;border:none;}}"
            f"QPushButton:hover{{opacity:0.85;}}"
            f"QPushButton:disabled{{background:#555;color:#888;}}")
        b.clicked.connect(slot)
        return b

    @staticmethod
    def _fmt(size):
        if size < 1024:        return f"{size} B"
        if size < 1024 ** 2:   return f"{size / 1024:.1f} KB"
        if size < 1024 ** 3:   return f"{size / 1024 ** 2:.1f} MB"
        return f"{size / 1024 ** 3:.2f} GB"

    # ══════════════════════════════════════════════════════
    #  Drive List & Info
    # ══════════════════════════════════════════════════════
    def _populate_drives(self):
        self._combo_drive.blockSignals(True)
        self._combo_drive.clear()
        if IS_WIN:
            import string
            for letter in string.ascii_uppercase:
                d = f"{letter}:\\"
                if os.path.exists(d):
                    try:
                        u = shutil.disk_usage(d)
                        self._combo_drive.addItem(
                            f"{d}  ({self._fmt(u.free)} free / {self._fmt(u.total)})", d)
                    except OSError:
                        self._combo_drive.addItem(d, d)
        elif IS_MAC:
            self._combo_drive.addItem("/ (Macintosh HD)", "/")
            if os.path.exists("/Volumes"):
                for p in Path("/Volumes").iterdir():
                    if p.is_dir() and not p.is_symlink():
                        try:
                            u = shutil.disk_usage(str(p))
                            self._combo_drive.addItem(
                                f"{p.name} ({self._fmt(u.free)} free)", str(p))
                        except Exception:
                            self._combo_drive.addItem(str(p), str(p))
        elif IS_LINUX:
            self._combo_drive.addItem("/ (Root)", "/")
            for base in ("/mnt", "/media"):
                bp = Path(base)
                if bp.exists():
                    for p in bp.iterdir():
                        if p.is_dir() and not p.is_symlink():
                            try:
                                u = shutil.disk_usage(str(p))
                                self._combo_drive.addItem(
                                    f"{p.name} ({self._fmt(u.free)} free)", str(p))
                            except Exception:
                                self._combo_drive.addItem(str(p), str(p))
        # Add user home as option
        home = get_user_home()
        self._combo_drive.addItem(f"🏠 Home ({home})", home)
        self._combo_drive.blockSignals(False)
        self._update_drive_info()

    def _browse_path(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if d:
            self._edit_custom_path.setText(d)

    def _get_scan_path(self):
        custom = self._edit_custom_path.text().strip()
        if custom and os.path.exists(custom):
            return custom
        return self._combo_drive.currentData()

    def _update_drive_info(self):
        drive = self._get_scan_path()
        if not drive:
            return
        try:
            u   = shutil.disk_usage(drive)
            pct = (u.used / u.total) * 100
            self._lbl_drive_info.setText(
                f"Drive: {drive}\n\n"
                f"Total: {self._fmt(u.total)}\n"
                f"Used:  {self._fmt(u.used)} ({pct:.1f}%)\n"
                f"Free:  {self._fmt(u.free)}\n\n"
                f"Scan to find reclaimable space.")
            self._disk_bar.set_usage(u.total, u.used, u.free)
        except OSError:
            self._lbl_drive_info.setText("Could not read drive info.")

    # ══════════════════════════════════════════════════════
    #  Scan Timer
    # ══════════════════════════════════════════════════════
    def _tick_timer(self):
        elapsed = time.time() - self._scan_start_time
        m, s = divmod(int(elapsed), 60)
        self._lbl_timer.setText(f"⏱ {m}:{s:02d}")

    # ══════════════════════════════════════════════════════
    #  Scanning
    # ══════════════════════════════════════════════════════
    def start_scan(self):
        drive = self._get_scan_path()
        if not drive:
            QMessageBox.warning(self, "No path", "Select a drive or enter a custom path.")
            return
        self.files_by_category.clear()
        self.all_files.clear()
        self._tree_cat.clear()
        self._table.setRowCount(0)
        self.total_reclaimable = 0
        self._update_drive_info()

        excl = self._edit_exclusions.text().split(";")
        analyzer = FileAnalyzer(
            min_age_days=self._spin_age.value(),
            large_file_mb=self._spin_large.value())
        self.scanner = ScannerThread(
            drive, analyzer,
            skip_system=self._chk_system.isChecked(),
            exclusion_patterns=excl,
            scan_hidden=self._chk_hidden.isChecked())
        self.scanner.progress_update.connect(self._on_scan_progress)
        self.scanner.file_found.connect(self._on_file_found)
        self.scanner.scan_complete.connect(self._on_scan_done)
        self.scanner.scan_error.connect(self._on_scan_error)

        self._progress.setVisible(True); self._progress.setRange(0, 0)
        self._btn_scan.setEnabled(False); self._btn_stop.setEnabled(True)
        self._btn_del.setEnabled(False); self._btn_dup.setEnabled(False)
        self._lbl_status.setText("Scanning…")
        self._lbl_status.setStyleSheet("color:#FF9800;font-size:13px;")

        self._scan_start_time = time.time()
        self._timer.start(1000)
        self.scanner.start()

    def stop_scan(self):
        if self.scanner and self.scanner.isRunning():
            self.scanner.stop()
        if self.dup_scanner and self.dup_scanner.isRunning():
            self.dup_scanner.stop()

    @Slot(int, str)
    def _on_scan_progress(self, n, path):
        self._lbl_status.setText(f"Scanned {n:,} files…  {path}")

    @Slot(object)
    def _on_file_found(self, entry: FileEntry):
        self.all_files.append(entry)
        self.files_by_category[entry.category].append(entry)
        self.total_reclaimable += entry.size
        self._lbl_files.setText(f"Files: {len(self.all_files):,}")
        self._lbl_reclaim.setText(f"Reclaimable: {self._fmt(self.total_reclaimable)}")

    @Slot(int)
    def _on_scan_done(self, total):
        self._timer.stop()
        elapsed = time.time() - self._scan_start_time
        m, s = divmod(int(elapsed), 60)
        self._progress.setVisible(False)
        self._btn_scan.setEnabled(True); self._btn_stop.setEnabled(False)
        self._btn_del.setEnabled(bool(self.all_files))
        self._btn_dup.setEnabled(True)
        self._lbl_status.setText(
            f"Scan complete – {total:,} files flagged  (⏱ {m}:{s:02d})")
        self._lbl_status.setStyleSheet("color:#4CAF50;font-size:13px;")
        self._build_categories()
        self._show_category("All")
        self._update_chart()
        self._build_top_files()
        self._build_ext_table()

    @Slot(str)
    def _on_scan_error(self, err):
        self._timer.stop()
        self._progress.setVisible(False)
        self._btn_scan.setEnabled(True); self._btn_stop.setEnabled(False)
        self._lbl_status.setText(f"Error: {err}")
        self._lbl_status.setStyleSheet("color:#f44336;font-size:13px;")

    # ══════════════════════════════════════════════════════
    #  Charts
    # ══════════════════════════════════════════════════════
    def _on_chart_mode_changed(self, idx):
        self._chart_mode = "pie" if idx == 0 else "bar"
        self._update_chart()

    def _update_chart(self):
        if self._chart_mode == "pie":
            self._update_pie_chart()
        else:
            self._update_bar_chart()

    def _update_pie_chart(self):
        series = QPieSeries()
        for cat in sorted(self.files_by_category):
            sz = sum(f.size for f in self.files_by_category[cat])
            if sz > 0:
                sl = series.append(f"{cat} ({self._fmt(sz)})", sz)
                avg = sum(f.relevance_score for f in self.files_by_category[cat]) / max(
                    len(self.files_by_category[cat]), 1)
                if avg >= 60:   sl.setColor(QColor("#f44336"))
                elif avg >= 30: sl.setColor(QColor("#FF9800"))
                else:          sl.setColor(QColor("#FFC107"))
        chart = QChart(); chart.addSeries(series)
        chart.setTitle("Reclaimable Space by Category")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setVisible(True); chart.legend().setAlignment(Qt.AlignBottom)
        chart.setBackgroundVisible(False)
        chart.setTitleBrush(QColor("#cdd6f4"))
        self._chart_view.setChart(chart)

    def _update_bar_chart(self):
        cats = sorted(self.files_by_category)
        if not cats:
            return
        bar_set = QBarSet("Size (MB)")
        for cat in cats:
            sz_mb = sum(f.size for f in self.files_by_category[cat]) / (1024 * 1024)
            bar_set.append(sz_mb)
        series = QBarSeries(); series.append(bar_set)
        chart = QChart(); chart.addSeries(series)
        chart.setTitle("Category Sizes (MB)")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.setBackgroundVisible(False)
        chart.setTitleBrush(QColor("#cdd6f4"))
        axis_x = QBarCategoryAxis(); axis_x.append(cats)
        chart.addAxis(axis_x, Qt.AlignBottom); series.attachAxis(axis_x)
        axis_y = QValueAxis(); axis_y.setTitleText("MB")
        chart.addAxis(axis_y, Qt.AlignLeft); series.attachAxis(axis_y)
        chart.legend().setVisible(True); chart.legend().setAlignment(Qt.AlignBottom)
        axis_x.setLabelsAngle(-45)
        self._chart_view.setChart(chart)

    # ══════════════════════════════════════════════════════
    #  Top Largest Files
    # ══════════════════════════════════════════════════════
    def _build_top_files(self):
        self._table_top.setRowCount(0)
        top20 = sorted(self.all_files, key=lambda f: f.size, reverse=True)[:20]
        for entry in top20:
            row = self._table_top.rowCount(); self._table_top.insertRow(row)
            pi = QTableWidgetItem(entry.path); pi.setToolTip(entry.path)
            self._table_top.setItem(row, 0, pi)
            si = NumericItem(self._fmt(entry.size), entry.size)
            si.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self._table_top.setItem(row, 1, si)
            sci = NumericItem(str(entry.relevance_score), entry.relevance_score)
            sci.setForeground(
                QColor("#f44336") if entry.relevance_score >= 60
                else QColor("#FF9800") if entry.relevance_score >= 30
                else QColor("#FFC107"))
            self._table_top.setItem(row, 2, sci)
            ci = QTableWidgetItem(entry.category)
            self._table_top.setItem(row, 3, ci)

    # ══════════════════════════════════════════════════════
    #  Extension Analysis
    # ══════════════════════════════════════════════════════
    def _build_ext_table(self):
        self._table_ext.setRowCount(0)
        ext_map = defaultdict(lambda: {"count": 0, "total_size": 0, "total_score": 0})
        for f in self.all_files:
            e = f.extension if f.extension else "(no ext)"
            ext_map[e]["count"]      += 1
            ext_map[e]["total_size"] += f.size
            ext_map[e]["total_score"] += f.relevance_score

        for ext in sorted(ext_map, key=lambda e: ext_map[e]["total_size"], reverse=True):
            d = ext_map[ext]
            row = self._table_ext.rowCount(); self._table_ext.insertRow(row)
            self._table_ext.setItem(row, 0, QTableWidgetItem(ext))
            self._table_ext.setItem(row, 1, NumericItem(f"{d['count']:,}", d["count"]))
            si = NumericItem(self._fmt(d["total_size"]), d["total_size"])
            si.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self._table_ext.setItem(row, 2, si)
            avg_sz = d["total_size"] / max(d["count"], 1)
            ai = NumericItem(self._fmt(int(avg_sz)), int(avg_sz))
            ai.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self._table_ext.setItem(row, 3, ai)
            avg_sc = d["total_score"] / max(d["count"], 1)
            sci = NumericItem(f"{avg_sc:.0f}", avg_sc)
            sci.setForeground(
                QColor("#f44336") if avg_sc >= 60
                else QColor("#FF9800") if avg_sc >= 30
                else QColor("#FFC107"))
            self._table_ext.setItem(row, 4, sci)

    # ══════════════════════════════════════════════════════
    #  Category Tree
    # ══════════════════════════════════════════════════════
    _CAT_ICONS = {
        "OS Trash": "🗑", "Temporary Files": "📄", "Browser Cache": "🌐",
        "OS/Application Cache": "💾", "Crash Dumps": "💥", "Log Files": "📋",
        "Installer Leftovers": "📦", "Developer Artifacts": "🛠",
        "Developer Caches": "🛠", "Junk Directories": "📁",
        "Package Manager Cache": "📦", "Windows Update Cache": "🪟",
        "Empty Files": "📭", "Old Large Files": "📂", "Old Files": "⏰",
        "Large Files": "📊", "Possibly Unnecessary": "❓", "Keep": "✅",
    }

    def _build_categories(self):
        self._tree_cat.clear()
        all_item = QTreeWidgetItem(
            ["📁 All Files", f"{len(self.all_files):,}", self._fmt(self.total_reclaimable)])
        all_item.setData(0, Qt.UserRole, "All")
        f = all_item.font(0); f.setBold(True); all_item.setFont(0, f)
        all_item.setForeground(0, QColor("#4CAF50"))
        self._tree_cat.addTopLevelItem(all_item)

        for cat in sorted(self.files_by_category):
            files = self.files_by_category[cat]
            sz  = sum(f.size for f in files)
            icon = self._CAT_ICONS.get(cat, "📁")
            item = QTreeWidgetItem([f"{icon} {cat}", f"{len(files):,}", self._fmt(sz)])
            item.setData(0, Qt.UserRole, cat)
            avg = sum(f.relevance_score for f in files) / max(len(files), 1)
            item.setForeground(0,
                QColor("#f44336") if avg >= 60
                else QColor("#FF9800") if avg >= 30
                else QColor("#FFC107"))
            item.setToolTip(0, f"{cat}\n{len(files)} files · {self._fmt(sz)}\nAvg score: {avg:.0f}")
            self._tree_cat.addTopLevelItem(item)

    def _on_category_click(self, item, _col):
        cat = item.data(0, Qt.UserRole)
        if cat is not None:
            self._show_category(cat)

    # ══════════════════════════════════════════════════════
    #  File Table
    # ══════════════════════════════════════════════════════
    def _show_category(self, category):
        self.current_category = category
        self._search_input.clear()
        self._populate_table()

    def _populate_table(self):
        self._table.blockSignals(True); self._table.setRowCount(0)
        category = self.current_category
        files = self.all_files if category == "All" else self.files_by_category.get(category, [])
        threshold = self._score_threshold
        for entry in sorted(files, key=lambda e: e.relevance_score, reverse=True):
            if entry.relevance_score < threshold:
                continue
            row = self._table.rowCount(); self._table.insertRow(row)
            ck = QTableWidgetItem()
            ck.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            ck.setCheckState(Qt.Checked if entry.is_checked else Qt.Unchecked)
            ck.setData(Qt.UserRole, entry)
            self._table.setItem(row, 0, ck)
            si = NumericItem(str(entry.relevance_score), entry.relevance_score)
            si.setForeground(
                QColor("#f44336") if entry.relevance_score >= 60
                else QColor("#FF9800") if entry.relevance_score >= 30
                else QColor("#FFC107"))
            self._table.setItem(row, 1, si)
            pi = QTableWidgetItem(entry.path); pi.setToolTip(entry.path)
            self._table.setItem(row, 2, pi)
            szi = NumericItem(self._fmt(entry.size), entry.size)
            szi.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self._table.setItem(row, 3, szi)
            ai = QTableWidgetItem(entry.accessed.strftime("%Y-%m-%d %H:%M"))
            self._table.setItem(row, 4, ai)
            ci = QTableWidgetItem(entry.category)
            self._table.setItem(row, 5, ci)
            ri = QTableWidgetItem("; ".join(entry.reasons))
            ri.setToolTip("\n".join(entry.reasons))
            self._table.setItem(row, 6, ri)
        self._table.blockSignals(False)
        self._refresh_selected()

    def _on_cell_changed(self, row, col):
        if col == 0:
            item = self._table.item(row, 0)
            entry = item.data(Qt.UserRole)
            if entry:
                entry.is_checked = item.checkState() == Qt.Checked
            self._refresh_selected()

    def _refresh_selected(self):
        total = sum(f.size for f in self.all_files if f.is_checked)
        self._lbl_selected.setText(f"Selected: {self._fmt(total)}")

    def select_all(self):
        self._table.blockSignals(True)
        for r in range(self._table.rowCount()):
            it = self._table.item(r, 0)
            it.setCheckState(Qt.Checked)
            e = it.data(Qt.UserRole)
            if e: e.is_checked = True
        self._table.blockSignals(False); self._refresh_selected()

    def deselect_all(self):
        self._table.blockSignals(True)
        for r in range(self._table.rowCount()):
            it = self._table.item(r, 0)
            it.setCheckState(Qt.Unchecked)
            e = it.data(Qt.UserRole)
            if e: e.is_checked = False
        self._table.blockSignals(False); self._refresh_selected()

    def filter_table(self, *_):
        text = self._search_input.text().lower()
        min_kb = self._spin_min_size.value()
        max_kb = self._spin_max_size.value()
        for r in range(self._table.rowCount()):
            path_item = self._table.item(r, 2)
            size_item = self._table.item(r, 3)
            if not path_item:
                continue
            hide = False
            if text and text not in path_item.text().lower():
                hide = True
            if size_item and isinstance(size_item, NumericItem):
                fkb = size_item._value / 1024
                if min_kb > 0 and fkb < min_kb:
                    hide = True
                if max_kb > 0 and fkb > max_kb:
                    hide = True
            self._table.setRowHidden(r, hide)

    def _on_score_threshold_changed(self, val):
        self._score_threshold = val
        self._lbl_score_thresh.setText(f"Score ≥ {val}")
        self._populate_table()

    # ══════════════════════════════════════════════════════
    #  Context Menus
    # ══════════════════════════════════════════════════════
    def _show_context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item:
            return
        row = item.row()
        path_item = self._table.item(row, 2)
        if not path_item:
            return
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#2b2b3d;color:#cdd6f4;border:1px solid #555;}"
            "QMenu::item:selected{background:#4CAF50;}")
        action_explore = QAction("📂 Open in File Explorer", self)
        action_trash   = QAction("🗑 Move to Trash", self)
        action_props   = QAction("ℹ File Properties", self)
        menu.addAction(action_explore); menu.addAction(action_trash)
        menu.addAction(action_props)
        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == action_explore:
            self._open_in_explorer(path_item.text())
        elif action == action_trash:
            entry = self._table.item(row, 0).data(Qt.UserRole)
            if entry:
                ok = QFile.moveToTrash(entry.path)
                self._log_deletion(entry.path, entry.size, "OK" if ok else "FAILED")
                if ok:
                    self._table.removeRow(row)
                    if entry in self.all_files:
                        self.all_files.remove(entry)
                    self._refresh_selected()
        elif action == action_props:
            entry = self._table.item(row, 0).data(Qt.UserRole)
            if entry:
                self._show_file_properties(entry)

    def _show_dup_context_menu(self, pos):
        item = self._tree_dup.itemAt(pos)
        if not item:
            return
        path = item.text(0)
        if not path or not os.path.exists(path):
            return
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#2b2b3d;color:#cdd6f4;border:1px solid #555;}"
            "QMenu::item:selected{background:#4CAF50;}")
        action_explore = QAction("📂 Open in File Explorer", self)
        menu.addAction(action_explore)
        action = menu.exec(self._tree_dup.viewport().mapToGlobal(pos))
        if action == action_explore:
            self._open_in_explorer(path)

    def _show_file_properties(self, entry: FileEntry):
        msg = (
            f"<b>Path:</b> {entry.path}<br>"
            f"<b>Size:</b> {self._fmt(entry.size)} ({entry.size:,} bytes)<br>"
            f"<b>Extension:</b> {entry.extension}<br>"
            f"<b>Score:</b> {entry.relevance_score}<br>"
            f"<b>Category:</b> {entry.category}<br><br>"
            f"<b>Created:</b> {entry.created.strftime('%Y-%m-%d %H:%M:%S')}<br>"
            f"<b>Modified:</b> {entry.modified.strftime('%Y-%m-%d %H:%M:%S')}<br>"
            f"<b>Accessed:</b> {entry.accessed.strftime('%Y-%m-%d %H:%M:%S')}<br><br>"
            f"<b>Reasons:</b><br>• " + "<br>• ".join(entry.reasons))
        QMessageBox.information(self, "File Properties", msg)

    def _open_in_explorer(self, path):
        if IS_WIN:    subprocess.Popen(f'explorer /select,"{path}"')
        elif IS_MAC:  subprocess.Popen(["open", "-R", path])
        else:         subprocess.Popen(["xdg-open", os.path.dirname(path)])

    # ══════════════════════════════════════════════════════
    #  Deletion (Move to Trash) with Progress
    # ══════════════════════════════════════════════════════
    def move_to_trash(self):
        sel = [f for f in self.all_files if f.is_checked]
        if not sel:
            QMessageBox.information(self, "Nothing selected", "No files are checked.")
            return
        sz = sum(f.size for f in sel)
        if QMessageBox.warning(
            self, "Confirm Move to Trash",
            f"Move <b>{len(sel):,}</b> files to Trash?<br>"
            f"Total size: <b>{self._fmt(sz)}</b>",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) != QMessageBox.Yes:
            return

        prog = QProgressDialog("Moving files to Trash…", "Cancel", 0, len(sel), self)
        prog.setWindowTitle("Deleting…")
        prog.setWindowModality(Qt.WindowModal)
        prog.setMinimumDuration(0)
        prog.setStyleSheet(_STYLESHEET)

        ok = fail = 0
        for i, e in enumerate(sel):
            if prog.wasCanceled():
                break
            prog.setValue(i)
            prog.setLabelText(f"Deleting: {os.path.basename(e.path)[:60]}")
            result = QFile.moveToTrash(e.path)
            if result:
                ok += 1
            else:
                fail += 1
            self._log_deletion(e.path, e.size, "OK" if result else "FAILED")

        prog.setValue(len(sel))
        QMessageBox.information(self, "Done",
            f"Moved to Trash: {ok}\nFailed: {fail}")
        self.start_scan()

    # ══════════════════════════════════════════════════════
    #  Deletion History
    # ══════════════════════════════════════════════════════
    def _log_deletion(self, path, size, result):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.deletion_log.append((ts, path, size, result))
        row = self._table_hist.rowCount(); self._table_hist.insertRow(row)
        self._table_hist.setItem(row, 0, QTableWidgetItem(ts))
        pi = QTableWidgetItem(path); pi.setToolTip(path)
        self._table_hist.setItem(row, 1, pi)
        si = QTableWidgetItem(self._fmt(size))
        si.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._table_hist.setItem(row, 2, si)
        ri = QTableWidgetItem(result)
        ri.setForeground(QColor("#4CAF50") if result == "OK" else QColor("#f44336"))
        self._table_hist.setItem(row, 3, ri)
        self._lbl_hist.setText(f"Deletions: {len(self.deletion_log)}")

    def _clear_deletion_log(self):
        self.deletion_log.clear()
        self._table_hist.setRowCount(0)
        self._lbl_hist.setText("No deletions yet")

    # ══════════════════════════════════════════════════════
    #  Duplicate Scanning
    # ══════════════════════════════════════════════════════
    def start_duplicate_scan(self):
        drive = self._get_scan_path()
        if not drive:
            return
        self._tree_dup.clear()
        excl = self._edit_exclusions.text().split(";")
        self.dup_scanner = DuplicateFinderThread(
            drive, min_size=1024,
            scan_hidden=self._chk_hidden.isChecked(),
            exclusion_patterns=excl)
        self.dup_scanner.duplicate_found.connect(self._on_dup_found)
        self.dup_scanner.progress_update.connect(self._on_dup_progress)
        self.dup_scanner.scan_complete.connect(self._on_dup_done)
        self._progress.setVisible(True); self._progress.setRange(0, 0)
        self._btn_dup.setEnabled(False)
        self._lbl_status.setText("Scanning for duplicates…")
        self._scan_start_time = time.time()
        self._timer.start(1000)
        self.dup_scanner.start()

    @Slot(list)
    def _on_dup_found(self, paths):
        try:
            sz = os.path.getsize(paths[0])
        except Exception:
            sz = 0
        grp = QTreeWidgetItem(
            [f"Duplicate group – {len(paths)} files", self._fmt(sz), ""])
        f = grp.font(0); f.setBold(True); grp.setFont(0, f)
        grp.setForeground(0, QColor("#FF9800"))
        for p in paths:
            try:
                mt = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
                s  = self._fmt(os.path.getsize(p))
            except Exception:
                mt = "?"; s = "?"
            ch = QTreeWidgetItem([p, s, mt])
            ch.setCheckState(0, Qt.Unchecked)
            ch.setToolTip(0, p)
            grp.addChild(ch)
        self._tree_dup.addTopLevelItem(grp)

    @Slot(str)
    def _on_dup_progress(self, msg):
        self._lbl_status.setText(msg[:120])

    @Slot(int, int)
    def _on_dup_done(self, total_dupes, wasted_bytes):
        self._timer.stop()
        elapsed = time.time() - self._scan_start_time
        m, s = divmod(int(elapsed), 60)
        self._progress.setVisible(False); self._btn_dup.setEnabled(True)
        self._lbl_dup_info.setText(
            f"🔀 {total_dupes:,} duplicate files  ·  "
            f"Wasted space: {self._fmt(wasted_bytes)}  (⏱ {m}:{s:02d})")
        self._btn_dup_auto.setEnabled(total_dupes > 0)
        self._btn_dup_del.setEnabled(total_dupes > 0)
        self._lbl_status.setText(f"Found {total_dupes:,} duplicates")

    def _dup_auto_select(self):
        """Auto-select all duplicates except the newest in each group."""
        root = self._tree_dup.invisibleRootItem()
        for i in range(root.childCount()):
            grp = root.child(i)
            children = []
            for j in range(grp.childCount()):
                ch = grp.child(j)
                try:
                    mt = os.path.getmtime(ch.text(0))
                except Exception:
                    mt = 0
                children.append((mt, j, ch))
            # Sort by mtime descending – newest first
            children.sort(key=lambda x: x[0], reverse=True)
            # Keep newest unchecked; check the rest
            for idx, (mt, j, ch) in enumerate(children):
                ch.setCheckState(0, Qt.Unchecked if idx == 0 else Qt.Checked)

    def _delete_dup_checked(self):
        to_del = []
        root = self._tree_dup.invisibleRootItem()
        for i in range(root.childCount()):
            grp = root.child(i)
            for j in range(grp.childCount()):
                ch = grp.child(j)
                if ch.checkState(0) == Qt.Checked:
                    to_del.append(ch.text(0))
        if not to_del:
            QMessageBox.information(self, "Nothing selected",
                                    "Check duplicate files first.")
            return
        if QMessageBox.warning(
            self, "Confirm",
            f"Move {len(to_del)} duplicate files to Trash?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) != QMessageBox.Yes:
            return
        ok = fail = 0
        for p in to_del:
            try:
                sz = os.path.getsize(p)
            except Exception:
                sz = 0
            result = QFile.moveToTrash(p)
            if result: ok += 1
            else:      fail += 1
            self._log_deletion(p, sz, "OK" if result else "FAILED")
        QMessageBox.information(self, "Done",
            f"Moved to Trash: {ok}\nFailed: {fail}")

    # ══════════════════════════════════════════════════════
    #  Save / Load Results
    # ══════════════════════════════════════════════════════
    def save_results(self):
        if not self.all_files:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "cleanup_results.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            data = {
                "version": "2.0",
                "platform": platform.system(),
                "saved_at": datetime.now().isoformat(),
                "scan_path": self._get_scan_path(),
                "total_reclaimable": self.total_reclaimable,
                "files": [f.to_dict() for f in self.all_files],
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Saved",
                f"Results saved to:\n{path}\n({len(self.all_files):,} files)")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def load_results(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Results", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.all_files.clear()
            self.files_by_category.clear()
            self.total_reclaimable = 0
            for fd in data.get("files", []):
                entry = FileEntry.from_dict(fd)
                self.all_files.append(entry)
                self.files_by_category[entry.category].append(entry)
                self.total_reclaimable += entry.size
            self._build_categories()
            self._show_category("All")
            self._update_chart()
            self._build_top_files()
            self._build_ext_table()
            self._lbl_files.setText(f"Files: {len(self.all_files):,}")
            self._lbl_reclaim.setText(f"Reclaimable: {self._fmt(self.total_reclaimable)}")
            self._btn_del.setEnabled(bool(self.all_files))
            self._btn_dup.setEnabled(True)
            saved = data.get("saved_at", "?")
            self._lbl_status.setText(
                f"Loaded {len(self.all_files):,} files (saved {saved})")
            self._lbl_status.setStyleSheet("color:#4CAF50;font-size:13px;")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load:\n{e}")

    # ══════════════════════════════════════════════════════
    #  Export CSV
    # ══════════════════════════════════════════════════════
    def export_to_csv(self):
        if not self.all_files:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "cleanup_report.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Path", "Size (Bytes)", "Size (Readable)", "Score",
                            "Category", "Last Accessed", "Created", "Reasons"])
                for e in self.all_files:
                    w.writerow([
                        e.path, e.size, self._fmt(e.size), e.relevance_score,
                        e.category, e.accessed.strftime("%Y-%m-%d %H:%M"),
                        e.created.strftime("%Y-%m-%d %H:%M"),
                        "; ".join(e.reasons)])
            QMessageBox.information(self, "Exported", f"Saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ══════════════════════════════════════════════════════
    #  OS-Specific Quick Cleanups
    # ══════════════════════════════════════════════════════
    def _clean_dir(self, path):
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Error", f"Directory not found:\n{path}")
            return
        if QMessageBox.warning(
            self, "Confirm", f"Delete contents of:\n{path}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) != QMessageBox.Yes:
            return
        del_count = 0; fail_count = 0
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path); del_count += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path); del_count += 1
                self._log_deletion(item_path,
                    os.path.getsize(item_path) if os.path.exists(item_path) else 0, "OK")
            except Exception:
                fail_count += 1
        QMessageBox.information(self, "Done",
            f"Cleaned {del_count} items.\nFailed: {fail_count}")

    # Windows
    def _quick_clean_temp(self):
        self._clean_dir(tempfile.gettempdir())

    def _quick_clean_user_temp(self):
        self._clean_dir(os.path.join(
            os.environ.get("USERPROFILE", ""), "AppData", "Local", "Temp"))

    def _quick_clean_recycle_win(self):
        if QMessageBox.warning(
            self, "Confirm", "Empty the Windows Recycle Bin?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) == QMessageBox.Yes:
            try:
                subprocess.run(
                    ["powershell", "-Command", "Clear-RecycleBin", "-Force"],
                    check=True)
                QMessageBox.information(self, "Done", "Recycle Bin emptied.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")

    def _open_disk_cleanup_win(self):
        try:
            subprocess.Popen("cleanmgr")
            QMessageBox.information(self, "Opened",
                                    "Windows Disk Cleanup utility launched.")
        except Exception:
            QMessageBox.critical(self, "Error", "Could not open Disk Cleanup.")

    # macOS
    def _quick_clean_trash_mac(self):
        trash_path = os.path.expanduser("~/.Trash")
        if QMessageBox.warning(
            self, "Confirm", "Empty the macOS Trash?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) == QMessageBox.Yes:
            self._clean_dir(trash_path)

    def _quick_clean_xcode_mac(self):
        derived_path = os.path.expanduser("~/Library/Developer/Xcode/DerivedData")
        if os.path.exists(derived_path):
            self._clean_dir(derived_path)
        else:
            QMessageBox.information(self, "Not Found",
                                    "Xcode DerivedData folder not found.")

    def _quick_clean_caches_mac(self):
        cache_path = os.path.expanduser("~/Library/Caches")
        if os.path.exists(cache_path):
            self._clean_dir(cache_path)

    # Linux
    def _quick_clean_trash_linux(self):
        trash_path = os.path.expanduser("~/.local/share/Trash")
        if os.path.exists(trash_path):
            self._clean_dir(trash_path)
        else:
            QMessageBox.information(self, "Not Found",
                                    "Linux Trash folder not found.")

    def _quick_clean_apt_linux(self):
        if QMessageBox.warning(
            self, "Confirm", "Clean APT cache? (Requires sudo privileges)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) == QMessageBox.Yes:
            try:
                subprocess.run(["pkexec", "apt", "clean"], check=True)
                QMessageBox.information(self, "Done", "APT cache cleaned.")
            except Exception:
                QMessageBox.warning(
                    self, "Permissions",
                    "Could not clean APT cache.\n"
                    "Run `sudo apt clean` in your terminal.")

    def _quick_clean_dnf_linux(self):
        if QMessageBox.warning(
            self, "Confirm", "Clean DNF cache? (Requires sudo privileges)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) == QMessageBox.Yes:
            try:
                subprocess.run(["pkexec", "dnf", "clean", "all"], check=True)
                QMessageBox.information(self, "Done", "DNF cache cleaned.")
            except Exception:
                QMessageBox.warning(
                    self, "Permissions",
                    "Could not clean DNF cache.\n"
                    "Run `sudo dnf clean all` in your terminal.")


# ══════════════════════════════════════════════════════════
#  Global Stylesheet  (enhanced for new widgets)
# ══════════════════════════════════════════════════════════
_STYLESHEET = """
QMainWindow, QWidget {
    background: #1a1a2e; color: #cdd6f4;
}
QFrame#topFrame  { background: #2b2b3d; border-radius: 8px; }
QFrame#statsBar  { background: #22223a; border-radius: 6px; }
QGroupBox {
    color: #cdd6f4; font-weight: bold; font-size: 13px;
    border: 1px solid #444; border-radius: 6px;
    margin-top: 12px; padding-top: 16px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 10px; padding: 0 6px;
}
QComboBox, QSpinBox, QLineEdit {
    background: #2b2b3d; color: #cdd6f4; padding: 5px;
    border: 1px solid #555; border-radius: 4px;
}
QComboBox QAbstractItemView {
    background: #2b2b3d; color: #cdd6f4;
    selection-background-color: #4CAF50;
}
QComboBox::drop-down { border: none; }
QComboBox::down-arrow { image: none; border: none; }
QTreeWidget {
    background: #1e1e2e; color: #cdd6f4;
    border: 1px solid #444; border-radius: 4px;
}
QTreeWidget::item:selected { background: #4CAF50; color: #fff; }
QTreeWidget::item:hover { background: #333; }
QTabWidget::pane { border: 1px solid #444; }
QTabBar::tab {
    background: #2b2b3d; color: #cdd6f4;
    padding: 8px 16px; margin: 2px; border-radius: 4px;
}
QTabBar::tab:selected { background: #4CAF50; color: #fff; }
QTableWidget {
    background: #1e1e2e; color: #cdd6f4;
    border: 1px solid #444; gridline-color: #333;
}
QTableWidget::item:selected { background: #4CAF50; color: #fff; }
QTableWidget::item:alternate { background: #252538; }
QHeaderView::section {
    background: #2b2b3d; color: #cdd6f4; padding: 6px;
    border: 1px solid #444; font-weight: bold;
}
QProgressBar {
    border: 1px solid #555; border-radius: 4px;
    text-align: center; height: 22px; color: #fff;
}
QProgressBar::chunk { background: #4CAF50; border-radius: 3px; }
QCheckBox { color: #cdd6f4; spacing: 6px; }
QCheckBox::indicator { width: 16px; height: 16px; }
QSlider::groove:horizontal {
    border: 1px solid #555; height: 6px; background: #333;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background: #4CAF50; border: none; width: 16px;
    margin: -5px 0; border-radius: 8px;
}
QSlider::sub-page:horizontal { background: #4CAF50; border-radius: 3px; }
QScrollBar:vertical {
    background: #1a1a2e; width: 10px; border: none;
}
QScrollBar::handle:vertical {
    background: #555; border-radius: 5px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #1a1a2e; height: 10px; border: none;
}
QScrollBar::handle:horizontal {
    background: #555; border-radius: 5px; min-width: 20px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QPushButton { min-height: 20px; }
QProgressDialog { background: #1a1a2e; color: #cdd6f4; }
QProgressDialog QLabel { color: #cdd6f4; }
QToolTip {
    background: #2b2b3d; color: #cdd6f4;
    border: 1px solid #555; padding: 4px;
}
"""

# ══════════════════════════════════════════════════════════
#  Main Entry Point
# ══════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window,          QColor(30, 30, 46))
    pal.setColor(QPalette.WindowText,      QColor(205, 214, 244))
    pal.setColor(QPalette.Base,            QColor(30, 30, 46))
    pal.setColor(QPalette.AlternateBase,   QColor(37, 37, 56))
    pal.setColor(QPalette.ToolTipBase,     QColor(49, 50, 68))
    pal.setColor(QPalette.ToolTipText,     QColor(205, 214, 244))
    pal.setColor(QPalette.Text,            QColor(205, 214, 244))
    pal.setColor(QPalette.Button,          QColor(49, 50, 68))
    pal.setColor(QPalette.ButtonText,      QColor(205, 214, 244))
    pal.setColor(QPalette.Highlight,       QColor(76, 175, 80))
    pal.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(pal)
    win = DriveCleanerWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()