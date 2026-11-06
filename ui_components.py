"""UI component helpers for TraceAnalyzer."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QTextOption
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
)


class UIFactory:
    """Factory helpers for the main TraceAnalyzer UI."""

    @staticmethod
    def create_separator() -> QFrame:
        """Create a subtle toolbar separator."""
        separator = QFrame()
        separator.setObjectName("toolbarSeparator")
        separator.setFrameShape(QFrame.VLine)
        separator.setFrameShadow(QFrame.Plain)
        separator.setFixedWidth(1)
        return separator

    @staticmethod
    def create_toolbar(callbacks: dict) -> tuple:
        """Create the main product-style toolbar."""
        toolbar = QFrame()
        toolbar.setObjectName("toolbarFrame")
        toolbar.setFrameShape(QFrame.NoFrame)
        toolbar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(20, 16, 20, 12)
        toolbar_layout.setSpacing(10)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(12)

        brand_title = QLabel("TraceAnalyzer")
        brand_title.setObjectName("brandTitle")
        title_row.addWidget(brand_title)

        brand_subtitle = QLabel("代码 / 指令分析工具")
        brand_subtitle.setObjectName("brandSubtitle")
        title_row.addWidget(brand_subtitle)
        title_row.addStretch(1)

        stats_card = QFrame()
        stats_card.setObjectName("statsCard")
        stats_card_layout = QVBoxLayout(stats_card)
        stats_card_layout.setContentsMargins(14, 8, 14, 8)
        stats_card_layout.setSpacing(2)

        stats_caption = QLabel("SYSTEM ONLINE")
        stats_caption.setObjectName("statsCardCaption")
        stats_card_layout.addWidget(stats_caption)

        stats_label = QLabel("")
        stats_label.setObjectName("statsCardValue")
        stats_label.setWordWrap(True)
        stats_card_layout.addWidget(stats_label)
        title_row.addWidget(stats_card, 0, Qt.AlignRight)

        toolbar_layout.addLayout(title_row)

        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.setSpacing(8)
        toolbar.controls_layout = controls_layout
        toolbar_layout.addLayout(controls_layout)

        load_btn = QPushButton("打开")
        load_btn.setObjectName("toolbarButton")
        load_btn.setMinimumWidth(94)
        load_btn.setMinimumHeight(36)
        if "load_file" in callbacks:
            load_btn.clicked.connect(callbacks["load_file"])
        controls_layout.addWidget(load_btn)

        controls_layout.addWidget(UIFactory.create_separator())

        search_label = QLabel("搜索")
        search_label.setObjectName("toolbarLabel")
        controls_layout.addWidget(search_label)

        search_input = QLineEdit()
        search_input.setObjectName("searchInput")
        search_input.setPlaceholderText("行号 / 地址 / 偏移 / 指令 / 数据 / 字符串...")
        search_input.setMinimumHeight(36)
        search_input.setMinimumWidth(220)
        search_input.setMaximumWidth(460)
        search_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if "search" in callbacks:
            search_input.returnPressed.connect(callbacks["search"])
        controls_layout.addWidget(search_input, 1)

        search_btn = QPushButton("查找")
        search_btn.setObjectName("toolbarButton")
        search_btn.setMinimumHeight(36)
        search_btn.setMinimumWidth(84)
        if "search" in callbacks:
            search_btn.clicked.connect(callbacks["search"])
        controls_layout.addWidget(search_btn)

        search_all_btn = QPushButton("地址全查")
        search_all_btn.setObjectName("toolbarButton")
        search_all_btn.setMinimumHeight(36)
        search_all_btn.setMinimumWidth(108)
        if "search_all" in callbacks:
            search_all_btn.clicked.connect(callbacks["search_all"])
        controls_layout.addWidget(search_all_btn)

        mnemonic_btn = QPushButton("指令全查")
        mnemonic_btn.setObjectName("toolbarButton")
        mnemonic_btn.setMinimumHeight(36)
        mnemonic_btn.setMinimumWidth(108)
        if "search_mnemonic" in callbacks:
            mnemonic_btn.clicked.connect(callbacks["search_mnemonic"])
        controls_layout.addWidget(mnemonic_btn)

        next_btn = QPushButton("下一个")
        next_btn.setObjectName("toolbarButton")
        next_btn.setMinimumHeight(36)
        next_btn.setMinimumWidth(96)
        if "search" in callbacks:
            next_btn.clicked.connect(callbacks["search"])
        controls_layout.addWidget(next_btn)

        controls_layout.addWidget(UIFactory.create_separator())
        controls_layout.addStretch(1)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 2, 0, 0)
        status_row.setSpacing(8)

        status_prefix = QLabel("状态")
        status_prefix.setObjectName("statusPrefix")
        status_row.addWidget(status_prefix)

        status_label = QLabel("就绪")
        status_label.setObjectName("statusLabel")
        status_label.setWordWrap(True)
        status_row.addWidget(status_label, 1)

        toolbar_layout.addLayout(status_row)
        return toolbar, search_input, status_label, stats_label

    @staticmethod
    def create_footer_bar() -> tuple:
        """Create a bottom status footer."""
        footer = QFrame()
        footer.setObjectName("footerFrame")
        footer.setFrameShape(QFrame.NoFrame)

        layout = QHBoxLayout(footer)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)

        labels = {}

        def add_card(key: str, caption: str, value: str, warning: bool = False):
            card = QFrame()
            card.setObjectName("footerWarningCard" if warning else "footerCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 8, 12, 8)
            card_layout.setSpacing(2)

            caption_label = QLabel(caption)
            caption_label.setObjectName("footerCaption")
            card_layout.addWidget(caption_label)

            value_label = QLabel(value)
            value_label.setObjectName("footerValue")
            value_label.setWordWrap(True)
            card_layout.addWidget(value_label)

            labels[key] = value_label
            layout.addWidget(card)

        add_card("status", "STATUS", "READY")
        add_card("mode", "MODE", "TRACE ANALYSIS")
        add_card("arch", "ARCH", "AARCH64")
        add_card("session", "SESSION", "WAITING")
        add_card("cache", "CACHE", "STRINGS: --  |  INST: --")
        add_card("performance", "PERFORMANCE", "READY")
        layout.addStretch(1)
        add_card("warning", "SYSTEM WARNING", "NONE", warning=True)
        return footer, labels

    @staticmethod
    def create_panel_title(text: str) -> QLabel:
        """Create a unified panel title bar."""
        title = QLabel(text)
        title.setObjectName("panelTitle")
        title.setMinimumHeight(38)
        return title

    @staticmethod
    def create_instruction_table() -> QTableWidget:
        """Create the left-side instruction table."""
        table = QTableWidget()
        table.setObjectName("instructionTable")
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["#", "地址", "偏移", "指令", "操作数", "注释"])
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setFont(QFont("Consolas", 10))
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        table.setColumnWidth(0, 68)
        table.setColumnWidth(1, 122)
        table.setColumnWidth(2, 86)
        table.setColumnWidth(3, 76)
        return table

    @staticmethod
    def create_instruction_panel() -> tuple:
        """Create the instruction panel and its table."""
        panel = QFrame()
        panel.setObjectName("panelCard")
        panel.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)
        layout.addWidget(UIFactory.create_panel_title("指令执行序列"))
        instruction_table = UIFactory.create_instruction_table()
        layout.addWidget(instruction_table)
        return panel, instruction_table

    @staticmethod
    def create_register_table() -> QTableWidget:
        """Create the right-side register table."""
        table = QTableWidget()
        table.setObjectName("registerTable")
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["寄存器", "X值(64位)", "W值(低32位)"])
        table.setFont(QFont("Consolas", 9))
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.setAlternatingRowColors(True)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        table.setColumnWidth(0, 90)
        return table

    @staticmethod
    def create_register_panel() -> tuple:
        """Create the register panel and its table."""
        panel = QFrame()
        panel.setObjectName("panelCard")
        panel.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)
        layout.addWidget(UIFactory.create_panel_title("寄存器状态"))
        register_table = UIFactory.create_register_table()
        layout.addWidget(register_table)
        return panel, register_table

    @staticmethod
    def create_memory_panel() -> tuple:
        """Create the memory panel and wrapped memory text area."""
        panel = QFrame()
        panel.setObjectName("panelCard")
        panel.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)
        layout.addWidget(UIFactory.create_panel_title("内存布局"))

        memory_display = QTextEdit()
        memory_display.setObjectName("memoryDisplay")
        memory_display.setReadOnly(True)
        memory_display.setFont(QFont("Consolas", 9))
        memory_display.setLineWrapMode(QTextEdit.WidgetWidth)
        memory_display.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        layout.addWidget(memory_display)
        return panel, memory_display

    @staticmethod
    def create_debug_panel() -> tuple:
        """Create the right-side splitter with register and memory panels."""
        panel = QFrame()
        panel.setObjectName("debugPanel")
        panel.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.setObjectName("debugSplitter")
        register_panel, register_table = UIFactory.create_register_panel()
        memory_panel, memory_display = UIFactory.create_memory_panel()
        right_splitter.addWidget(register_panel)
        right_splitter.addWidget(memory_panel)
        right_splitter.setStretchFactor(0, 4)
        right_splitter.setStretchFactor(1, 6)
        layout.addWidget(right_splitter)
        return panel, register_table, memory_display

    @staticmethod
    def create_progress_bar() -> QProgressBar:
        """Create the thin top progress bar."""
        progress_bar = QProgressBar()
        progress_bar.setObjectName("topProgressBar")
        progress_bar.setMaximumHeight(4)
        progress_bar.setTextVisible(False)
        progress_bar.setVisible(False)
        return progress_bar


def _palette(theme: str) -> dict:
    """Return palette tokens for the selected theme."""
    if theme == "midnight":
        return {
            "root_bg": "#060b12",
            "toolbar_start": "#0f1b2d",
            "toolbar_mid": "#09111d",
            "toolbar_end": "#0f1c26",
            "card_start": "#0d1624",
            "card_end": "#091019",
            "panel_title_start": "#102033",
            "panel_title_end": "#0a1521",
            "border": "#1f6c93",
            "border_soft": "#18455f",
            "accent": "#74d8ff",
            "accent_soft": "#8fd9f4",
            "accent_dim": "#68a9c8",
            "text": "#d9f6ff",
            "text_dim": "#95c8dd",
            "table_bg": "#071019",
            "table_alt": "#0b1520",
            "selection": "#155a85",
            "selection_text": "#f5fdff",
            "line": "#103044",
            "button_start": "#143149",
            "button_mid": "#0e2436",
            "button_end": "#091723",
            "button_hover_start": "#1a3f5f",
            "button_hover_end": "#102a3e",
            "button_border": "#2f90ba",
            "button_border_hover": "#7ad7ff",
            "input_bg": "#0b1522",
            "progress": "#42c8ff",
            "scroll_handle": "#2578a1",
            "scroll_hover": "#42c8ff",
        }
    return {
        "root_bg": "#080703",
        "toolbar_start": "#171008",
        "toolbar_mid": "#0e0b06",
        "toolbar_end": "#1a1208",
        "card_start": "#141007",
        "card_end": "#0d0a06",
        "panel_title_start": "#241a0c",
        "panel_title_end": "#151008",
        "border": "#7f5716",
        "border_soft": "#49340f",
        "accent": "#ffc857",
        "accent_soft": "#ffd97c",
        "accent_dim": "#c7983a",
        "text": "#f4deb0",
        "text_dim": "#ceb676",
        "table_bg": "#0a0906",
        "table_alt": "#110f0a",
        "selection": "#b96d0f",
        "selection_text": "#fff5d7",
        "line": "#281d0b",
        "button_start": "#3a2408",
        "button_mid": "#211507",
        "button_end": "#161006",
        "button_hover_start": "#4a2d09",
        "button_hover_end": "#281907",
        "button_border": "#b67f1d",
        "button_border_hover": "#ffbc42",
        "input_bg": "#100d07",
        "progress": "#ffb62f",
        "scroll_handle": "#7e5718",
        "scroll_hover": "#b67f1d",
    }


def get_theme_stylesheet(theme: str = "amber") -> str:
    """Return the app-wide stylesheet for the selected theme."""
    p = _palette(theme)
    return f"""
QWidget {{
    background-color: {p["root_bg"]};
    color: {p["text"]};
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 12px;
}}

QMainWindow,
QWidget#centralRoot {{
    background-color: {p["root_bg"]};
}}

QWidget#centralRoot {{
    border-image: none;
}}

QFrame#toolbarFrame,
QFrame#panelCard,
QFrame#statsCard,
QFrame#debugPanel,
QFrame#footerFrame,
QFrame#footerCard,
QFrame#footerWarningCard,
QDialog#floatingDialog,
QMessageBox {{
    background-color: {p["card_end"]};
    border: 1px solid {p["border"]};
    border-radius: 10px;
}}

QFrame#toolbarFrame {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {p["toolbar_start"]},
        stop:0.46 {p["toolbar_mid"]},
        stop:1 {p["toolbar_end"]}
    );
}}

QFrame#panelCard,
QFrame#debugPanel,
QDialog#floatingDialog,
QFrame#footerCard,
QFrame#footerWarningCard,
QFrame#statsCard {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {p["card_start"]},
        stop:1 {p["card_end"]}
    );
}}

QFrame#footerWarningCard {{
    border-color: {p["button_border_hover"]};
}}

QLabel#brandTitle {{
    color: {p["accent"]};
    font-size: 29px;
    font-weight: 800;
    padding: 2px 0;
}}

QLabel#brandSubtitle {{
    color: {p["text_dim"]};
    font-size: 15px;
    padding-top: 10px;
}}

QLabel#statsCardCaption,
QLabel#footerCaption {{
    color: {p["accent_dim"]};
    font-size: 10px;
    font-weight: 700;
}}

QLabel#statsCardValue {{
    color: {p["accent_soft"]};
    font-family: "Consolas", monospace;
    font-size: 18px;
    font-weight: 700;
}}

QLabel#footerValue {{
    color: {p["text"]};
    font-size: 12px;
    font-weight: 700;
}}

QLabel#toolbarLabel,
QLabel#statusPrefix {{
    color: {p["accent_dim"]};
    font-weight: 700;
}}

QLabel#statusLabel {{
    color: {p["text"]};
    font-size: 12px;
}}

QLabel#panelTitle {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {p["panel_title_start"]},
        stop:1 {p["panel_title_end"]}
    );
    color: {p["accent"]};
    border: none;
    border-bottom: 1px solid {p["border"]};
    padding: 9px 14px;
    font-size: 15px;
    font-weight: 800;
}}

QLabel#dialogSummary {{
    color: {p["text"]};
    background-color: {p["card_start"]};
    border: 1px solid {p["border_soft"]};
    border-radius: 7px;
    padding: 10px 12px;
}}

QTableWidget,
QTableView {{
    background-color: {p["table_bg"]};
    alternate-background-color: {p["table_alt"]};
    color: {p["text"]};
    gridline-color: {p["line"]};
    border: none;
    selection-background-color: {p["selection"]};
    selection-color: {p["selection_text"]};
    outline: 0;
}}

QTableWidget#instructionTable,
QTableWidget#registerTable,
QTableView#dialogResultsTable {{
    border-top: 1px solid {p["line"]};
}}

QTableWidget::item,
QTableView::item {{
    background-color: transparent;
    color: {p["text"]};
    padding: 3px 6px;
    border: none;
}}

QTableWidget::item:selected,
QTableView::item:selected {{
    background-color: {p["selection"]};
    color: {p["selection_text"]};
}}

QHeaderView::section {{
    background-color: {p["panel_title_end"]};
    color: {p["accent"]};
    padding: 7px 8px;
    border: none;
    border-right: 1px solid {p["line"]};
    border-bottom: 1px solid {p["border"]};
    font-weight: 800;
}}

QTextEdit {{
    background-color: {p["table_bg"]};
    color: {p["text"]};
    border: none;
    selection-background-color: {p["selection"]};
    selection-color: {p["selection_text"]};
    padding: 8px;
}}

QTextEdit#memoryDisplay {{
    font-family: "Consolas", monospace;
}}

QLineEdit {{
    background-color: {p["input_bg"]};
    color: {p["text"]};
    border: 1px solid {p["button_border"]};
    border-radius: 7px;
    padding: 7px 10px;
    selection-background-color: {p["selection"]};
}}

QLineEdit:focus {{
    border: 1px solid {p["button_border_hover"]};
}}

QPushButton {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {p["button_start"]},
        stop:0.55 {p["button_mid"]},
        stop:1 {p["button_end"]}
    );
    color: {p["accent_soft"]};
    border: 1px solid {p["button_border"]};
    border-radius: 7px;
    padding: 7px 16px;
    font-weight: 800;
    min-height: 22px;
}}

QPushButton:hover {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {p["button_hover_start"]},
        stop:1 {p["button_hover_end"]}
    );
    border: 1px solid {p["button_border_hover"]};
    color: {p["selection_text"]};
}}

QPushButton:pressed {{
    background-color: {p["button_end"]};
    border: 1px solid {p["accent"]};
}}

QProgressBar {{
    background-color: {p["card_start"]};
    border: none;
}}

QProgressBar::chunk {{
    background-color: {p["progress"]};
}}

QLabel {{
    background: transparent;
}}

QSplitter::handle {{
    background-color: {p["border_soft"]};
}}

QSplitter::handle:horizontal {{
    width: 5px;
}}

QSplitter::handle:vertical {{
    height: 5px;
}}

QMenu {{
    background-color: {p["card_start"]};
    color: {p["text"]};
    border: 1px solid {p["border"]};
}}

QMenu::item {{
    padding: 6px 18px;
}}

QMenu::item:selected {{
    background-color: {p["selection"]};
    color: {p["selection_text"]};
}}

QMessageBox QLabel {{
    color: {p["text"]};
}}

QMessageBox QPushButton {{
    min-width: 96px;
}}

QScrollBar:vertical {{
    background: {p["table_bg"]};
    width: 12px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: {p["scroll_handle"]};
    min-height: 24px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: {p["scroll_hover"]};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical,
QScrollBar:horizontal,
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {{
    background: transparent;
    border: none;
    height: 0;
    width: 0;
}}
"""


def get_dark_stylesheet() -> str:
    """Backwards-compatible alias for the default amber theme."""
    return get_theme_stylesheet("amber")
