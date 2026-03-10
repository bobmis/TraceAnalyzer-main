"""ui_components module."""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton,
    QTableWidget, QTextEdit, QSplitter, QLineEdit, QProgressBar,
    QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class UIFactory:
    """UIFactory class."""
    
    @staticmethod
    def create_separator() -> QFrame:
        """create_separator function."""
        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setFrameShadow(QFrame.Sunken)
        return separator
    
    @staticmethod
    def create_toolbar(callbacks: dict) -> tuple:
        """create_toolbar function."""
        toolbar = QFrame()
        toolbar.setFrameShape(QFrame.StyledPanel)
        toolbar.setMaximumHeight(40)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)
        toolbar_layout.setSpacing(6)
        
        load_btn = QPushButton('📁 打开')
        load_btn.setMaximumHeight(28)
        load_btn.setMinimumWidth(80)
        if 'load_file' in callbacks:
            load_btn.clicked.connect(callbacks['load_file'])
        toolbar_layout.addWidget(load_btn)
        
        toolbar_layout.addWidget(UIFactory.create_separator())
        
        search_label = QLabel('🔍')
        toolbar_layout.addWidget(search_label)
        
        search_input = QLineEdit()
        search_input.setPlaceholderText('行号/地址/偏移/指令...')
        search_input.setMaximumHeight(26)
        search_input.setMinimumWidth(180)
        search_input.setMaximumWidth(250)
        if 'search' in callbacks:
            search_input.returnPressed.connect(callbacks['search'])
        toolbar_layout.addWidget(search_input)
        
        search_btn = QPushButton('查找')
        search_btn.setMaximumHeight(26)
        search_btn.setMaximumWidth(80)
        if 'search' in callbacks:
            search_btn.clicked.connect(callbacks['search'])
        toolbar_layout.addWidget(search_btn)

        search_all_btn = QPushButton('地址全查')
        search_all_btn.setMaximumHeight(26)
        search_all_btn.setMaximumWidth(110)
        if 'search_all' in callbacks:
            search_all_btn.clicked.connect(callbacks['search_all'])
        toolbar_layout.addWidget(search_all_btn)

        mnemonic_btn = QPushButton('指令全查')
        mnemonic_btn.setMaximumHeight(26)
        mnemonic_btn.setMaximumWidth(110)
        if 'search_mnemonic' in callbacks:
            mnemonic_btn.clicked.connect(callbacks['search_mnemonic'])
        toolbar_layout.addWidget(mnemonic_btn)

        next_btn = QPushButton('下一个')
        next_btn.setMaximumHeight(26)
        next_btn.setMaximumWidth(100)
        if 'search' in callbacks:
            next_btn.clicked.connect(callbacks['search'])
        toolbar_layout.addWidget(next_btn)
        
        toolbar_layout.addWidget(UIFactory.create_separator())
        
        status_label = QLabel('就绪')
        status_label.setStyleSheet("color: #cccccc; font-size: 11px;")
        toolbar_layout.addWidget(status_label, 1)
        
        stats_label = QLabel('')
        stats_label.setStyleSheet("color: #569cd6; font-size: 11px;")
        toolbar_layout.addWidget(stats_label)
        
        return toolbar, search_input, status_label, stats_label
    
    @staticmethod
    def create_instruction_table() -> QTableWidget:
        """create_instruction_table function."""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(['#', '地址', '偏移', '指令', '操作数', '注释'])
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setFont(QFont('Consolas', 10))
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        
        table.setStyleSheet("""
            QTableWidget::item:selected {
                background-color: rgb(37, 99, 235);
                color: white;
            }
        """)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        table.setColumnWidth(0, 60)
        table.setColumnWidth(1, 120)
        table.setColumnWidth(2, 80)
        table.setColumnWidth(3, 80)
        
        return table
    
    @staticmethod
    def create_instruction_panel() -> tuple:
        """create_instruction_panel function."""
        panel = QFrame()
        panel.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header = QLabel('  指令执行序列')
        header.setStyleSheet("background: #2d2d30; color: #cccccc; padding: 8px; font-weight: bold;")
        layout.addWidget(header)
        
        instruction_table = UIFactory.create_instruction_table()
        layout.addWidget(instruction_table)
        
        return panel, instruction_table
    
    @staticmethod
    def create_register_table() -> QTableWidget:
        """create_register_table function."""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(['寄存器', 'X值 (64位)', 'W值 (低32位)'])
        table.setFont(QFont('Consolas', 9))
        table.horizontalHeader().setStretchLastSection(True)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        
        table.setStyleSheet("""
            QTableWidget::item:selected {
                background-color: rgb(37, 99, 235);
                color: white;
            }
        """)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        table.setColumnWidth(0, 80)
        
        return table
    
    @staticmethod
    def create_register_panel() -> tuple:
        """create_register_panel function."""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header = QLabel('  寄存器状态')
        header.setStyleSheet("background: #2d2d30; color: #cccccc; padding: 8px; font-weight: bold;")
        layout.addWidget(header)
        
        register_table = UIFactory.create_register_table()
        layout.addWidget(register_table)
        
        return panel, register_table
    
    @staticmethod
    def create_memory_panel() -> tuple:
        """create_memory_panel function."""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header = QLabel('  内存布局')
        header.setStyleSheet("background: #2d2d30; color: #cccccc; padding: 8px; font-weight: bold;")
        layout.addWidget(header)
        
        memory_display = QTextEdit()
        memory_display.setReadOnly(True)
        memory_display.setFont(QFont('Consolas', 9))
        memory_display.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(memory_display)
        
        return panel, memory_display
    
    @staticmethod
    def create_debug_panel() -> tuple:
        """create_debug_panel function."""
        panel = QFrame()
        panel.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        right_splitter = QSplitter(Qt.Vertical)
        
        register_panel, register_table = UIFactory.create_register_panel()
        right_splitter.addWidget(register_panel)
        
        memory_panel, memory_display = UIFactory.create_memory_panel()
        right_splitter.addWidget(memory_panel)
        
        right_splitter.setStretchFactor(0, 4)
        right_splitter.setStretchFactor(1, 6)
        
        layout.addWidget(right_splitter)
        
        return panel, register_table, memory_display
    
    @staticmethod
    def create_progress_bar() -> QProgressBar:
        """create_progress_bar function."""
        progress_bar = QProgressBar()
        progress_bar.setMaximumHeight(3)
        progress_bar.setTextVisible(False)
        progress_bar.setVisible(False)
        return progress_bar


def get_dark_stylesheet() -> str:
    """get_dark_stylesheet function."""
    return """
    QMainWindow, QWidget {
        background-color: #1e1e1e;
        color: #d4d4d4;
    }
    QFrame {
        background-color: #252526;
        border: 1px solid #3e3e42;
    }
    QTableWidget {
        background-color: #1e1e1e;
        gridline-color: #3e3e42;
        border: none;
        selection-background-color: #094771;
    }
    QTableWidget::item:selected {
        background-color: #094771;
    }
    QTableWidget::item:alternate {
        background-color: #252526;
    }
    QHeaderView::section {
        background-color: #2d2d30;
        color: #cccccc;
        padding: 6px;
        border: none;
        border-bottom: 1px solid #3e3e42;
        border-right: 1px solid #3e3e42;
        font-weight: bold;
    }
    QTextEdit {
        background-color: #1e1e1e;
        border: none;
        selection-background-color: #264f78;
    }
    QPushButton {
        background-color: #0e639c;
        color: white;
        border: none;
        padding: 6px 16px;
        border-radius: 2px;
        font-weight: 500;
    }
    QPushButton:hover {
        background-color: #1177bb;
    }
    QPushButton:pressed {
        background-color: #094771;
    }
    QLineEdit {
        background-color: #3c3c3c;
        color: #cccccc;
        border: 1px solid #3e3e42;
        padding: 5px;
        border-radius: 2px;
    }
    QLineEdit:focus {
        border: 1px solid #007acc;
    }
    QProgressBar {
        background-color: #252526;
        border: none;
    }
    QProgressBar::chunk {
        background-color: #007acc;
    }
    QLabel {
        background: transparent;
    }
    QSplitter::handle {
        background-color: #3e3e42;
    }
    QSplitter::handle:horizontal {
        width: 4px;
    }
    QSplitter::handle:vertical {
        height: 4px;
    }
    QMenu {
        background-color: #252526;
        color: #cccccc;
        border: 1px solid #3e3e42;
    }
    QMenu::item:selected {
        background-color: #094771;
    }
    """
