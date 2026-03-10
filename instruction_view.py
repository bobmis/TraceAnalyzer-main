"""instruction_view module."""
import math
from typing import Optional, Callable, List, Dict, TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QScrollBar, QLabel, QFrame, QHeaderView, QAbstractItemView, QApplication
)
from PySide6.QtCore import Qt, QTimer, QObject, Signal, QThread
from PySide6.QtGui import QColor, QFont, QWheelEvent, QKeySequence, QShortcut

if TYPE_CHECKING:
    from lazy_parser import LazyLogParser


class DataCacheWorker(QThread):
    """DataCacheWorker class."""
    
    progress = Signal(int, int)  # current, total
    finished = Signal()
    
    def __init__(self, parser: 'LazyLogParser', instruction_count: int):
        super().__init__()
        self.parser = parser
        self.instruction_count = instruction_count
        self._running = True
        
        self.data_cache: List[Dict] = [None] * instruction_count
    
    def run(self):
        """run function."""
        print(f"[缓存] 开始缓存 {self.instruction_count} 行数据...")
        
        batch_size = 10000
        for start in range(0, self.instruction_count, batch_size):
            if not self._running:
                break
            
            end = min(start + batch_size, self.instruction_count)
            for i in range(start, end):
                if not self._running:
                    break
                instr_info = self.parser.get_instruction_info(i)
                if instr_info:
                    self.data_cache[i] = {
                        'num': str(i + 1),
                        'address': instr_info.address,
                        'offset': instr_info.offset,
                        'mnemonic': instr_info.mnemonic,
                        'operands': instr_info.operands,
                        'comment': instr_info.comment
                    }
            
            self.progress.emit(end, self.instruction_count)
        
        if self._running:
            self.finished.emit()
            print(f"[缓存] 数据缓存完成")
    
    def stop(self):
        self._running = False
    
    def get_row_data(self, index: int) -> Optional[Dict]:
        """get_row_data function."""
        if 0 <= index < len(self.data_cache):
            return self.data_cache[index]
        return None


class VirtualScrollTable(QWidget):
    """VirtualScrollTable class."""
    
    selection_changed = Signal(int)
    row_clicked = Signal(int)
    scroll_stopped = Signal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.parser: Optional['LazyLogParser'] = None
        self.total_rows = 0
        self.visible_rows = 50
        self.current_top = 0
        self.selected_logical_row = -1
        
        self.data_cache: Optional[DataCacheWorker] = None
        
        self.is_scrolling = False
        self.allow_heavy_update = True
        self.scroll_timer = QTimer()
        self.scroll_timer.setSingleShot(True)
        self.scroll_timer.timeout.connect(self._on_scroll_stopped)
        
        self._init_ui()
        
        QTimer.singleShot(0, self._calculate_visible_rows)
    
    def _init_ui(self):
        """_init_ui function."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(['#', '地址', '偏移', '指令', '操作数', '注释'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFont(QFont('Consolas', 10))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 80)
        
        self.table.setStyleSheet("""
            QTableWidget::item:selected {
                background-color: rgb(37, 99, 235);
                color: white;
            }
        """)
        
        self.table.itemSelectionChanged.connect(self._on_table_selection_changed)
        self.table.cellClicked.connect(self._on_cell_clicked)
        
        copy_row_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.table)
        copy_row_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        copy_row_shortcut.activated.connect(self._copy_selected_row_to_clipboard)
        
        layout.addWidget(self.table)
        
        self.scrollbar = QScrollBar(Qt.Vertical)
        self.scrollbar.setMinimum(0)
        self.scrollbar.valueChanged.connect(self._on_scrollbar_changed)
        layout.addWidget(self.scrollbar)
        
        self._init_empty_table()
    
    def _calculate_visible_rows(self):
        """_calculate_visible_rows function."""
        if not self.table:
            return
        
        available_height = self.table.viewport().height()
        
        if available_height <= 0:
            return
        
        if self.table.rowCount() > 0:
            row_height = self.table.rowHeight(0)
        else:
            self.table.setRowCount(1)
            row_height = self.table.rowHeight(0)
            if row_height <= 0:
                self.table.setRowHeight(0, 24)
                row_height = self.table.rowHeight(0)
            self.table.setRowCount(0)
        
        if row_height <= 0:
            row_height = 24
        
        calculated_rows = (available_height + row_height * 0.8) / row_height
        new_visible_rows = max(1, int(math.ceil(calculated_rows)))
        
        
        if new_visible_rows != self.visible_rows:
            old_selected = self.selected_logical_row
            old_top = self.current_top
            
            self.visible_rows = new_visible_rows
            
            current_row_count = self.table.rowCount()
            if current_row_count != self.visible_rows:
                if self.visible_rows > current_row_count:
                    for row in range(current_row_count, self.visible_rows):
                        for col in range(6):
                            item = QTableWidgetItem('')
                            self.table.setItem(row, col, item)
                else:
                    self.table.setRowCount(self.visible_rows)
            
            if self.total_rows > 0:
                max_scroll = max(0, self.total_rows - self.visible_rows)
                self.scrollbar.setMaximum(max_scroll)
                self.scrollbar.setPageStep(self.visible_rows)
                
                if self.current_top > max_scroll:
                    self.current_top = max_scroll
                    self.scrollbar.setValue(self.current_top)
                
                self._update_visible_rows()
                
                if old_selected >= 0:
                    self.select_logical_row(old_selected)
    
    def resizeEvent(self, event):
        """resizeEvent function."""
        super().resizeEvent(event)
        QTimer.singleShot(10, self._calculate_visible_rows)
    
    def _init_empty_table(self):
        """_init_empty_table function."""
        self.table.setRowCount(self.visible_rows)
        for row in range(self.visible_rows):
            for col in range(6):
                item = QTableWidgetItem('')
                self.table.setItem(row, col, item)
    
    def wheelEvent(self, event: QWheelEvent):
        """wheelEvent function."""
        delta = event.angleDelta().y()
        steps = -delta // 40
        new_value = self.scrollbar.value() + steps
        new_value = max(0, min(new_value, self.scrollbar.maximum()))
        self.scrollbar.setValue(new_value)
        event.accept()
    
    def set_data(self, parser: 'LazyLogParser', total_rows: int):
        """set_data function."""
        if self.data_cache:
            self.data_cache.stop()
            self.data_cache.wait()
        
        self.parser = parser
        self.total_rows = total_rows
        self.current_top = 0
        self.selected_logical_row = -1
        
        self._calculate_visible_rows()
        
        max_scroll = max(0, total_rows - self.visible_rows)
        self.scrollbar.setMaximum(max_scroll)
        self.scrollbar.setPageStep(self.visible_rows)
        self.scrollbar.setValue(0)
        
        self.data_cache = DataCacheWorker(parser, total_rows)
        self.data_cache.progress.connect(self._on_cache_progress)
        self.data_cache.finished.connect(self._on_cache_finished)
        self.data_cache.start()
        
        self._update_visible_rows()
    
    def _on_cache_progress(self, current: int, total: int):
        """_on_cache_progress function."""
        pass
    
    def _on_cache_finished(self):
        """_on_cache_finished function."""
        print("[虚拟滚动] 数据缓存完成，滚动将更流畅")
    
    def _on_scrollbar_changed(self, value: int):
        """_on_scrollbar_changed function."""
        self.current_top = value
        self.is_scrolling = True
        self.allow_heavy_update = False
        
        self._update_visible_rows()
        
        self.scroll_timer.stop()
        self.scroll_timer.start(200)
    
    def _update_visible_rows(self):
        """_update_visible_rows function."""
        self.table.setUpdatesEnabled(False)
        try:
            for visual_row in range(self.visible_rows):
                logical_row = self.current_top + visual_row
                self._update_row(visual_row, logical_row)
        finally:
            self.table.setUpdatesEnabled(True)
    
    def _update_row(self, visual_row: int, logical_row: int):
        """_update_row function."""
        if logical_row >= self.total_rows:
            for col in range(6):
                item = self.table.item(visual_row, col)
                if item:
                    item.setText('')
            return
        
        data = None
        if self.data_cache and self.data_cache.data_cache[logical_row]:
            data = self.data_cache.data_cache[logical_row]
        elif self.parser:
            instr_info = self.parser.get_instruction_info(logical_row)
            if instr_info:
                data = {
                    'num': str(logical_row + 1),
                    'address': instr_info.address,
                    'offset': instr_info.offset,
                    'mnemonic': instr_info.mnemonic,
                    'operands': instr_info.operands,
                    'comment': instr_info.comment
                }
        
        if not data:
            return
        
        colors = [
            QColor(128, 128, 128),
            QColor(86, 156, 214), 
            QColor(128, 128, 128),
            QColor(220, 220, 170),
            QColor(206, 145, 120),
            QColor(106, 153, 85), 
        ]
        values = [data['num'], data['address'], data['offset'], 
                  data['mnemonic'], data['operands'], data['comment']]
        
        for col, (value, color) in enumerate(zip(values, colors)):
            item = self.table.item(visual_row, col)
            if item:
                item.setText(value)
                item.setForeground(color)
                if col == 0:
                    item.setTextAlignment(Qt.AlignCenter)
    
    def _on_scroll_stopped(self):
        """_on_scroll_stopped function."""
        self.is_scrolling = False
        self.allow_heavy_update = True
        
        middle_row = self.current_top + self.visible_rows // 2
        if middle_row >= self.total_rows:
            middle_row = self.total_rows - 1
        
        if self.selected_logical_row < 0:
            self.selected_logical_row = middle_row
        
        self.scroll_stopped.emit(self.selected_logical_row)
    
    def _on_table_selection_changed(self):
        """_on_table_selection_changed function."""
        selected = self.table.selectedItems()
        if selected:
            visual_row = selected[0].row()
            logical_row = self.current_top + visual_row
            self.selected_logical_row = logical_row
            
            if self.allow_heavy_update:
                self.selection_changed.emit(logical_row)
    
    def _on_cell_clicked(self, visual_row: int, col: int):
        """_on_cell_clicked function."""
        logical_row = self.current_top + visual_row
        self.selected_logical_row = logical_row
        self.is_scrolling = False
        self.allow_heavy_update = True
        self.row_clicked.emit(logical_row)
    
    def select_logical_row(self, logical_row: int):
        """select_logical_row function."""
        if logical_row < 0 or logical_row >= self.total_rows:
            return
        
        self.selected_logical_row = logical_row
        
        if logical_row < self.current_top or logical_row >= self.current_top + self.visible_rows:
            new_top = max(0, logical_row - self.visible_rows // 2)
            new_top = min(new_top, self.total_rows - self.visible_rows)
            self.scrollbar.setValue(new_top)
        
        visual_row = logical_row - self.current_top
        if 0 <= visual_row < self.visible_rows:
            self.table.selectRow(visual_row)
    
    def get_selected_logical_row(self) -> int:
        """get_selected_logical_row function."""
        return self.selected_logical_row
    
    _COPY_COL_WIDTHS = (6, 14, 10, 8, 40)

    def _copy_selected_row_to_clipboard(self):
        """_copy_selected_row_to_clipboard function."""
        logical_row = self.selected_logical_row
        if logical_row < 0 or logical_row >= self.total_rows:
            return
        data = None
        if self.data_cache:
            data = self.data_cache.get_row_data(logical_row)
        if not data and self.parser:
            instr_info = self.parser.get_instruction_info(logical_row)
            if instr_info:
                data = {
                    'num': str(logical_row + 1),
                    'address': instr_info.address,
                    'offset': instr_info.offset,
                    'mnemonic': instr_info.mnemonic,
                    'operands': instr_info.operands,
                    'comment': instr_info.comment
                }
        if not data:
            return
        w_num, w_addr, w_offset, w_mnemonic, w_instr = self._COPY_COL_WIDTHS
        num_str = (data.get('num') or '').strip()[:w_num].ljust(w_num)
        addr_str = (data.get('address') or '').strip()[:w_addr].ljust(w_addr)
        offset_str = (data.get('offset') or '').strip()[:w_offset].ljust(w_offset)
        mnemonic = (data.get('mnemonic') or '').strip()[:w_mnemonic].ljust(w_mnemonic)
        operands = (data.get('operands') or '').strip()
        instr_part = (mnemonic + ' ' + operands).strip()[:w_instr].ljust(w_instr)
        comment = (data.get('comment') or '').strip()
        line = f"{num_str} {addr_str} {offset_str} {instr_part} ;{comment}"
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(line)
    
    def clear(self):
        """clear function."""
        if self.data_cache:
            self.data_cache.stop()
            self.data_cache.wait()
            self.data_cache = None
        
        self.total_rows = 0
        self.current_top = 0
        self.selected_logical_row = -1
        self.scrollbar.setMaximum(0)
        
        for visual_row in range(self.visible_rows):
            for col in range(6):
                item = self.table.item(visual_row, col)
                if item:
                    item.setText('')


class InstructionViewController(QObject):
    """InstructionViewController class."""
    
    scroll_stopped = Signal(int)
    request_precache = Signal(int, int)
    
    def __init__(self, table: QTableWidget, parent=None):
        super().__init__(parent)
        self.virtual_table: Optional[VirtualScrollTable] = None
        self.parser = None
        self.instruction_count = 0
        self.is_scrolling = False
        self.allow_heavy_update = True
        self.selected_index = -1
    
    def set_virtual_table(self, virtual_table: VirtualScrollTable):
        """set_virtual_table function."""
        self.virtual_table = virtual_table
        self.virtual_table.scroll_stopped.connect(self._on_scroll_stopped)
        self.virtual_table.selection_changed.connect(self._on_selection_changed)
        self.virtual_table.row_clicked.connect(self._on_row_clicked)
    
    def set_parser(self, parser: 'LazyLogParser', instruction_count: int):
        """set_parser function."""
        self.parser = parser
        self.instruction_count = instruction_count
        self.selected_index = -1
    
    def initialize_table(self, initial_batch_size: int = 500):
        """initialize_table function."""
        if self.virtual_table and self.parser:
            self.virtual_table.set_data(self.parser, self.instruction_count)
    
    def _on_scroll_stopped(self, logical_row: int):
        """_on_scroll_stopped function."""
        self.is_scrolling = False
        self.allow_heavy_update = True
        self.selected_index = logical_row
        self.scroll_stopped.emit(logical_row)
    
    def _on_selection_changed(self, logical_row: int):
        """_on_selection_changed function."""
        self.selected_index = logical_row
    
    def _on_row_clicked(self, logical_row: int):
        """_on_row_clicked function."""
        self.is_scrolling = False
        self.allow_heavy_update = True
        self.selected_index = logical_row
    
    def on_instruction_clicked(self):
        """on_instruction_clicked function."""
        self.is_scrolling = False
        self.allow_heavy_update = True
    
    def ensure_row_rendered(self, row: int):
        """ensure_row_rendered function."""
        pass
    
    def select_row(self, row: int, scroll_to: bool = True):
        """select_row function."""
        if self.virtual_table:
            self.virtual_table.select_logical_row(row)
    
    def clear(self):
        """clear function."""
        if self.virtual_table:
            self.virtual_table.clear()
        self.selected_index = -1
