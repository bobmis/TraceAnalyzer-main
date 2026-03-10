"""main module."""
import sys
import time
import re
from pathlib import Path
from typing import Optional, List, Tuple, Dict

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QMessageBox, QMenu, QTableWidgetItem,
    QAbstractItemView, QFrame, QLabel, QDialog, QTableWidget, QHeaderView
)
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QKeySequence, QShortcut

from parser import Instruction
from lazy_parser import LazyLogParser
from register import Register, RegisterState
from cache_worker import CacheWorker
from register_calc import RegisterCalculator
from instruction_view import VirtualScrollTable, InstructionViewController
from ui_components import UIFactory, get_dark_stylesheet


class ParseThread(QThread):
    """ParseThread class."""
    finished = Signal(object, object)
    error = Signal(str)
    file_loaded = Signal()

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
    
    def run(self):
        try:
            parser = LazyLogParser(self.file_path)
            count, initial_sp = parser.build_index()
            parser.load_file_lines()
            self.file_loaded.emit()
            self.finished.emit(parser, initial_sp)
        except Exception as e:
            self.error.emit(str(e))


class SortableTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by an explicit key."""

    def __init__(self, text: str, sort_key=None):
        super().__init__(text)
        self._sort_key = text if sort_key is None else sort_key

    def __lt__(self, other):
        if isinstance(other, SortableTableWidgetItem):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.parser: Optional[LazyLogParser] = None
        self.instruction_count = 0
        self.initial_sp: Optional[str] = None
        
        self.cache_worker: Optional[CacheWorker] = None
        self.register_calc: Optional[RegisterCalculator] = None
        
        self.parse_thread: Optional[ParseThread] = None
        
        
        self.instruction_view: Optional[InstructionViewController] = None
        
        self.history: List[int] = []
        self.history_index = -1
        self.max_history = 100
        
        self.selected_register: Optional[str] = None
        self.selected_index = -1
        
        self.search_input = None
        self.status_label = None
        self.stats_label = None
        self.progress_bar = None
        self.virtual_table: Optional[VirtualScrollTable] = None
        self.register_table = None
        self.memory_display = None
        
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle('TraceAnalyzer')
        self.setGeometry(100, 100, 1800, 1000)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        
        toolbar, self.search_input, self.status_label, self.stats_label = UIFactory.create_toolbar({
            'load_file': self.load_file,
            'search': self.search_instruction,
            'search_all': self.search_all_addresses,
            'search_mnemonic': self.search_instructions_by_mnemonic
        })
        main_layout.addWidget(toolbar)
        
        
        self.progress_bar = UIFactory.create_progress_bar()
        main_layout.addWidget(self.progress_bar)
        
        content_splitter = QSplitter(Qt.Horizontal)
        
        
        instruction_panel = self._create_instruction_panel()
        content_splitter.addWidget(instruction_panel)
        
        
        debug_panel, self.register_table, self.memory_display = UIFactory.create_debug_panel()
        content_splitter.addWidget(debug_panel)
        
        content_splitter.setStretchFactor(0, 6)
        content_splitter.setStretchFactor(1, 4)
        
        main_layout.addWidget(content_splitter)
        
        self.instruction_view = InstructionViewController(None, self)
        self.instruction_view.set_virtual_table(self.virtual_table)
        self.instruction_view.scroll_stopped.connect(self.on_scroll_stopped)
        self.instruction_view.request_precache.connect(self.on_request_precache)
        
        self.virtual_table.selection_changed.connect(self.on_instruction_selected_virtual)
        self.virtual_table.row_clicked.connect(self.on_instruction_clicked_virtual)
        
        
        self.register_table.customContextMenuRequested.connect(self.show_register_menu)
        self.register_table.cellDoubleClicked.connect(self.on_register_double_click)
        self.register_table.itemSelectionChanged.connect(self.on_register_click)
        
        
        self.setup_shortcuts()
    
    def _create_instruction_panel(self) -> QFrame:
        """_create_instruction_panel function."""
        panel = QFrame()
        panel.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header = QLabel("  指令执行序列")
        header.setStyleSheet("background: #2d2d30; color: #cccccc; padding: 8px; font-weight: bold;")
        layout.addWidget(header)
        
        self.virtual_table = VirtualScrollTable()
        layout.addWidget(self.virtual_table)
        
        return panel
    
    def load_file(self):
        """load_file function."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择日志文件", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if not file_path:
            return
        
        self._cleanup()
        
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"正在建立索引: {Path(file_path).name}...")
        self.setEnabled(False)
        
        self.parse_thread = ParseThread(file_path)
        self.parse_thread.finished.connect(self.on_parse_finished)
        self.parse_thread.error.connect(self.on_parse_error)
        self.parse_thread.file_loaded.connect(self.on_file_lines_loaded)
        self.parse_thread.start()
    
    def _cleanup(self):
        """_cleanup function."""
        if self.cache_worker:
            self.cache_worker.stop()
            self.cache_worker = None
        
        self.parser = None
        self.instruction_count = 0
        self.selected_index = -1
        self.history.clear()
        self.history_index = -1
        
        if self.register_table:
            self.register_table.setRowCount(0)
        if self.memory_display:
            self.memory_display.clear()
        
        if self.instruction_view:
            self.instruction_view.clear()
    
    def on_parse_finished(self, parser: LazyLogParser, initial_sp: Optional[str]):
        """on_parse_finished function."""
        self.parser = parser
        self.instruction_count = parser.get_instruction_count()
        self.initial_sp = initial_sp
        
        
        self.cache_worker = CacheWorker(parser, checkpoint_interval=500)
        self.cache_worker.checkpoint_ready.connect(self.on_checkpoint_ready)
        self.cache_worker.progress.connect(self.on_cache_progress)
        self.cache_worker.all_checkpoints_ready.connect(self.on_all_checkpoints_ready)
        
        
        self.register_calc = RegisterCalculator(parser, self.cache_worker)
        
        self.instruction_view.set_parser(parser, self.instruction_count)
        
        self.stats_label.setText(f'Total {self.instruction_count:,} instructions')
        
    def on_parse_error(self, error_msg: str):
        """on_parse_error function."""
        QMessageBox.critical(self, "错误", f"解析文件失败: {error_msg}")
        self.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("加载失败")

    def on_file_lines_loaded(self):
        """on_file_lines_loaded function."""
        QTimer.singleShot(10, self.delayed_update_table)
    def delayed_update_table(self):
        """delayed_update_table function."""
        self.instruction_view.initialize_table(500)

        self.status_label.setText("就绪")

        self.progress_bar.setVisible(False)
        self.setEnabled(True)

        self.cache_worker.start_building_checkpoints()

    def on_checkpoint_ready(self, index: int, state: RegisterState):
        """on_checkpoint_ready function."""
        pass
    
    def on_cache_progress(self, current: int, total: int):
        """on_cache_progress function."""
        if total > 0:
            percent = current * 100 // total
            self.stats_label.setText(f'Total {self.instruction_count:,} instructions')
    
    def on_all_checkpoints_ready(self):
        """on_all_checkpoints_ready function."""
        self.stats_label.setText(f'Total {self.instruction_count:,} instructions')
        print("[缓存] 所有检查点构建完成")
    
    def on_request_precache(self, start: int, end: int):
        """on_request_precache function."""
        if self.cache_worker:
            self.cache_worker.request_range_cache(start, end)
    
    def on_scroll_stopped(self, index: int):
        """on_scroll_stopped function."""
        self.selected_index = index
        self.update_selected_instruction_details()
    
    def on_instruction_clicked_virtual(self, logical_row: int):
        """on_instruction_clicked_virtual function."""
        self.selected_index = logical_row
        if self.instruction_view:
            self.instruction_view.on_instruction_clicked()
        self.update_selected_instruction_details()
    
    def on_instruction_selected_virtual(self, logical_row: int):
        """on_instruction_selected_virtual function."""
        if not self.instruction_view or not self.instruction_view.allow_heavy_update:
            return
        
        self.selected_index = logical_row
        self.update_selected_instruction_details()
    
    def update_selected_instruction_details(self):
        """update_selected_instruction_details function."""
        if self.selected_index < 0 or not self.parser:
            return
        
        detail_start = time.time()
        
        instruction = self.parser.parse_instruction_at(self.selected_index)
        if not instruction:
            return
        
        self.status_label.setText(f"第 {self.selected_index + 1} 条指令 {instruction.address}")
        
        
        reg_start = time.time()
        self.update_register_display(self.selected_index)
        reg_time = (time.time() - reg_start) * 1000
        
        mem_start = time.time()
        self.update_memory_display(instruction)
        mem_time = (time.time() - mem_start) * 1000
        
        total_time = (time.time() - detail_start) * 1000
        if total_time > 100:
            print(f"[性能] 详情面板刷新耗时 {total_time:.1f}ms (寄存器 {reg_time:.1f}ms, 内存 {mem_time:.1f}ms)")
    
    def update_register_display(self, index: int):
        """update_register_display function."""
        if index < 0 or not self.register_calc:
            self.register_table.setRowCount(0)
            return
        
        instruction = self.parser.parse_instruction_at(index)
        if not instruction:
            return
        
        changed_registers = set()
        for change in instruction.register_changes:
            normalized = Register.normalize_name(change.register)
            changed_registers.add(normalized)
            if Register.is_w_register(change.register):
                changed_registers.add('W_' + normalized)
            else:
                changed_registers.add('X_' + normalized)
        
        all_registers = RegisterCalculator.get_all_arm64_registers()
        
        
        current_state = self.register_calc.compute_state_at(index, all_registers)
        prev_state = RegisterState()
        if index > 0:
            prev_state = self.register_calc.compute_state_at(index - 1, all_registers)
        
        
        sorted_registers = sorted(all_registers, key=RegisterCalculator.get_register_sort_key)
        
        
        self.register_table.setUpdatesEnabled(False)
        try:
            self.register_table.setRowCount(len(sorted_registers))
            
            for row, register in enumerate(sorted_registers):
                is_x_series = Register.is_x_register(register)
                
                current_reg = current_state.get_register(register)
                prev_reg = prev_state.get_register(register)
                
                x_value = current_reg.get_x_value()
                w_value = current_reg.get_w_value() if is_x_series else ''
                
                x_prev = prev_reg.get_x_value()
                w_prev = prev_reg.get_w_value() if is_x_series else ''
                
                x_changed = register in changed_registers and f'X_{register}' in changed_registers
                w_changed = register in changed_registers and f'W_{register}' in changed_registers
                
                reg_item = QTableWidgetItem(register)
                reg_item.setForeground(QColor(86, 156, 214))
                self.register_table.setItem(row, 0, reg_item)
                
                
                x_item = QTableWidgetItem(x_value)
                if x_changed:
                    x_item.setBackground(QColor(37, 99, 235))
                    x_item.setForeground(QColor(255, 255, 255))
                elif x_value != x_prev:
                    x_item.setForeground(QColor(255, 198, 109))
                else:
                    x_item.setForeground(QColor(206, 145, 120))
                self.register_table.setItem(row, 1, x_item)
                
                
                if is_x_series:
                    w_item = QTableWidgetItem(w_value)
                    if w_changed:
                        w_item.setBackground(QColor(37, 99, 235))
                        w_item.setForeground(QColor(255, 255, 255))
                    elif w_value != w_prev:
                        w_item.setForeground(QColor(255, 198, 109))
                    else:
                        w_item.setForeground(QColor(206, 145, 120))
                    self.register_table.setItem(row, 2, w_item)
                else:
                    empty_item = QTableWidgetItem('')
                    empty_item.setForeground(QColor(128, 128, 128))
                    self.register_table.setItem(row, 2, empty_item)
        finally:
            self.register_table.setUpdatesEnabled(True)
    
    @staticmethod
    def _string_to_hex_bytes(text: str) -> str:
        """_string_to_hex_bytes function."""
        data = text.encode("utf-8", errors="replace")
        return " ".join(f"{byte:02X}" for byte in data)

    def _extract_string_annotations(self, raw_line: str) -> List[Tuple[str, str, str, str]]:
        """_extract_string_annotations function."""
        hints: List[Tuple[str, str, str, str]] = []
        if not raw_line:
            return hints

        pattern = r'\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)\s*\(string:\s*"([^"]*)"\)'
        seen = set()
        for match in re.finditer(pattern, raw_line):
            reg = match.group(1).upper()
            val = match.group(2)
            text = match.group(3)
            hex_data = self._string_to_hex_bytes(text)
            key = (reg, val, text, hex_data)
            if key in seen:
                continue
            seen.add(key)
            hints.append(key)
        return hints

    @staticmethod
    def _normalize_data_token(token: str) -> str:
        value = (token or "").strip()
        if not value:
            return value
        if re.fullmatch(r"[0-9a-fA-F]+", value):
            return "0x" + value.lower()
        return value

    def _format_memory_value(self, raw_value: str) -> Tuple[str, str]:
        if not raw_value:
            return "?", ""

        text = raw_value.strip()
        assignments = list(re.finditer(r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)", text))
        if not assignments:
            return self._normalize_data_token(text), ""

        values = [self._normalize_data_token(match.group(2)) for match in assignments]
        value_text = values[0] if len(values) == 1 else ", ".join(values)
        return value_text, text

    def update_memory_display(self, instruction: Instruction):
        """update_memory_display function."""
        string_hints = self._extract_string_annotations(instruction.raw_line)

        if instruction.memory_dump:
            lines = []
            for dump_line in instruction.memory_dump:
                address = dump_line.address
                hex_data = " ".join(dump_line.data)
                ascii_str = "".join(
                    chr(int(byte, 16)) if 32 <= int(byte, 16) <= 126 else "."
                    for byte in dump_line.data
                )
                marker = "*" if dump_line.is_modified else " "
                lines.append(f"{marker} {address}  {hex_data:<48} |{ascii_str}|")
            if string_hints:
                lines.append("")
                lines.append("String annotations:")
                for reg, val, _text, hex_data in string_hints:
                    lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            return

        if instruction.memory_ops:
            lines = ["Memory operations (parsed/inferred):"]
            for i, op in enumerate(instruction.memory_ops, 1):
                rw = "R" if op.type == "read" else "W"
                value, detail = self._format_memory_value(op.data_value)
                line = f"{i:>2}. [{rw}] addr={op.address} size={op.data_size} value={value} instr={op.instruction_address}"
                if detail and detail != value:
                    line += f" ({detail})"
                lines.append(line)
            if string_hints:
                lines.append("")
                lines.append("String annotations:")
                for reg, val, _text, hex_data in string_hints:
                    lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            return

        if string_hints:
            lines = ["String annotations:"]
            for reg, val, _text, hex_data in string_hints:
                lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            return

        self.memory_display.setPlainText("No memory data for this instruction.")

    def on_register_double_click(self, row: int, column: int):
        """on_register_double_click function."""
        item = self.register_table.item(row, 0)
        if item:
            register = item.text()
            self.selected_register = register
            self.trace_register_source(register)

    def on_register_click(self):
        """on_register_click function."""
        selected_items = self.register_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            register_item = self.register_table.item(row, 0)
            if register_item:
                self.selected_register = register_item.text()
                self.status_label.setText(f"已选寄存器: {self.selected_register}（按 PgUp 可追踪来源）")

    def show_register_menu(self, position):
        """show_register_menu function."""
        item = self.register_table.itemAt(position)
        if not item:
            return

        row = item.row()
        register_item = self.register_table.item(row, 0)
        if not register_item:
            return

        register = register_item.text()
        menu = QMenu(self)
        trace_action = menu.addAction(f"追踪 {register} 来源")
        data_flow_action = menu.addAction(f"数据来源追踪 {register}")
        reverse_taint_action = menu.addAction(f"反向污点分析 {register}")

        action = menu.exec(self.register_table.mapToGlobal(position))
        if action == trace_action:
            self.trace_register_source(register)
        elif action == data_flow_action:
            self.analyze_data_provenance(register)
        elif action == reverse_taint_action:
            self.analyze_reverse_taint(register)

    def trace_register_source(self, register: str):
        """trace_register_source function."""
        if self.selected_index < 0 or not self.register_calc:
            self.status_label.setText("请先选择一条指令")
            return

        source_index = self.register_calc.trace_register_source(register, self.selected_index)

        if source_index is not None:
            self.jump_to_instruction(source_index, add_history=True)

            QTimer.singleShot(100, lambda: self.select_register_in_table(register))

            source_instr = self.parser.parse_instruction_at(source_index)
            if source_instr:
                self.status_label.setText(
                    f"追踪: {register} 在第 {source_index + 1} 条指令被修改 ({source_instr.address})（PgUp 继续 / PgDn 返回）"
                )
        else:
            self.status_label.setText(f"未找到寄存器 {register} 的来源")

    def _current_selected_register(self) -> Optional[str]:
        """_current_selected_register function."""
        if self.selected_register:
            return self.selected_register

        selected_items = self.register_table.selectedItems() if self.register_table else []
        if not selected_items:
            return None

        row = selected_items[0].row()
        reg_item = self.register_table.item(row, 0)
        return reg_item.text() if reg_item else None

    def _show_reverse_taint_dialog(self, register: str, chain: List[dict]):
        """_show_reverse_taint_dialog function."""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"反向污点分析: {register}")
        dialog.resize(1380, 760)
        layout = QVBoxLayout(dialog)

        summary = QLabel(
            f"目标寄存器: {register}，共回溯到 {len(chain)} 条指令，双击行可跳转。"
        )
        summary.setStyleSheet("color: #cccccc; padding: 4px 2px;")
        layout.addWidget(summary)

        table = QTableWidget(dialog)
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "步骤",
            "行号",
            "指令地址",
            "指令",
            "命中写寄存器",
            "读寄存器",
            "污点(前)",
            "污点(后)",
        ])
        table.setRowCount(len(chain))
        self._bind_table_copy_actions(table)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)

        for row, node in enumerate(chain):
            step = row + 1
            index = int(node["index"])

            step_item = SortableTableWidgetItem(str(step), step)
            line_item = SortableTableWidgetItem(str(index + 1), index + 1)
            line_item.setData(Qt.UserRole, index)
            addr = self._format_address_for_display(node["address"])
            addr_item = SortableTableWidgetItem(addr, self._address_sort_key(addr))
            inst_text = f'{node["mnemonic"]} {node["operands"]}'.strip()

            table.setItem(row, 0, step_item)
            table.setItem(row, 1, line_item)
            table.setItem(row, 2, addr_item)
            table.setItem(row, 3, QTableWidgetItem(inst_text))
            table.setItem(row, 4, QTableWidgetItem(", ".join(node["hit_writes"]) or "-"))
            table.setItem(row, 5, QTableWidgetItem(", ".join(node["read_regs"]) or "-"))
            table.setItem(row, 6, QTableWidgetItem(", ".join(node["taint_before"]) or "-"))
            table.setItem(row, 7, QTableWidgetItem(", ".join(node["taint_after"]) or "-"))

        def on_row_activated(row: int, _column: int):
            item = table.item(row, 1)
            if not item:
                return
            index = item.data(Qt.UserRole)
            if isinstance(index, int):
                self.jump_to_instruction(index, add_history=True)
                self.status_label.setText(f"反向污点跳转: 第 {index + 1} 条指令")
                dialog.accept()

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        dialog.exec()

    def analyze_reverse_taint(self, register: Optional[str] = None):
        """analyze_reverse_taint function."""
        if self.selected_index < 0 or not self.register_calc:
            self.status_label.setText("请先选择一条指令")
            return

        target_register = register or self._current_selected_register()
        if not target_register:
            self.status_label.setText("请先在寄存器表格中选中目标寄存器")
            return

        chain = self.register_calc.reverse_taint_trace(
            target_register,
            self.selected_index,
            max_steps=500,
        )
        if not chain:
            self.status_label.setText(f"反向污点分析无结果: {target_register}")
            return

        self.status_label.setText(
            f"反向污点分析完成: {target_register}，共 {len(chain)} 条指令"
        )
        self._show_reverse_taint_dialog(target_register, chain)

    @staticmethod
    def _data_event_kind_text(kind: str) -> str:
        if kind == "load":
            return "读取"
        if kind == "write":
            return "写入"
        if kind == "calc":
            return "计算"
        return kind or "-"

    def _show_data_provenance_dialog(self, register: str, trace_result: Dict):
        events = trace_result.get("events", [])

        dialog = QDialog(self)
        dialog.setWindowTitle(f"数据来源追踪: {register}")
        dialog.resize(1480, 780)
        layout = QVBoxLayout(dialog)

        summary = QLabel(
            f"目标寄存器: {register}，共 {len(events)} 条记录（读取 -> 写入 -> 计算链）。双击可跳转。"
        )
        summary.setStyleSheet("color: #cccccc; padding: 4px 2px;")
        layout.addWidget(summary)

        table = QTableWidget(dialog)
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "步骤",
            "类型",
            "行号",
            "指令地址",
            "指令",
            "内存地址",
            "数据(HEX)",
            "说明",
        ])
        table.setRowCount(len(events))
        self._bind_table_copy_actions(table)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)

        table.setSortingEnabled(False)
        for row, event in enumerate(events):
            step = row + 1
            index = int(event.get("index", -1))
            line_no = index + 1 if index >= 0 else 0
            addr = self._format_address_for_display(event.get("instruction_address", ""))

            table.setItem(row, 0, SortableTableWidgetItem(str(step), step))
            table.setItem(row, 1, QTableWidgetItem(self._data_event_kind_text(event.get("kind", ""))))
            line_item = SortableTableWidgetItem(str(line_no), line_no)
            line_item.setData(Qt.UserRole, index)
            table.setItem(row, 2, line_item)
            table.setItem(row, 3, SortableTableWidgetItem(addr, self._address_sort_key(addr)))
            table.setItem(row, 4, QTableWidgetItem(event.get("instruction_text", "")))
            table.setItem(row, 5, QTableWidgetItem(event.get("memory_address", "-")))
            table.setItem(row, 6, QTableWidgetItem(event.get("value_hex", "-")))
            table.setItem(row, 7, QTableWidgetItem(event.get("detail", "")))

        table.setSortingEnabled(True)
        table.sortItems(2, Qt.AscendingOrder)

        def on_row_activated(row: int, _column: int):
            item = table.item(row, 2)
            if not item:
                return
            index = item.data(Qt.UserRole)
            if isinstance(index, int) and index >= 0:
                self.jump_to_instruction(index, add_history=True)
                self.status_label.setText(f"数据来源追踪跳转: 第 {index + 1} 条指令")
                dialog.accept()

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        dialog.exec()

    def analyze_data_provenance(self, register: Optional[str] = None):
        """analyze_data_provenance function."""
        if self.selected_index < 0 or not self.register_calc:
            self.status_label.setText("请先选择一条指令")
            return

        target_register = register or self._current_selected_register()
        if not target_register:
            self.status_label.setText("请先在寄存器表格中选中目标寄存器")
            return

        trace_result = self.register_calc.trace_data_provenance(
            target_register,
            self.selected_index,
            max_scan=30000,
            max_calc_steps=160,
        )
        events = trace_result.get("events", [])
        message = trace_result.get("message", "")

        if not events:
            self.status_label.setText(f"数据来源追踪无结果: {target_register} ({message})")
            return

        self.status_label.setText(f"数据来源追踪完成: {target_register}，共 {len(events)} 条记录")
        self._show_data_provenance_dialog(target_register, trace_result)

    def select_register_in_table(self, register: str):
        """select_register_in_table function."""
        for row in range(self.register_table.rowCount()):
            item = self.register_table.item(row, 0)
            if item and item.text() == register:
                self.register_table.selectRow(row)
                self.register_table.scrollToItem(item)
                self.selected_register = register
                break

    @staticmethod
    def _normalize_address_text(value: str) -> str:
        text = (value or "").strip().lower()
        return text[2:] if text.startswith("0x") else text

    @staticmethod
    def _is_probable_address_query(search_text: str) -> bool:
        text = (search_text or "").strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        return len(text) >= 4 and bool(re.fullmatch(r"[0-9a-f]+", text))

    def _is_memory_address_match(self, instruction: Optional[Instruction], search_lower: str, search_addr: str) -> bool:
        if not instruction:
            return False

        def matches(candidate: str) -> bool:
            value = (candidate or "").strip().lower()
            if not value:
                return False
            if search_lower in value:
                return True
            if search_addr and search_addr in self._normalize_address_text(value):
                return True
            return False

        for op in instruction.memory_ops:
            if matches(op.address):
                return True

        for dump_line in instruction.memory_dump:
            if matches(dump_line.address):
                return True

        return False

    def _instruction_matches_search(
        self,
        index: int,
        search_lower: str,
        search_addr: str,
        enable_memory_addr_search: bool,
    ) -> bool:
        instr_info = self.parser.get_instruction_info(index)
        if instr_info and (
            search_lower in instr_info.address.lower() or search_lower in instr_info.offset.lower()
        ):
            return True

        if not enable_memory_addr_search:
            return False

        instruction = self.parser.parse_instruction_at(index)
        return self._is_memory_address_match(instruction, search_lower, search_addr)

    @staticmethod
    def _format_address_for_display(address: str) -> str:
        value = (address or "").strip().lower()
        if not value:
            return value
        return value if value.startswith("0x") else f"0x{value}"

    @staticmethod
    def _address_sort_key(address: str) -> int:
        normalized = MainWindow._normalize_address_text(address)
        if normalized and re.fullmatch(r"[0-9a-f]+", normalized):
            return int(normalized, 16)
        return (1 << 63) - 1

    def _collect_address_matches(self, search_text: str) -> list:
        query_norm = self._normalize_address_text(search_text)
        if not query_norm or not re.fullmatch(r"[0-9a-f]+", query_norm):
            return []

        matches: list = []
        for i in range(self.instruction_count):
            if i % 500 == 0:
                QApplication.processEvents()

            instruction = self.parser.parse_instruction_at(i)
            if not instruction:
                continue

            line_no = i + 1
            instr_addr = self._format_address_for_display(instruction.address)

            for op in instruction.memory_ops:
                if not self._normalize_address_text(op.address).startswith(query_norm):
                    continue

                value, detail = self._format_memory_value(op.data_value)
                data_text = value
                if detail and detail != value:
                    data_text = f"{value} ({detail})"

                matches.append({
                    "index": i,
                    "line": line_no,
                    "instruction_address": instr_addr,
                    "access": "R" if op.type == "read" else "W",
                    "memory_address": self._format_address_for_display(op.address),
                    "data": data_text,
                })

            for dump_line in instruction.memory_dump:
                if not self._normalize_address_text(dump_line.address).startswith(query_norm):
                    continue

                dump_hex = " ".join(dump_line.data)
                access_type = "D*" if dump_line.is_modified else "D"
                matches.append({
                    "index": i,
                    "line": line_no,
                    "instruction_address": instr_addr,
                    "access": access_type,
                    "memory_address": self._format_address_for_display(dump_line.address),
                    "data": dump_hex,
                })

        return sorted(
            matches,
            key=lambda item: (
                self._address_sort_key(item["memory_address"]),
                self._address_sort_key(item["instruction_address"]),
                int(item["line"]),
                item["access"],
            ),
        )

    @staticmethod
    def _selected_row_indices(table: QTableWidget) -> List[int]:
        selected = sorted({item.row() for item in table.selectedIndexes()})
        return selected

    def _copy_table_rows(self, table: QTableWidget, rows: Optional[List[int]] = None):
        if table.rowCount() == 0:
            return

        row_indices = rows if rows is not None else self._selected_row_indices(table)
        if not row_indices:
            row_indices = list(range(table.rowCount()))

        headers = []
        for c in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(c)
            headers.append(header_item.text() if header_item else f"col{c}")

        lines = ["\t".join(headers)]
        for r in row_indices:
            cells = []
            for c in range(table.columnCount()):
                item = table.item(r, c)
                cells.append(item.text() if item else "")
            lines.append("\t".join(cells))

        QApplication.clipboard().setText("\n".join(lines))

    def _bind_table_copy_actions(self, table: QTableWidget):
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setContextMenuPolicy(Qt.CustomContextMenu)

        QShortcut(QKeySequence("Ctrl+A"), table).activated.connect(table.selectAll)
        QShortcut(QKeySequence("Ctrl+C"), table).activated.connect(
            lambda: self._copy_table_rows(table)
        )

        def on_context_menu(pos):
            menu = QMenu(table)
            act_copy_selected = menu.addAction("复制选中")
            act_copy_all = menu.addAction("复制全部")
            act_select_all = menu.addAction("全选")
            chosen = menu.exec(table.viewport().mapToGlobal(pos))
            if chosen == act_copy_selected:
                self._copy_table_rows(table)
            elif chosen == act_copy_all:
                self._copy_table_rows(table, list(range(table.rowCount())))
            elif chosen == act_select_all:
                table.selectAll()

        table.customContextMenuRequested.connect(on_context_menu)

    def _show_address_matches_dialog(self, search_text: str, matches: list):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"地址全查: {search_text}")
        dialog.resize(1150, 680)
        layout = QVBoxLayout(dialog)

        summary = QLabel(
            f"共找到 {len(matches)} 条匹配，双击任意行可跳转到对应指令。"
        )
        summary.setStyleSheet("color: #cccccc; padding: 4px 2px;")
        layout.addWidget(summary)

        table = QTableWidget(dialog)
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["行号", "指令地址", "类型", "内存地址", "数据"])
        table.setRowCount(len(matches))
        self._bind_table_copy_actions(table)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        table.setSortingEnabled(False)
        for row, match in enumerate(matches):
            line_item = SortableTableWidgetItem(str(match["line"]), int(match["line"]))
            line_item.setData(Qt.UserRole, int(match["index"]))
            table.setItem(row, 0, line_item)
            table.setItem(
                row,
                1,
                SortableTableWidgetItem(
                    match["instruction_address"],
                    self._address_sort_key(match["instruction_address"]),
                ),
            )
            table.setItem(row, 2, QTableWidgetItem(match["access"]))
            table.setItem(
                row,
                3,
                SortableTableWidgetItem(
                    match["memory_address"],
                    self._address_sort_key(match["memory_address"]),
                ),
            )
            table.setItem(row, 4, QTableWidgetItem(match["data"]))
        table.setSortingEnabled(True)
        table.sortItems(3, Qt.AscendingOrder)

        def on_row_activated(row: int, _column: int):
            item = table.item(row, 0)
            if not item:
                return
            index = item.data(Qt.UserRole)
            if isinstance(index, int):
                self.jump_to_instruction(index, add_history=True)
                self.status_label.setText(
                    f"地址全查跳转: 第 {index + 1} 条指令"
                )
                dialog.accept()

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        dialog.exec()

    def search_all_addresses(self):
        search_text = self.search_input.text().strip()
        if not search_text or not self.parser:
            return

        if not self._is_probable_address_query(search_text):
            QMessageBox.information(
                self,
                "地址全查",
                "请输入十六进制地址或前缀，例如 0xbfffeb0。",
            )
            return

        self.status_label.setText(f"正在全量搜索地址: {search_text} ...")
        QApplication.processEvents()

        matches = self._collect_address_matches(search_text)
        if not matches:
            QMessageBox.information(self, "地址全查", f"未找到匹配地址: {search_text}")
            self.status_label.setText(f"地址全查无结果: {search_text}")
            return

        self.status_label.setText(f"地址全查完成: {len(matches)} 条匹配")
        self._show_address_matches_dialog(search_text, matches)

    @staticmethod
    def _normalize_mnemonic_query(search_text: str) -> str:
        return (search_text or "").strip().lower()

    @staticmethod
    def _is_probable_mnemonic_query(search_text: str) -> bool:
        query = (search_text or "").strip().lower()
        if not query:
            return False
        if query.endswith("*"):
            query = query[:-1]
        return bool(query) and bool(re.fullmatch(r"[a-z][a-z0-9.]*", query))

    def _build_instruction_memory_summary(self, instruction: Optional[Instruction]) -> Tuple[str, str]:
        if not instruction:
            return "-", "-"

        if instruction.memory_ops:
            addresses: List[str] = []
            data_items: List[str] = []
            for op in instruction.memory_ops[:3]:
                addresses.append(self._format_address_for_display(op.address))
                value, detail = self._format_memory_value(op.data_value)
                text = value if not detail or detail == value else f"{value} ({detail})"
                data_items.append(f"{'R' if op.type == 'read' else 'W'}:{text}")
            if len(instruction.memory_ops) > 3:
                addresses.append("...")
                data_items.append("...")
            return ", ".join(addresses), " | ".join(data_items)

        if instruction.memory_dump:
            addresses = [self._format_address_for_display(d.address) for d in instruction.memory_dump[:3]]
            if len(instruction.memory_dump) > 3:
                addresses.append("...")
            first_dump = instruction.memory_dump[0]
            dump_hex = " ".join(first_dump.data[:16])
            if len(first_dump.data) > 16:
                dump_hex += " ..."
            return ", ".join(addresses), dump_hex if dump_hex else "-"

        return "-", "-"

    def _collect_mnemonic_matches(self, mnemonic_query: str) -> List[dict]:
        query = self._normalize_mnemonic_query(mnemonic_query)
        prefix_mode = True
        if query.endswith("*"):
            query = query[:-1]
        if not query:
            return []

        matches: List[dict] = []
        for i in range(self.instruction_count):
            if i % 500 == 0:
                QApplication.processEvents()

            info = self.parser.get_instruction_info(i)
            if not info:
                continue
            mnemonic = (info.mnemonic or "").lower()
            if not mnemonic:
                continue
            if prefix_mode:
                if not mnemonic.startswith(query):
                    continue
            elif mnemonic != query:
                continue

            instruction = self.parser.parse_instruction_at(i)
            mem_addr, mem_data = self._build_instruction_memory_summary(instruction)
            matches.append({
                "index": i,
                "line": i + 1,
                "instruction_address": self._format_address_for_display(info.address),
                "mnemonic": info.mnemonic,
                "instruction_text": f"{info.mnemonic} {info.operands}".strip(),
                "memory_address": mem_addr,
                "data": mem_data,
            })
        return sorted(
            matches,
            key=lambda item: (
                self._address_sort_key(item["instruction_address"]),
                int(item["line"]),
                (item["mnemonic"] or "").lower(),
            ),
        )

    def _show_mnemonic_matches_dialog(self, query: str, matches: List[dict]):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"指令全查: {query}")
        dialog.resize(1320, 720)
        layout = QVBoxLayout(dialog)

        summary = QLabel(f"匹配助记符 `{query}`，共找到 {len(matches)} 条结果，双击可跳转。")
        summary.setStyleSheet("color: #cccccc; padding: 4px 2px;")
        layout.addWidget(summary)

        table = QTableWidget(dialog)
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["行号", "指令地址", "助记符", "指令", "内存地址", "数据"])
        table.setRowCount(len(matches))
        self._bind_table_copy_actions(table)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)

        table.setSortingEnabled(False)
        for row, match in enumerate(matches):
            line_item = SortableTableWidgetItem(str(match["line"]), int(match["line"]))
            line_item.setData(Qt.UserRole, int(match["index"]))
            table.setItem(row, 0, line_item)
            table.setItem(
                row,
                1,
                SortableTableWidgetItem(
                    match["instruction_address"],
                    self._address_sort_key(match["instruction_address"]),
                ),
            )
            table.setItem(row, 2, QTableWidgetItem(match["mnemonic"]))
            table.setItem(row, 3, QTableWidgetItem(match["instruction_text"]))
            table.setItem(row, 4, QTableWidgetItem(match["memory_address"]))
            table.setItem(row, 5, QTableWidgetItem(match["data"]))
        table.setSortingEnabled(True)
        table.sortItems(1, Qt.AscendingOrder)

        def on_row_activated(row: int, _column: int):
            item = table.item(row, 0)
            if not item:
                return
            index = item.data(Qt.UserRole)
            if isinstance(index, int):
                self.jump_to_instruction(index, add_history=True)
                self.status_label.setText(f"指令全查跳转: 第 {index + 1} 条指令")
                dialog.accept()

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        dialog.exec()

    def search_instructions_by_mnemonic(self):
        if not self.parser:
            return

        query = self._normalize_mnemonic_query(self.search_input.text())
        if not self._is_probable_mnemonic_query(query):
            QMessageBox.information(
                self,
                "指令全查",
                "请输入 ARM64 指令助记符，例如 ldr、str、add（支持前缀匹配）。",
            )
            return

        self.status_label.setText(f"正在全量搜索指令: {query} ...")
        QApplication.processEvents()

        matches = self._collect_mnemonic_matches(query)
        if not matches:
            QMessageBox.information(self, "指令全查", f"未找到匹配助记符: {query}")
            self.status_label.setText(f"指令全查无结果: {query}")
            return

        self.status_label.setText(f"指令全查完成: {len(matches)} 条匹配")
        self._show_mnemonic_matches_dialog(query, matches)

    def search_instruction(self):
        """search_instruction function."""
        search_text = self.search_input.text().strip()
        if not search_text or not self.parser:
            return

        found_index = -1

        if search_text.isdigit():
            line_num = int(search_text)
            if 1 <= line_num <= self.instruction_count:
                found_index = line_num - 1
            else:
                QMessageBox.information(self, "搜索结果", f"行号超出范围: 1-{self.instruction_count}")
                return
        else:
            if self._is_probable_mnemonic_query(search_text) and not self._is_probable_address_query(search_text):
                self.search_instructions_by_mnemonic()
                return

            search_lower = search_text.lower()
            search_addr = self._normalize_address_text(search_text)
            enable_memory_addr_search = self._is_probable_address_query(search_text)
            start_index = self.selected_index + 1 if self.selected_index >= 0 else 0

            for i in range(start_index, self.instruction_count):
                if self._instruction_matches_search(
                    i, search_lower, search_addr, enable_memory_addr_search
                ):
                    found_index = i
                    break

            if found_index == -1:
                for i in range(0, start_index):
                    if self._instruction_matches_search(
                        i, search_lower, search_addr, enable_memory_addr_search
                    ):
                        found_index = i
                        break

        if found_index != -1:
            self.jump_to_instruction(found_index, add_history=True)
            self.status_label.setText(f"已定位到第 {found_index + 1} 条指令")
        else:
            QMessageBox.information(self, "搜索结果", f"未找到匹配项: {search_text}")

    def setup_shortcuts(self):
        """setup_shortcuts function."""
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(lambda: self.search_input.setFocus())
        QShortcut(QKeySequence("F3"), self).activated.connect(self.search_instruction)
        QShortcut(QKeySequence("Ctrl+Shift+F"), self).activated.connect(self.search_all_addresses)
        QShortcut(QKeySequence("Ctrl+Shift+M"), self).activated.connect(self.search_instructions_by_mnemonic)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self.quick_data_provenance)
        QShortcut(QKeySequence("Ctrl+Shift+T"), self).activated.connect(self.quick_reverse_taint)
        QShortcut(QKeySequence("Ctrl+O"), self).activated.connect(self.load_file)
        QShortcut(QKeySequence("Up"), self).activated.connect(lambda: self.navigate_instruction(-1))
        QShortcut(QKeySequence("Down"), self).activated.connect(lambda: self.navigate_instruction(1))
        QShortcut(QKeySequence("PgUp"), self).activated.connect(self.quick_trace_register)
        QShortcut(QKeySequence("PgDown"), self).activated.connect(self.navigate_history_back)

    def navigate_instruction(self, delta: int):
        """navigate_instruction function."""
        if not self.parser or not self.virtual_table:
            return

        if self.instruction_view:
            self.instruction_view.allow_heavy_update = True
            self.instruction_view.is_scrolling = False

        current = self.virtual_table.get_selected_logical_row()
        if current < 0:
            new_row = 0
        else:
            new_row = max(0, min(self.instruction_count - 1, current + delta))

        if new_row != current:
            self.virtual_table.select_logical_row(new_row)
            self.selected_index = new_row
            self.update_selected_instruction_details()

    def add_to_history(self, index: int):
        """add_to_history function."""
        if self.history and self.history_index < len(self.history) - 1:
            self.history = self.history[: self.history_index + 1]

        if not self.history or self.history[-1] != index:
            self.history.append(index)
            if len(self.history) > self.max_history:
                self.history.pop(0)
            else:
                self.history_index = len(self.history) - 1
        else:
            self.history_index = len(self.history) - 1

    def quick_trace_register(self):
        """quick_trace_register function."""
        if not self.parser:
            return

        if self.selected_register:
            self.trace_register_source(self.selected_register)
        else:
            self.status_label.setText("提示: 请先选中寄存器，再按 PgUp 追踪来源")

    def quick_data_provenance(self):
        """quick_data_provenance function."""
        if not self.parser:
            return
        self.analyze_data_provenance()

    def quick_reverse_taint(self):
        """quick_reverse_taint function."""
        if not self.parser:
            return
        self.analyze_reverse_taint()

    def navigate_history_back(self):
        """navigate_history_back function."""
        if not self.parser or not self.history:
            self.status_label.setText("没有历史记录")
            return

        if self.history_index > 0:
            self.history_index -= 1
            target_index = self.history[self.history_index]
            self.jump_to_instruction(target_index, add_history=False)

            if self.selected_register:
                QTimer.singleShot(100, lambda: self.select_register_in_table(self.selected_register))

            self.status_label.setText(
                f"后退到第 {target_index + 1} 行 ({self.history_index + 1}/{len(self.history)})"
            )
        else:
            self.status_label.setText("已经是最早的历史记录")

    def jump_to_instruction(self, index: int, add_history: bool = True):
        """jump_to_instruction function."""
        if index < 0 or index >= self.instruction_count or not self.virtual_table:
            return

        if add_history:
            if self.selected_index >= 0:
                if not self.history:
                    self.add_to_history(self.selected_index)
                elif self.history_index >= 0 and self.history[self.history_index] != self.selected_index:
                    self.add_to_history(self.selected_index)
            self.add_to_history(index)

        if self.instruction_view:
            self.instruction_view.allow_heavy_update = True
            self.instruction_view.is_scrolling = False

        self.virtual_table.select_logical_row(index)
        self.selected_index = index
        self.update_selected_instruction_details()

    def closeEvent(self, event):
        """closeEvent function."""
        if self.cache_worker:
            self.cache_worker.stop()
        if self.virtual_table:
            self.virtual_table.clear()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setStyleSheet(get_dark_stylesheet())
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    #python -m venv venv
    main()






