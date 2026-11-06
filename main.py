"""main module."""
import os
import sys
import time
import re
import threading
import json
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Callable, Any

PROJECT_ROOT = Path(__file__).resolve().parent
CONFLICTING_PYTHON_PATH_MARKERS = (
    "vector35\\binaryninja\\python",
    "vector35\\binaryninja\\python3",
)


def _strip_conflicting_python_paths():
    """Remove injected third-party Python paths that break PySide6 loading."""
    cleaned = []
    for entry in sys.path:
        normalized = str(entry).replace("/", "\\").lower()
        if any(marker in normalized for marker in CONFLICTING_PYTHON_PATH_MARKERS):
            continue
        cleaned.append(entry)
    sys.path[:] = cleaned


def _bootstrap_project_python():
    """Re-exec with the project's virtualenv when available."""
    _strip_conflicting_python_paths()

    if __name__ != "__main__":
        return

    if os.environ.get("TRACE_ANALYZER_SKIP_VENV_BOOTSTRAP") == "1":
        return

    if os.name == "nt":
        venv_python = PROJECT_ROOT / "venv" / "Scripts" / "python.exe"
    else:
        venv_python = PROJECT_ROOT / "venv" / "bin" / "python3"
        if not venv_python.exists():
            venv_python = PROJECT_ROOT / "venv" / "bin" / "python"

    if not venv_python.exists():
        return

    current_python = Path(sys.executable).resolve() if sys.executable else None
    target_python = venv_python.resolve()
    if current_python == target_python:
        return

    os.environ.pop("PYTHONPATH", None)
    os.environ.pop("PYTHONHOME", None)
    os.execv(
        str(target_python),
        [str(target_python), str(PROJECT_ROOT / "main.py"), *sys.argv[1:]],
    )


_bootstrap_project_python()

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QMessageBox, QMenu, QTableWidgetItem,
    QAbstractItemView, QFrame, QLabel, QDialog, QTableWidget, QHeaderView, QTableView,
    QPushButton
)
from PySide6.QtCore import Qt, Signal, QThread, QTimer, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QEvent
from PySide6.QtGui import QColor, QKeySequence, QShortcut, QTextCursor

from parser import Instruction
from lazy_parser import LazyLogParser
from register import Register, RegisterState
from cache_worker import CacheWorker
from register_calc import RegisterCalculator
from instruction_view import VirtualScrollTable, InstructionViewController
from ui_components import UIFactory, get_dark_stylesheet, get_theme_stylesheet


class ParseThread(QThread):
    """ParseThread class."""
    finished = Signal(object, object)
    error = Signal(str)
    progress = Signal(object, object)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    @staticmethod
    def _estimate_checkpoint_interval(file_size: int) -> int:
        """Use wider checkpoint spacing for multi-GB traces."""
        gib = 1024 * 1024 * 1024
        if file_size >= 16 * gib:
            return 20000
        if file_size >= 8 * gib:
            return 10000
        if file_size >= 2 * gib:
            return 5000
        if file_size >= 512 * 1024 * 1024:
            return 2000
        return 500

    def _emit_progress(self, current: int, total: int):
        self.progress.emit(current, total)
    
    def run(self):
        try:
            parser = LazyLogParser(self.file_path)
            file_size = Path(self.file_path).stat().st_size
            checkpoint_interval = self._estimate_checkpoint_interval(file_size)
            _, initial_sp = parser.build_index(
                progress_callback=self._emit_progress,
                checkpoint_interval=checkpoint_interval,
            )
            self.finished.emit(parser, initial_sp)
        except Exception as e:
            self.error.emit(str(e))


class SearchThread(QThread):
    """Background search worker for large traces."""

    finished = Signal(str, object)
    error = Signal(str)
    progress = Signal(object, object, str)

    MODE_FIND_FIRST = "find_first"
    MODE_ADDRESS_ALL = "address_all"
    MODE_OFFSET_ALL = "offset_all"
    MODE_MNEMONIC_ALL = "mnemonic_all"
    MODE_DATA_ALL = "data_all"
    MODE_STRING_ALL = "string_all"
    MAX_RESULTS = None

    def __init__(self, parser: LazyLogParser, mode: str, query: str, start_index: int = 0):
        super().__init__()
        self.parser = parser
        self.mode = mode
        self.query = query
        self.start_index = max(0, start_index)
        self._cancelled = False
        self._last_cooperative_yield = time.perf_counter()

    def cancel(self):
        self._cancelled = True

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

    @staticmethod
    def _is_probable_exact_instruction_address(search_text: str) -> bool:
        text = (search_text or "").strip().lower()
        if not text.startswith("0x"):
            return False
        body = text[2:]
        return len(body) >= 8 and bool(re.fullmatch(r"[0-9a-f]+", body))

    @staticmethod
    def _is_probable_offset_query(search_text: str) -> bool:
        text = (search_text or "").strip().lower()
        if not text.startswith("0x"):
            return False
        body = text[2:]
        return 0 < len(body) < 8 and bool(re.fullmatch(r"[0-9a-f]+", body))

    @staticmethod
    def _normalize_data_query(search_text: str) -> str:
        text = (search_text or "").strip().lower()
        if not text:
            return ""
        if re.fullmatch(r"[0-9a-f]+", text):
            return f"0x{text}"
        return text

    @staticmethod
    def _normalize_string_query(search_text: str) -> str:
        text = (search_text or "").strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
            text = text[1:-1]
        return text.strip()

    @staticmethod
    def _string_to_hex_bytes(text: str) -> str:
        data = (text or "").encode("utf-8", errors="replace")
        return " ".join(f"{byte:02X}" for byte in data)

    @staticmethod
    def _extract_string_annotations_from_text(raw_line: str) -> List[Tuple[str, str, str, str]]:
        if not raw_line:
            return []

        pattern = r'\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)\s*\(string:\s*"([^"]*)"\)'
        hints: List[Tuple[str, str, str, str]] = []
        seen = set()
        for match in re.finditer(pattern, raw_line):
            reg = match.group(1).upper()
            value = match.group(2)
            string_value = match.group(3)
            hex_bytes = SearchThread._string_to_hex_bytes(string_value)
            key = (reg, value, string_value, hex_bytes)
            if key in seen:
                continue
            seen.add(key)
            hints.append(key)
        return hints

    @classmethod
    def _data_query_tokens(cls, search_text: str) -> List[str]:
        normalized = cls._normalize_data_query(search_text)
        if not normalized:
            return []

        tokens: List[str] = [normalized]
        if normalized.startswith("0x") and re.fullmatch(r"0x[0-9a-f]+", normalized):
            body = normalized[2:]
            if len(body) % 2 == 0 and body:
                byte_groups = [body[i:i + 2] for i in range(0, len(body), 2)]
                tokens.append(" ".join(byte_groups))
            elif body:
                tokens.append(body)

        seen = set()
        ordered: List[str] = []
        for token in tokens:
            key = token.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            ordered.append(key)
        return ordered

    @classmethod
    def _data_match_scope(
        cls,
        search_text: str,
        info,
        instruction: Optional[Instruction],
    ) -> str:
        tokens = cls._data_query_tokens(search_text)
        if not tokens:
            return ""

        compact_tokens = [token for token in tokens if " " not in token]
        spaced_tokens = [token for token in tokens if " " in token]

        scopes: List[str] = []

        comment_text = (getattr(info, "comment", "") or "").lower()
        if any(token in comment_text for token in compact_tokens):
            scopes.append("寄存器/注释")

        operands_text = (getattr(info, "operands", "") or "").lower()
        if any(token in operands_text for token in compact_tokens):
            scopes.append("操作数")

        if instruction:
            for op in instruction.memory_ops:
                data_text = (op.data_value or "").lower()
                if any(token in data_text for token in compact_tokens):
                    scopes.append("内存数据")
                    break

            if instruction.memory_dump:
                for dump_line in instruction.memory_dump:
                    spaced = " ".join(dump_line.data).lower()
                    compact = "".join(dump_line.data).lower()
                    if any(token in spaced for token in spaced_tokens) or any(
                        token in compact for token in compact_tokens if not token.startswith("0x")
                    ):
                        scopes.append("内存Dump")
                        break

            raw_line = (instruction.raw_line or "").lower()
            if not scopes and any(token in raw_line for token in tokens):
                scopes.append("原始行")

        return " / ".join(scopes)

    @staticmethod
    def _format_address_for_display(address: str) -> str:
        value = (address or "").strip().lower()
        if not value:
            return value
        return value if value.startswith("0x") else f"0x{value}"

    @staticmethod
    def _address_sort_key(address: str) -> int:
        normalized = SearchThread._normalize_address_text(address)
        if normalized and re.fullmatch(r"[0-9a-f]+", normalized):
            return int(normalized, 16)
        return (1 << 63) - 1

    @staticmethod
    def _format_memory_value(raw_value: str) -> Tuple[str, str]:
        if not raw_value:
            return "?", ""

        text = raw_value.strip()
        assignments = list(re.finditer(r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)", text))
        if not assignments:
            token = text
            if token.startswith("0x") or token.startswith("0X"):
                token = token.lower()
            return token, ""

        values = []
        for match in assignments:
            token = match.group(2).strip()
            if token.startswith("0x") or token.startswith("0X"):
                token = token.lower()
            values.append(token)
        value_text = values[0] if len(values) == 1 else ", ".join(values)
        return value_text, text

    @staticmethod
    def _is_memory_address_match(
        instruction: Optional[Instruction],
        search_lower: str,
        search_addr: str,
    ) -> bool:
        if not instruction:
            return False

        def matches(candidate: str) -> bool:
            value = (candidate or "").strip().lower()
            if not value:
                return False
            if search_lower in value:
                return True
            if search_addr and search_addr in SearchThread._normalize_address_text(value):
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
        info = self.parser.get_instruction_info(index)
        if info and (
            search_lower in info.address.lower() or search_lower in info.offset.lower()
        ):
            return True

        if not enable_memory_addr_search:
            return False

        instruction = self.parser.parse_instruction_at(index)
        return self._is_memory_address_match(instruction, search_lower, search_addr)

    @staticmethod
    def _build_instruction_memory_summary(
        instruction: Optional[Instruction],
        fallback_text: str = "",
    ) -> Tuple[str, str]:
        if not instruction:
            detail_text = (fallback_text or "").strip()
            return "-", detail_text if detail_text else "-"

        if instruction.memory_ops:
            addresses: List[str] = []
            data_items: List[str] = []
            for op in instruction.memory_ops[:3]:
                addresses.append(SearchThread._format_address_for_display(op.address))
                value, detail = SearchThread._format_memory_value(op.data_value)
                text = value if not detail or detail == value else f"{value} ({detail})"
                data_items.append(f"{'R' if op.type == 'read' else 'W'}:{text}")
            if len(instruction.memory_ops) > 3:
                addresses.append("...")
                data_items.append("...")
            return ", ".join(addresses), " | ".join(data_items)

        if instruction.memory_dump:
            addresses = [
                SearchThread._format_address_for_display(d.address)
                for d in instruction.memory_dump[:3]
            ]
            if len(instruction.memory_dump) > 3:
                addresses.append("...")
            first_dump = instruction.memory_dump[0]
            dump_hex = " ".join(first_dump.data[:16])
            if len(first_dump.data) > 16:
                dump_hex += " ..."
            return ", ".join(addresses), dump_hex if dump_hex else "-"

        detail_text = (fallback_text or "").strip()
        return "-", detail_text if detail_text else "-"

    def _emit_progress(self, current: int, total: int, text: str):
        self.progress.emit(current, total, text)

    def _progress_due(self, index: int, step: int = 50000) -> bool:
        return index == 0 or index % step == 0

    @staticmethod
    def _progress_step(total: int, minimum: int = 1000, maximum: int = 20000) -> int:
        """Choose a reasonable refresh cadence for progress updates."""
        if total <= 0:
            return minimum
        return max(minimum, min(maximum, total // 100))

    def _cooperative_yield(self, iteration: int = 0, every: int = 2048, min_interval: float = 0.015):
        """Periodically yield the GIL so the UI thread can stay responsive during heavy scans."""
        if iteration > 0 and every > 0 and iteration % every != 0:
            return
        now = time.perf_counter()
        if now - self._last_cooperative_yield < min_interval:
            return
        time.sleep(0)
        self._last_cooperative_yield = time.perf_counter()

    def _find_first_match(self) -> Dict:
        total = self.parser.get_instruction_count()
        search_lower = self.query.lower()
        search_addr = self._normalize_address_text(self.query)
        enable_memory_addr_search = self._is_probable_address_query(self.query)

        if self._is_probable_exact_instruction_address(self.query):
            self._emit_progress(0, 1, f"正在定位地址: {self.query}")
            direct_index = self.parser.find_next_instruction_index_by_address(
                self.query,
                self.start_index,
            )
            if direct_index >= 0:
                self._emit_progress(1, 1, f"地址定位完成: {self.query}")
                return {"query": self.query, "found_index": direct_index, "cancelled": False}

        if search_lower.startswith("0x") and hasattr(self.parser, "find_next_instruction_index_by_offset"):
            self._emit_progress(0, 1, f"正在定位偏移: {self.query}")
            direct_offset_index = self.parser.find_next_instruction_index_by_offset(
                self.query,
                self.start_index,
            )
            if direct_offset_index >= 0:
                self._emit_progress(1, 1, f"偏移定位完成: {self.query}")
                return {
                    "query": self.query,
                    "found_index": direct_offset_index,
                    "cancelled": False,
                }

        if enable_memory_addr_search and hasattr(self.parser, "find_next_instruction_index_by_memory_address"):
            self._emit_progress(0, 1, f"正在定位内存地址: {self.query}")
            direct_memory_index = self.parser.find_next_instruction_index_by_memory_address(
                self.query,
                self.start_index,
            )
            if direct_memory_index >= 0:
                self._emit_progress(1, 1, f"内存地址定位完成: {self.query}")
                return {
                    "query": self.query,
                    "found_index": direct_memory_index,
                    "cancelled": False,
                }

            if search_lower.startswith("0x"):
                self._emit_progress(1, 1, f"搜索完成: {self.query}")
                return {
                    "query": self.query,
                    "found_index": -1,
                    "cancelled": False,
                    "hint": (
                        "未在完整指令地址、模块偏移或索引化的内存地址中找到匹配。"
                        "短十六进制查询不再回扫整份文件；如需内存地址列表请使用“地址全查”，"
                        "如需模块偏移请继续使用当前“查找”，如需指令地址请输入更完整的 0x 地址。"
                    ),
                }

        ranges = [
            (self.start_index, total),
            (0, min(self.start_index, total)),
        ]

        scanned = 0
        for range_start, range_end in ranges:
            for i in range(range_start, range_end):
                if self._cancelled:
                    return {"query": self.query, "found_index": -1, "cancelled": True}
                self._cooperative_yield(scanned)
                if self._progress_due(scanned):
                    self._emit_progress(scanned, total, f"正在搜索: {self.query}")
                if self._instruction_matches_search(
                    i,
                    search_lower,
                    search_addr,
                    enable_memory_addr_search,
                ):
                    self._emit_progress(total, total, f"搜索完成: {self.query}")
                    return {"query": self.query, "found_index": i, "cancelled": False}
                scanned += 1

        self._emit_progress(total, total, f"搜索完成: {self.query}")
        return {"query": self.query, "found_index": -1, "cancelled": False}

    def _collect_address_matches(self) -> Dict:
        total = self.parser.get_instruction_count()
        query_norm = self._normalize_address_text(self.query)
        if not query_norm or not re.fullmatch(r"[0-9a-f]+", query_norm):
            return {"query": self.query, "matches": [], "cancelled": False, "truncated": False}

        if hasattr(self.parser, "iter_memory_records_for_address_prefix"):
            candidate_total = total
            if hasattr(self.parser, "estimate_memory_record_candidates"):
                candidate_total = max(
                    1,
                    int(self.parser.estimate_memory_record_candidates(self.query)),
                )
            progress_step = self._progress_step(candidate_total)
            self._emit_progress(0, candidate_total, f"正在全量搜索地址: {self.query}")

            truncated = False
            processed = 0
            match_count = 0
            kind_read = int(getattr(self.parser, "MEMORY_KIND_READ", 0))
            kind_write = int(getattr(self.parser, "MEMORY_KIND_WRITE", 1))
            kind_dump = int(getattr(self.parser, "MEMORY_KIND_DUMP", 2))
            kind_dump_modified = int(getattr(self.parser, "MEMORY_KIND_DUMP_MODIFIED", 3))

            for instruction_index, _address_value, _data_size, kind, slot in (
                self.parser.iter_memory_records_for_address_prefix(
                    self.query,
                    limit=self.MAX_RESULTS,
                )
            ):
                if self._cancelled:
                    return {
                        "query": self.query,
                        "count": match_count,
                        "cancelled": True,
                        "truncated": truncated,
                        "lazy": True,
                    }
                self._cooperative_yield(processed)
                if processed > 0 and self._progress_due(processed, step=progress_step):
                    self._emit_progress(processed, candidate_total, f"正在全量搜索地址: {self.query}")

                instruction = self.parser.parse_instruction_at(instruction_index)
                if not instruction:
                    processed += 1
                    continue

                line_no = instruction_index + 1
                instr_addr = self._format_address_for_display(instruction.address)

                if kind in (kind_read, kind_write):
                    if slot >= len(instruction.memory_ops):
                        processed += 1
                        continue
                    op = instruction.memory_ops[slot]
                    if not self._normalize_address_text(op.address).startswith(query_norm):
                        processed += 1
                        continue
                    match_count += 1
                elif kind in (kind_dump, kind_dump_modified):
                    if slot >= len(instruction.memory_dump):
                        processed += 1
                        continue
                    dump_line = instruction.memory_dump[slot]
                    if not self._normalize_address_text(dump_line.address).startswith(query_norm):
                        processed += 1
                        continue
                    match_count += 1

                processed += 1
                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            self._emit_progress(candidate_total, candidate_total, f"地址搜索完成: {self.query}")
            return {
                "query": self.query,
                "count": match_count,
                "cancelled": False,
                "truncated": truncated,
                "lazy": True,
            }

        truncated = False
        match_count = 0
        progress_step = self._progress_step(total)
        self._emit_progress(0, total, f"正在全量搜索地址: {self.query}")
        for i in range(total):
            if self._cancelled:
                return {"query": self.query, "count": match_count, "cancelled": True, "truncated": truncated, "lazy": True}
            self._cooperative_yield(i)
            if i > 0 and self._progress_due(i, step=progress_step):
                self._emit_progress(i, total, f"正在全量搜索地址: {self.query}")

            instruction = self.parser.parse_instruction_at(i)
            if not instruction:
                continue

            line_no = i + 1
            instr_addr = self._format_address_for_display(instruction.address)

            for op in instruction.memory_ops:
                if not self._normalize_address_text(op.address).startswith(query_norm):
                    continue
                match_count += 1
                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            if truncated:
                break

            for dump_line in instruction.memory_dump:
                if not self._normalize_address_text(dump_line.address).startswith(query_norm):
                    continue
                match_count += 1
                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            if truncated:
                break

        self._emit_progress(total, total, f"地址搜索完成: {self.query}")
        return {
            "query": self.query,
            "count": match_count,
            "cancelled": False,
            "truncated": truncated,
            "lazy": True,
        }

    def _collect_offset_matches(self) -> Dict:
        query_norm = self._format_address_for_display(self.query)
        truncated = False
        match_count = 0
        known_total = 0
        if hasattr(self.parser, "count_instruction_indices_for_offset"):
            try:
                known_total = max(0, int(self.parser.count_instruction_indices_for_offset(self.query)))
            except Exception:
                known_total = 0

        if hasattr(self.parser, "iter_instruction_indices_by_offset"):
            progress_total = known_total if known_total > 0 else 0
            progress_step = self._progress_step(progress_total, minimum=500, maximum=5000)
            self._emit_progress(0, progress_total, f"正在全量搜索偏移: {query_norm}")
            for processed, instruction_index in enumerate(
                self.parser.iter_instruction_indices_by_offset(self.query),
                start=1,
            ):
                if self._cancelled:
                    return {
                        "query": query_norm,
                        "count": match_count,
                        "cancelled": True,
                        "truncated": truncated,
                        "lazy": True,
                    }
                self._cooperative_yield(processed, every=512)
                if progress_total > 0:
                    if self._progress_due(processed, step=progress_step):
                        self._emit_progress(
                            processed,
                            progress_total,
                            f"正在全量搜索偏移: {query_norm} (已找到 {match_count} 条)",
                        )
                elif processed == 1 or processed % 5000 == 0:
                    self._emit_progress(
                        0,
                        0,
                        f"正在全量搜索偏移: {query_norm} (已找到 {match_count} 条)",
                    )

                info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
                if not info:
                    continue

                match_count += 1
                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            self._emit_progress(
                max(1, match_count),
                max(1, match_count),
                f"偏移搜索完成: {query_norm}",
            )
            return {
                "query": query_norm,
                "count": match_count,
                "cancelled": False,
                "truncated": truncated,
                "lazy": True,
            }

        total = self.parser.get_instruction_count()
        progress_step = self._progress_step(total)
        self._emit_progress(0, total, f"正在全量搜索偏移: {query_norm}")
        for i in range(total):
            if self._cancelled:
                return {
                    "query": query_norm,
                    "count": match_count,
                    "cancelled": True,
                    "truncated": truncated,
                    "lazy": True,
                }
            self._cooperative_yield(i)
            if self._progress_due(i, step=progress_step):
                self._emit_progress(i, total, f"正在全量搜索偏移: {query_norm}")

            info = self.parser.get_instruction_info(i)
            if not info or (info.offset or "").lower() != query_norm.lower():
                continue

            full_info = self.parser.get_instruction_info(i, include_line_text=True)
            if not full_info:
                continue

            match_count += 1
            if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                truncated = True
                break

        self._emit_progress(total, total, f"偏移搜索完成: {query_norm}")
        return {
            "query": query_norm,
            "count": match_count,
            "cancelled": False,
            "truncated": truncated,
            "lazy": True,
        }

    def _collect_mnemonic_matches(self) -> Dict:
        query = (self.query or "").strip().lower()
        if query.endswith("*"):
            query = query[:-1]
        if not query:
            return {
                "query": self.query,
                "matches": [],
                "count": 0,
                "cancelled": False,
                "truncated": False,
                "lazy": True,
            }

        self._emit_progress(0, 1, f"正在统计指令搜索结果: {self.query}")
        count = 0
        if hasattr(self.parser, "count_instruction_indices_for_mnemonic_prefix"):
            count = int(self.parser.count_instruction_indices_for_mnemonic_prefix(query))
        elif hasattr(self.parser, "iter_instruction_indices_for_mnemonic_prefix"):
            for count, _instruction_index in enumerate(
                self.parser.iter_instruction_indices_for_mnemonic_prefix(query),
                start=1,
            ):
                if self._cancelled:
                    return {
                        "query": self.query,
                        "matches": [],
                        "count": 0,
                        "cancelled": True,
                        "truncated": False,
                        "lazy": True,
                    }

        self._emit_progress(1, 1, f"指令搜索完成: {self.query}")
        return {
            "query": self.query,
            "matches": [],
            "count": count,
            "cancelled": False,
            "truncated": False,
            "lazy": True,
        }

    def _collect_data_matches(self) -> Dict:
        query_norm = self._normalize_data_query(self.query)
        if not query_norm:
            return {"query": self.query, "matches": [], "cancelled": False, "truncated": False}

        truncated = False
        match_count = 0
        tokens = self._data_query_tokens(self.query)

        if hasattr(self.parser, "iter_instruction_indices_by_text_tokens"):
            def progress(current: int, total: int):
                self._emit_progress(current, total, f"正在全量搜索数据: {query_norm}")

            self._emit_progress(0, max(1, getattr(self.parser, "file_size", 0)), f"正在全量搜索数据: {query_norm}")
            processed = 0
            for instruction_index in self.parser.iter_instruction_indices_by_text_tokens(
                tokens,
                limit=self.MAX_RESULTS,
                progress_callback=progress,
                yield_callback=self._cooperative_yield,
            ):
                if self._cancelled:
                    return {
                        "query": query_norm,
                        "count": match_count,
                        "cancelled": True,
                        "truncated": truncated,
                        "lazy": True,
                    }
                self._cooperative_yield(processed, every=512)

                full_info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
                if not full_info:
                    processed += 1
                    continue

                instruction = self.parser.parse_instruction_at(instruction_index)
                match_scope = self._data_match_scope(self.query, full_info, instruction)
                if not match_scope:
                    processed += 1
                    continue

                match_count += 1
                processed += 1

                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            self._emit_progress(max(1, match_count), max(1, match_count), f"数据搜索完成: {query_norm}")
            return {
                "query": query_norm,
                "count": match_count,
                "cancelled": False,
                "truncated": truncated,
                "lazy": True,
            }

        total = self.parser.get_instruction_count()
        for i in range(total):
            if self._cancelled:
                return {
                    "query": query_norm,
                    "count": match_count,
                    "cancelled": True,
                    "truncated": truncated,
                    "lazy": True,
                }
            if self._progress_due(i):
                self._emit_progress(i, total, f"正在全量搜索数据: {query_norm}")

            full_info = self.parser.get_instruction_info(i, include_line_text=True)
            if not full_info:
                continue

            instruction = self.parser.parse_instruction_at(i)
            match_scope = self._data_match_scope(self.query, full_info, instruction)
            if not match_scope:
                continue

            match_count += 1
            if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                truncated = True
                break

        self._emit_progress(total, total, f"数据搜索完成: {query_norm}")
        return {
            "query": query_norm,
            "count": match_count,
            "cancelled": False,
            "truncated": truncated,
            "lazy": True,
        }

    def _collect_string_matches(self) -> Dict:
        query = self._normalize_string_query(self.query)
        if not query:
            return {"query": self.query, "matches": [], "cancelled": False, "truncated": False}

        query_lower = query.lower()
        truncated = False
        match_count = 0

        if hasattr(self.parser, "iter_string_annotation_matches"):
            total_records = 0
            if hasattr(self.parser, "get_string_annotation_count"):
                try:
                    total_records = max(0, int(self.parser.get_string_annotation_count()))
                except Exception:
                    total_records = 0
            progress_step = self._progress_step(total_records, minimum=500, maximum=5000)
            self._emit_progress(0, total_records, f"正在读取字符串缓存: {query}")
            processed = 0
            for record in self.parser.iter_string_annotation_matches(query, limit=self.MAX_RESULTS):
                if self._cancelled:
                    return {
                        "query": query,
                        "count": match_count,
                        "cancelled": True,
                        "truncated": truncated,
                        "lazy": True,
                    }
                if total_records > 0:
                    if processed > 0 and self._progress_due(processed, step=progress_step):
                        self._emit_progress(
                            min(processed, total_records),
                            total_records,
                            f"正在搜索字符串缓存: {query} (已找到 {match_count} 条)",
                        )
                elif processed == 0 or processed % 1000 == 0:
                    self._emit_progress(
                        0,
                        0,
                        f"正在搜索字符串缓存: {query} (已找到 {match_count} 条)",
                    )

                instruction_index = int(record.get("index", -1))
                if instruction_index < 0:
                    processed += 1
                    continue
                match_count += 1
                processed += 1

                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            if total_records > 0:
                self._emit_progress(total_records, total_records, f"字符串缓存搜索完成: {query}")
            else:
                self._emit_progress(max(1, match_count), max(1, match_count), f"字符串缓存搜索完成: {query}")
            return {
                "query": query,
                "count": match_count,
                "cancelled": False,
                "truncated": truncated,
                "lazy": True,
            }

        total = self.parser.get_instruction_count()
        progress_step = self._progress_step(total)
        self._emit_progress(0, total, f"正在全量搜索字符串: {query}")

        for i in range(total):
            if self._cancelled:
                return {
                    "query": query,
                    "count": match_count,
                    "cancelled": True,
                    "truncated": truncated,
                    "lazy": True,
                }
            self._cooperative_yield(i)
            if i > 0 and self._progress_due(i, step=progress_step):
                self._emit_progress(i, total, f"正在全量搜索字符串: {query}")

            full_info = self.parser.get_instruction_info(i, include_line_text=True)
            if not full_info:
                continue

            instruction = self.parser.parse_instruction_at(i)
            raw_line = instruction.raw_line if instruction else getattr(full_info, "line_text", "")
            string_hints = self._extract_string_annotations_from_text(raw_line)
            if not string_hints:
                continue

            for reg, reg_value, string_value, hex_bytes in string_hints:
                if query_lower not in string_value.lower():
                    continue
                match_count += 1
                if self.MAX_RESULTS is not None and match_count >= self.MAX_RESULTS:
                    truncated = True
                    break

            if truncated:
                break

        self._emit_progress(total, total, f"字符串搜索完成: {query}")
        return {
            "query": query,
            "count": match_count,
            "cancelled": False,
            "truncated": truncated,
            "lazy": True,
        }

    def run(self):
        try:
            if self.mode == self.MODE_FIND_FIRST:
                result = self._find_first_match()
            elif self.mode == self.MODE_ADDRESS_ALL:
                result = self._collect_address_matches()
            elif self.mode == self.MODE_OFFSET_ALL:
                result = self._collect_offset_matches()
            elif self.mode == self.MODE_MNEMONIC_ALL:
                result = self._collect_mnemonic_matches()
            elif self.mode == self.MODE_DATA_ALL:
                result = self._collect_data_matches()
            elif self.mode == self.MODE_STRING_ALL:
                result = self._collect_string_matches()
            else:
                raise ValueError(f"Unknown search mode: {self.mode}")

            self.finished.emit(self.mode, result)
        except Exception as exc:
            if not self._cancelled:
                self.error.emit(str(exc))


class SearchProcessThread(QThread):
    """Run heavy searches in a separate Python process to keep the UI responsive."""

    finished = Signal(str, object)
    error = Signal(str)
    progress = Signal(object, object, str)

    def __init__(self, file_path: str, mode: str, query: str, start_index: int = 0):
        super().__init__()
        self.file_path = file_path
        self.mode = mode
        self.query = query
        self.start_index = max(0, int(start_index))
        self._cancelled = False
        self._process: Optional[subprocess.Popen] = None

    def cancel(self):
        self._cancelled = True
        process = self._process
        if not process or process.poll() is not None:
            return
        try:
            process.terminate()
        except OSError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass

    def _build_command(self) -> List[str]:
        return [
            sys.executable,
            str(PROJECT_ROOT / "search_worker.py"),
            "--file",
            self.file_path,
            "--mode",
            self.mode,
            "--query",
            self.query,
            "--start-index",
            str(self.start_index),
        ]

    def run(self):
        command = self._build_command()
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        result_payload: Optional[Dict[str, Any]] = None
        worker_error: Optional[str] = None
        process: Optional[subprocess.Popen] = None
        try:
            process = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
            self._process = process

            assert process.stdout is not None
            for raw_line in process.stdout:
                if self._cancelled:
                    break
                line = (raw_line or "").strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg_type = message.get("type")
                if msg_type == "progress":
                    self.progress.emit(
                        int(message.get("current", 0)),
                        int(message.get("total", 0)),
                        str(message.get("text", "")),
                    )
                elif msg_type == "result":
                    result_payload = message.get("result", {})
                elif msg_type == "error":
                    worker_error = str(message.get("error", "搜索失败"))

            if self._cancelled:
                return

            stderr_text = ""
            if process.stderr is not None:
                stderr_text = process.stderr.read().strip()
            return_code = process.wait()

            if result_payload is not None:
                self.finished.emit(self.mode, result_payload)
                return

            if worker_error:
                self.error.emit(worker_error)
                return

            if return_code != 0:
                self.error.emit(stderr_text or f"搜索进程退出异常: {return_code}")
                return

            self.error.emit("搜索进程未返回结果")
        except Exception as exc:
            if not self._cancelled:
                self.error.emit(str(exc))
        finally:
            self._process = None
            if process is not None:
                try:
                    if process.stdout:
                        process.stdout.close()
                except OSError:
                    pass
                try:
                    if process.stderr:
                        process.stderr.close()
                except OSError:
                    pass


class AnalysisThread(QThread):
    """Background worker for register-centric analyses."""

    finished = Signal(str, object)
    error = Signal(str)

    MODE_TRACE_SOURCE = "trace_source"
    MODE_REVERSE_TAINT = "reverse_taint"
    MODE_DATA_PROVENANCE = "data_provenance"

    def __init__(
        self,
        parser: LazyLogParser,
        cache_worker: CacheWorker,
        mode: str,
        register: str,
        from_index: int,
    ):
        super().__init__()
        self.parser = parser
        self.cache_worker = cache_worker
        self.mode = mode
        self.register = register
        self.from_index = from_index

    def run(self):
        try:
            calc = RegisterCalculator(self.parser, self.cache_worker)
            if self.mode == self.MODE_TRACE_SOURCE:
                result = {
                    "register": self.register,
                    "source_index": calc.trace_register_source(self.register, self.from_index),
                }
            elif self.mode == self.MODE_REVERSE_TAINT:
                result = {
                    "register": self.register,
                    "chain": calc.reverse_taint_trace(
                        self.register,
                        self.from_index,
                        max_steps=500,
                    ),
                }
            elif self.mode == self.MODE_DATA_PROVENANCE:
                result = {
                    "register": self.register,
                    "trace_result": calc.trace_data_provenance(
                        self.register,
                        self.from_index,
                        max_scan=30000,
                        max_calc_steps=160,
                    ),
                }
            else:
                raise ValueError(f"Unknown analysis mode: {self.mode}")

            self.finished.emit(self.mode, result)
        except Exception as exc:
            self.error.emit(str(exc))


class SortableTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by an explicit key."""

    def __init__(self, text: str, sort_key=None):
        super().__init__(text)
        self._sort_key = text if sort_key is None else sort_key

    def __lt__(self, other):
        if isinstance(other, SortableTableWidgetItem):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


class SearchResultsTableModel(QAbstractTableModel):
    """Lightweight table model for large search result sets."""

    def __init__(self, columns: List[Dict[str, Any]], rows, parent=None):
        super().__init__(parent)
        self._columns = columns
        self._rows = rows if isinstance(rows, list) else None
        self._row_source = None if isinstance(rows, list) else rows
        self._row_cache: "OrderedDict[int, Dict[str, Any]]" = OrderedDict()
        self._row_cache_max_size = 2048

    def _resolve_row(self, row_index: int) -> Dict[str, Any]:
        if self._rows is not None:
            return self._rows[row_index]

        cached = self._row_cache.get(row_index)
        if cached is not None:
            self._row_cache.move_to_end(row_index)
            return cached

        row = self._row_source.row_at(row_index)
        self._row_cache[row_index] = row
        self._row_cache.move_to_end(row_index)
        while len(self._row_cache) > self._row_cache_max_size:
            self._row_cache.popitem(last=False)
        return row

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        if self._rows is not None:
            return len(self._rows)
        return self._row_source.row_count()

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._columns)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None

        row = self._resolve_row(index.row())
        column = self._columns[index.column()]
        display_fn: Callable[[Dict[str, Any]], Any] = column["display"]
        sort_fn: Callable[[Dict[str, Any]], Any] = column["sort"]

        if role == Qt.DisplayRole:
            value = display_fn(row)
            return "" if value is None else str(value)
        if role == Qt.ToolTipRole:
            value = display_fn(row)
            return "" if value is None else str(value)
        if role == Qt.UserRole:
            return sort_fn(row)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._columns[section]["header"]
        return str(section + 1)

    def instruction_index_at(self, row: int) -> int:
        if row < 0 or row >= self.rowCount():
            return -1
        try:
            return int(self._resolve_row(row).get("index", -1))
        except (TypeError, ValueError):
            return -1


class AdaptiveTableView(QTableView):
    """QTableView that reflows wrapped rows when the dialog is resized."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._resize_rows_timer = QTimer(self)
        self._resize_rows_timer.setSingleShot(True)
        self._resize_rows_timer.timeout.connect(self.resizeRowsToContents)
        self.setWordWrap(True)
        self.setTextElideMode(Qt.ElideNone)
        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def schedule_row_resize(self):
        self._resize_rows_timer.start(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.schedule_row_resize()

    def showEvent(self, event):
        super().showEvent(event)
        self.schedule_row_resize()


class MnemonicSearchResultsSource:
    """Lazy row source for very large mnemonic search result sets."""

    def __init__(self, parser: LazyLogParser, query: str):
        self.parser = parser
        self.query = query
        self._count = parser.count_instruction_indices_for_mnemonic_prefix(query)
        self._cache: "OrderedDict[int, Dict[str, Any]]" = OrderedDict()
        self._cache_max_size = 4096

    def row_count(self) -> int:
        return self._count

    def row_at(self, row_index: int) -> Dict[str, Any]:
        cached = self._cache.get(row_index)
        if cached is not None:
            self._cache.move_to_end(row_index)
            return cached

        instruction_index = self.parser.get_instruction_index_for_mnemonic_prefix_position(
            self.query,
            row_index,
        )
        if instruction_index < 0:
            return {}

        full_info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
        if not full_info:
            return {}

        instruction = self.parser.parse_instruction_at(instruction_index)
        mem_addr, mem_data = SearchThread._build_instruction_memory_summary(
            instruction,
            full_info.comment,
        )
        row = {
            "index": instruction_index,
            "line": instruction_index + 1,
            "instruction_address": MainWindow._format_address_for_display(full_info.address),
            "mnemonic": full_info.mnemonic,
            "instruction_text": f"{full_info.mnemonic} {full_info.operands}".strip(),
            "memory_address": mem_addr,
            "data": mem_data,
        }
        self._cache[row_index] = row
        self._cache.move_to_end(row_index)
        while len(self._cache) > self._cache_max_size:
            self._cache.popitem(last=False)
        return row


class _StreamingSearchResultsSource:
    """Base class for parser-backed lazy result sources."""

    def __init__(self, parser: LazyLogParser, count: int):
        self.parser = parser
        self._count = max(0, int(count))
        self._refs: List[Any] = []
        self._iterator = self._iter_refs()
        self._exhausted = False
        self._cache: "OrderedDict[int, Dict[str, Any]]" = OrderedDict()
        self._cache_max_size = 2048

    def row_count(self) -> int:
        return self._count

    def _iter_refs(self):
        raise NotImplementedError

    def _build_row(self, row_index: int, ref: Any) -> Dict[str, Any]:
        raise NotImplementedError

    def _ensure_ref_loaded(self, row_index: int):
        while not self._exhausted and len(self._refs) <= row_index:
            try:
                self._refs.append(next(self._iterator))
            except StopIteration:
                self._exhausted = True
                break

    def row_at(self, row_index: int) -> Dict[str, Any]:
        cached = self._cache.get(row_index)
        if cached is not None:
            self._cache.move_to_end(row_index)
            return cached

        self._ensure_ref_loaded(row_index)
        if row_index >= len(self._refs):
            return {}

        row = self._build_row(row_index, self._refs[row_index])
        self._cache[row_index] = row
        self._cache.move_to_end(row_index)
        while len(self._cache) > self._cache_max_size:
            self._cache.popitem(last=False)
        return row


class AddressSearchResultsSource(_StreamingSearchResultsSource):
    """Lazy row source for address-search results."""

    def __init__(self, parser: LazyLogParser, query: str, count: int):
        self.query = query
        super().__init__(parser, count)

    def _iter_refs(self):
        kind_read = int(getattr(self.parser, "MEMORY_KIND_READ", 0))
        kind_write = int(getattr(self.parser, "MEMORY_KIND_WRITE", 1))
        kind_dump = int(getattr(self.parser, "MEMORY_KIND_DUMP", 2))
        kind_dump_modified = int(getattr(self.parser, "MEMORY_KIND_DUMP_MODIFIED", 3))
        for instruction_index, _address_value, _data_size, kind, slot in self.parser.iter_memory_records_for_address_prefix(
            self.query,
            limit=self._count,
        ):
            instruction = self.parser.parse_instruction_at(instruction_index)
            if not instruction:
                continue
            if kind in (kind_read, kind_write):
                if slot >= len(instruction.memory_ops):
                    continue
                op = instruction.memory_ops[slot]
                value, detail = SearchThread._format_memory_value(op.data_value)
                data_text = value if not detail or detail == value else f"{value} ({detail})"
                yield (
                    instruction_index,
                    "R" if kind == kind_read else "W",
                    MainWindow._format_address_for_display(op.address),
                    data_text,
                )
            elif kind in (kind_dump, kind_dump_modified):
                if slot >= len(instruction.memory_dump):
                    continue
                dump_line = instruction.memory_dump[slot]
                yield (
                    instruction_index,
                    "D*" if kind == kind_dump_modified else "D",
                    MainWindow._format_address_for_display(dump_line.address),
                    " ".join(dump_line.data),
                )

    def _build_row(self, _row_index: int, ref: Any) -> Dict[str, Any]:
        instruction_index, access, memory_address, data_text = ref
        info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
        return {
            "index": instruction_index,
            "line": instruction_index + 1,
            "instruction_address": MainWindow._format_address_for_display(info.address) if info else "-",
            "access": access,
            "memory_address": memory_address,
            "data": data_text,
        }


class OffsetSearchResultsSource(_StreamingSearchResultsSource):
    """Lazy row source for exact-offset search results."""

    def __init__(self, parser: LazyLogParser, query: str, count: int):
        self.query = query
        super().__init__(parser, count)

    def _iter_refs(self):
        for position in range(self._count):
            instruction_index = self.parser.get_instruction_index_for_offset_position(self.query, position)
            if instruction_index >= 0:
                yield instruction_index

    def _build_row(self, _row_index: int, ref: Any) -> Dict[str, Any]:
        instruction_index = int(ref)
        info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
        instruction = self.parser.parse_instruction_at(instruction_index)
        mem_addr, mem_data = SearchThread._build_instruction_memory_summary(instruction, info.comment if info else "")
        return {
            "index": instruction_index,
            "line": instruction_index + 1,
            "instruction_address": MainWindow._format_address_for_display(info.address) if info else "-",
            "offset": MainWindow._format_address_for_display(info.offset) if info else self.query,
            "mnemonic": info.mnemonic if info else "",
            "instruction_text": f"{info.mnemonic} {info.operands}".strip() if info else "",
            "memory_address": mem_addr,
            "data": mem_data,
        }


class DataSearchResultsSource(_StreamingSearchResultsSource):
    """Lazy row source for data-search results."""

    def __init__(self, parser: LazyLogParser, query: str, count: int):
        self.query = query
        self._tokens = SearchThread._data_query_tokens(query)
        super().__init__(parser, count)

    def _iter_refs(self):
        for instruction_index in self.parser.iter_instruction_indices_by_text_tokens(
            self._tokens,
            limit=self._count,
        ):
            full_info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
            if not full_info:
                continue
            instruction = self.parser.parse_instruction_at(instruction_index)
            match_scope = SearchThread._data_match_scope(self.query, full_info, instruction)
            if not match_scope:
                continue
            yield (instruction_index, match_scope)

    def _build_row(self, _row_index: int, ref: Any) -> Dict[str, Any]:
        instruction_index, match_scope = ref
        info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
        instruction = self.parser.parse_instruction_at(instruction_index)
        mem_addr, detail = SearchThread._build_instruction_memory_summary(instruction, info.comment if info else "")
        return {
            "index": instruction_index,
            "line": instruction_index + 1,
            "instruction_address": MainWindow._format_address_for_display(info.address) if info else "-",
            "offset": MainWindow._format_address_for_display(info.offset) if info else "-",
            "mnemonic": info.mnemonic if info else "",
            "instruction_text": f"{info.mnemonic} {info.operands}".strip() if info else "",
            "match_scope": match_scope,
            "memory_address": mem_addr,
            "data": detail,
        }


class StringSearchResultsSource(_StreamingSearchResultsSource):
    """Lazy row source for string-search results."""

    def __init__(self, parser: LazyLogParser, query: str, count: int):
        self.query = query
        super().__init__(parser, count)

    def _iter_refs(self):
        for record in self.parser.iter_string_annotation_matches(self.query, limit=self._count):
            instruction_index = int(record.get("index", -1))
            if instruction_index < 0:
                continue
            yield (
                instruction_index,
                str(record.get("string_register", "")),
                str(record.get("register_value", "")),
                str(record.get("string_value", "")),
                str(record.get("string_hex", "")),
            )

    def _build_row(self, _row_index: int, ref: Any) -> Dict[str, Any]:
        instruction_index, reg, reg_value, string_value, string_hex = ref
        info = self.parser.get_instruction_info(instruction_index, include_line_text=True)
        instruction = self.parser.parse_instruction_at(instruction_index)
        mem_addr, detail = SearchThread._build_instruction_memory_summary(instruction, info.comment if info else "")
        return {
            "index": instruction_index,
            "line": instruction_index + 1,
            "instruction_address": MainWindow._format_address_for_display(info.address) if info else "-",
            "offset": MainWindow._format_address_for_display(info.offset) if info else "-",
            "mnemonic": info.mnemonic if info else "",
            "instruction_text": f"{info.mnemonic} {info.operands}".strip() if info else "",
            "string_register": reg,
            "register_value": reg_value,
            "string_value": string_value,
            "string_hex": string_hex,
            "memory_address": mem_addr,
            "data": detail,
        }


class MainWindow(QMainWindow):
    string_cache_status_signal = Signal(bool, int, str)
    string_cache_progress_signal = Signal(object, object, str)

    def __init__(self):
        super().__init__()
        
        self.parser: Optional[LazyLogParser] = None
        self.instruction_count = 0
        self.initial_sp: Optional[str] = None
        
        self.cache_worker: Optional[CacheWorker] = None
        self.register_calc: Optional[RegisterCalculator] = None
        
        self.parse_thread: Optional[ParseThread] = None
        self.search_thread: Optional[SearchThread] = None
        self.analysis_thread: Optional[AnalysisThread] = None
        self.offset_warmup_thread: Optional[threading.Thread] = None
        self.string_annotations_warmup_thread: Optional[threading.Thread] = None
        self.string_cache_rebuild_thread: Optional[threading.Thread] = None
        self.open_dialogs: List[QDialog] = []
        
        
        self.instruction_view: Optional[InstructionViewController] = None
        
        self.history: List[int] = []
        self.history_index = -1
        self.max_history = 100
        
        self.selected_register: Optional[str] = None
        self.selected_index = -1
        
        self.search_input = None
        self.status_label = None
        self.stats_label = None
        self.footer_labels = {}
        self.theme_button = None
        self.current_theme = "amber"
        self.progress_bar = None
        self.virtual_table: Optional[VirtualScrollTable] = None
        self.register_table = None
        self.memory_display = None
        self.current_file_path: Optional[str] = None
        self.string_cache_ready = False
        self.sorted_registers = sorted(
            RegisterCalculator.get_all_arm64_registers(),
            key=RegisterCalculator.get_register_sort_key,
        )
        self.memory_refresh_timer = QTimer(self)
        self.memory_refresh_timer.setSingleShot(True)
        self.memory_refresh_timer.timeout.connect(self._refresh_memory_display_for_resize)
        self.chrome_sync_timer = QTimer(self)
        self.chrome_sync_timer.timeout.connect(self._sync_chrome_labels)
        self.chrome_sync_timer.start(200)
        self.string_cache_status_signal.connect(self._on_string_cache_status_changed)
        self.string_cache_progress_signal.connect(self._on_string_cache_progress)
        
        self.init_ui()

    @staticmethod
    def _dispose_dialog(dialog: QDialog, table: Optional[QAbstractItemView] = None):
        """Release large table dialogs promptly after they close."""
        if table is not None:
            try:
                if isinstance(table, QTableWidget):
                    table.setSortingEnabled(False)
                    table.clearContents()
                    table.setRowCount(0)
                elif hasattr(table, "setModel"):
                    table.setModel(None)
            except RuntimeError:
                pass
        try:
            dialog.deleteLater()
        except RuntimeError:
            pass

    def _show_persistent_dialog(self, dialog: QDialog, table: Optional[QAbstractItemView] = None):
        """Show a modeless dialog and keep it alive until the user closes it."""
        dialog.setModal(False)
        dialog.setWindowModality(Qt.NonModal)
        self.open_dialogs.append(dialog)

        def on_finished(_result: int, current_dialog=dialog, current_table=table):
            try:
                self.open_dialogs.remove(current_dialog)
            except ValueError:
                pass
            self._dispose_dialog(current_dialog, current_table)

        dialog.finished.connect(on_finished)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
    
    def init_ui(self):
        self.setWindowTitle('TraceAnalyzer')
        self.setGeometry(100, 100, 1800, 1000)
        
        central_widget = QWidget()
        central_widget.setObjectName("centralRoot")
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 14, 14, 12)
        main_layout.setSpacing(10)
        
        
        toolbar, self.search_input, self.status_label, self.stats_label = UIFactory.create_toolbar({
            'load_file': self.load_file,
            'search': self.search_instruction,
            'search_all': self.search_all_addresses,
            'search_mnemonic': self.search_instructions_by_mnemonic
        })
        clear_cache_btn = QPushButton("清理缓存")
        clear_cache_btn.setObjectName("toolbarButton")
        clear_cache_btn.setMinimumHeight(36)
        clear_cache_btn.setMinimumWidth(104)
        clear_cache_btn.clicked.connect(self.clear_trace_cache)
        toolbar.controls_layout.insertWidget(1, clear_cache_btn)
        rebuild_string_cache_btn = QPushButton("重建字符串缓存")
        rebuild_string_cache_btn.setObjectName("toolbarButton")
        rebuild_string_cache_btn.setMinimumHeight(36)
        rebuild_string_cache_btn.setMinimumWidth(140)
        rebuild_string_cache_btn.clicked.connect(self.rebuild_string_cache)
        toolbar.controls_layout.insertWidget(2, rebuild_string_cache_btn)
        self.theme_button = QPushButton()
        self.theme_button.setObjectName("toolbarButton")
        self.theme_button.setMinimumHeight(36)
        self.theme_button.setMinimumWidth(110)
        self.theme_button.clicked.connect(self.toggle_theme)
        toolbar.controls_layout.insertWidget(3, self.theme_button)
        self.search_input.setPlaceholderText("行号/地址/偏移/指令/数据/字符串...")
        data_search_btn = QPushButton("数据全查")
        data_search_btn.setObjectName("toolbarButton")
        data_search_btn.setMinimumHeight(36)
        data_search_btn.setMinimumWidth(104)
        data_search_btn.clicked.connect(self.search_data_values)
        toolbar.controls_layout.insertWidget(7, data_search_btn)
        string_search_btn = QPushButton("字符串全查")
        string_search_btn.setObjectName("toolbarButton")
        string_search_btn.setMinimumHeight(36)
        string_search_btn.setMinimumWidth(116)
        string_search_btn.clicked.connect(self.search_string_values)
        toolbar.controls_layout.insertWidget(8, string_search_btn)
        main_layout.addWidget(toolbar)
        
        
        self.progress_bar = UIFactory.create_progress_bar()
        main_layout.addWidget(self.progress_bar)
        
        content_splitter = QSplitter(Qt.Horizontal)
        
        
        instruction_panel = self._create_instruction_panel()
        content_splitter.addWidget(instruction_panel)
        
        
        debug_panel, self.register_table, self.memory_display = UIFactory.create_debug_panel()
        self.memory_display.installEventFilter(self)
        content_splitter.addWidget(debug_panel)
        
        content_splitter.setStretchFactor(0, 6)
        content_splitter.setStretchFactor(1, 4)
        content_splitter.splitterMoved.connect(self._on_content_splitter_moved)
        
        main_layout.addWidget(content_splitter, 1)

        footer_bar, self.footer_labels = UIFactory.create_footer_bar()
        main_layout.addWidget(footer_bar)
        
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
        self._update_theme_button()
        self._sync_chrome_labels()

    def _update_theme_button(self):
        if not self.theme_button:
            return
        if self.current_theme == "amber":
            self.theme_button.setText("主题: 琥珀")
            self.theme_button.setToolTip("点击切换到冷色主题")
        else:
            self.theme_button.setText("主题: 冷色")
            self.theme_button.setToolTip("点击切换到琥珀主题")

    def apply_theme(self, theme: str):
        theme = theme if theme in {"amber", "midnight"} else "amber"
        self.current_theme = theme
        app = QApplication.instance()
        if app is not None:
            app.setProperty("taTheme", theme)
            app.setStyleSheet(get_theme_stylesheet(theme))
        self._update_theme_button()

    def toggle_theme(self):
        next_theme = "midnight" if self.current_theme == "amber" else "amber"
        self.apply_theme(next_theme)
        theme_text = "冷色" if next_theme == "midnight" else "琥珀"
        self.status_label.setText(f"已切换到{theme_text}主题")
        self._sync_chrome_labels()

    def _set_footer_value(self, key: str, value: str):
        label = self.footer_labels.get(key)
        if label is not None:
            label.setText(value)

    def _sync_chrome_labels(self):
        """Mirror live status into the lower chrome cards."""
        status_text = self.status_label.text().strip() if self.status_label else "就绪"
        stats_text = self.stats_label.text().strip() if self.stats_label else ""

        self._set_footer_value("status", status_text or "就绪")
        self._set_footer_value("mode", "TRACE ANALYSIS")
        self._set_footer_value("arch", "AARCH64")

        if self.current_file_path:
            session_text = Path(self.current_file_path).stem
        else:
            session_text = "WAITING"
        self._set_footer_value("session", session_text)

        strings_text = "--"
        if self.string_cache_ready and self.parser and hasattr(self.parser, "get_string_annotation_count"):
            try:
                strings_text = f"{int(self.parser.get_string_annotation_count()):,}"
            except Exception:
                strings_text = "--"
        inst_text = "--"
        if self.instruction_count:
            inst_text = f"{int(self.instruction_count):,}"
        self._set_footer_value("cache", f"STRINGS: {strings_text}  |  INST: {inst_text}")

        perf_text = "READY"
        if self.parse_thread:
            perf_text = "INDEXING"
        elif self.search_thread:
            perf_text = "SEARCHING"
        elif self.analysis_thread:
            perf_text = "ANALYZING"
        self._set_footer_value("performance", perf_text)

        warning_text = "NONE"
        status_upper = status_text.upper()
        if any(token in status_text for token in ("失败", "错误", "异常")):
            warning_text = "ERROR"
        elif "警告" in status_text or "WARNING" in status_upper:
            warning_text = "WARNING"
        elif self.search_thread or self.analysis_thread or self.parse_thread:
            warning_text = "BUSY"
        self._set_footer_value("warning", warning_text)

    def _on_content_splitter_moved(self, _pos: int, _index: int):
        """左右面板拖动时，同步刷新虚拟表格的可见行数与列宽。"""
        if self.instruction_view:
            QTimer.singleShot(0, self.instruction_view.refresh_geometry)
        self._schedule_memory_display_refresh()

    def eventFilter(self, watched, event):
        """监听内存区尺寸变化，按当前宽度重新排版内存布局。"""
        if watched is self.memory_display and event.type() in (QEvent.Resize, QEvent.Show):
            self._schedule_memory_display_refresh()
        return super().eventFilter(watched, event)

    def _schedule_memory_display_refresh(self):
        """延迟刷新内存区，避免拖动 splitter 时过于频繁重绘。"""
        if self.memory_display:
            self.memory_refresh_timer.start(40)

    def _refresh_memory_display_for_resize(self):
        """窗口或右侧面板尺寸变化后，按新宽度重排内存布局。"""
        if self.selected_index < 0 or not self.parser:
            return
        instruction = self.parser.parse_instruction_at(self.selected_index)
        if instruction:
            self.update_memory_display(instruction)
    
    def _create_instruction_panel(self) -> QFrame:
        """_create_instruction_panel function."""
        panel = QFrame()
        panel.setObjectName("panelCard")
        panel.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        header = UIFactory.create_panel_title("指令执行序列")
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
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"正在建立索引: {Path(file_path).name}...")
        self.setEnabled(False)
        self.current_file_path = file_path
        
        self.parse_thread = ParseThread(file_path)
        self.parse_thread.finished.connect(self.on_parse_finished)
        self.parse_thread.error.connect(self.on_parse_error)
        self.parse_thread.progress.connect(self.on_parse_progress)
        self.parse_thread.start()

    def clear_trace_cache(self):
        """Delete cached sidecar data for the current trace, or clear the whole cache root."""
        if self.parse_thread and self.parse_thread.isRunning():
            QMessageBox.information(self, "请稍候", "当前正在建立索引，请等待完成后再清理缓存。")
            return

        current_file = self.current_file_path
        if current_file:
            cache_dir = LazyLogParser.cache_dir_for_file(current_file)
            temp_artifact_count = len(LazyLogParser.list_temp_artifacts())
            reply = QMessageBox.question(
                self,
                "清理当前缓存",
                (
                    f"确认删除当前 trace 的缓存目录吗？\n\n"
                    f"文件：{Path(current_file).name}\n"
                    f"缓存目录：{cache_dir}\n\n"
                    f"另外还会清理 Unidbg 相关目录中的 {temp_artifact_count} 个临时调试产物。"
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

            self._cleanup()
            removed, _ = LazyLogParser.clear_cache_for_file(current_file)
            temp_removed = LazyLogParser.clear_temp_artifacts()
            total_removed = removed + temp_removed
            if total_removed > 0:
                self.status_label.setText(f"已清理当前 trace 缓存与临时调试文件：{cache_dir.name}")
                QMessageBox.information(
                    self,
                    "清理完成",
                    (
                        f"已删除当前 trace 的缓存数据，并清理 Unidbg 相关目录中的临时调试文件。\n\n"
                        f"缓存目录：{cache_dir}\n"
                        f"删除数量：{total_removed}"
                    ),
                )
            else:
                self.status_label.setText("当前 trace 没有可删除的缓存或临时文件")
                QMessageBox.information(
                    self,
                    "没有缓存",
                    (
                        f"当前 trace 没有发现缓存目录，也没有发现可清理的 Unidbg 临时调试文件。\n\n"
                        f"缓存目录：{cache_dir}"
                    ),
                )
            return

        cache_root = LazyLogParser.get_cache_root()
        temp_artifact_count = len(LazyLogParser.list_temp_artifacts())
        reply = QMessageBox.question(
            self,
            "清理全部缓存",
            (
                f"当前没有打开 trace，是否删除整个缓存目录，并清理 Unidbg 相关目录中的临时调试产物？\n\n"
                f"缓存目录：{cache_root}\n"
                f"临时调试文件数量：{temp_artifact_count}"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        removed, _ = LazyLogParser.clear_all_cache()
        if removed > 0:
            self.status_label.setText("已清理全部 trace 缓存")
            QMessageBox.information(
                self,
                "清理完成",
                f"已删除整个缓存目录，共清理 {removed} 个缓存项。\n\n{cache_root}",
            )
        else:
            self.status_label.setText("缓存目录为空")
            QMessageBox.information(
                self,
                "没有缓存",
                f"缓存目录当前为空。\n\n{cache_root}",
            )
    
    def _cleanup(self):
        """_cleanup function."""
        self._stop_search_thread()
        self._stop_analysis_thread()

        if self.cache_worker:
            self.cache_worker.stop()
            self.cache_worker = None

        if self.parser:
            self.parser.close()
        
        self.parser = None
        self.instruction_count = 0
        self.selected_index = -1
        self.history.clear()
        self.history_index = -1
        self.current_file_path = None
        
        if self.register_table:
            self.register_table.setRowCount(0)
        if self.memory_display:
            self.memory_display.clear()
        
        if self.instruction_view:
            self.instruction_view.clear()
    
    def on_parse_finished(self, parser: LazyLogParser, initial_sp: Optional[str]):
        """on_parse_finished function."""
        finished_thread = self.parse_thread
        self.parse_thread = None
        if finished_thread is not None:
            finished_thread.deleteLater()

        self.parser = parser
        self.instruction_count = parser.get_instruction_count()
        self.initial_sp = initial_sp
        self.string_cache_ready = bool(
            hasattr(parser, "has_string_annotations_sidecar")
            and parser.has_string_annotations_sidecar()
        )
        
        
        self.cache_worker = CacheWorker(parser)
        self.cache_worker.checkpoint_ready.connect(self.on_checkpoint_ready)
        self.cache_worker.progress.connect(self.on_cache_progress)
        self.cache_worker.all_checkpoints_ready.connect(self.on_all_checkpoints_ready)
        
        
        self.register_calc = RegisterCalculator(parser, self.cache_worker)
        self._start_offset_postings_warmup(parser)
        self._start_string_annotations_warmup(parser)

        self.instruction_view.set_parser(parser, self.instruction_count)
        
        self.stats_label.setText(f'Total {self.instruction_count:,} instructions')
        QTimer.singleShot(10, self.delayed_update_table)

    def on_parse_error(self, error_msg: str):
        """on_parse_error function."""
        failed_thread = self.parse_thread
        self.parse_thread = None
        if failed_thread is not None:
            failed_thread.deleteLater()

        QMessageBox.critical(self, "错误", f"解析文件失败: {error_msg}")
        self.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("加载失败")

    def on_parse_progress(self, current: int, total: int):
        """Update visible load progress for large files."""
        if total <= 0:
            self.progress_bar.setRange(0, 0)
            return

        percent = max(0, min(100, int(current * 100 / total)))
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(percent)

        file_name = Path(self.current_file_path).name if self.current_file_path else "trace"
        current_mb = current / (1024 * 1024)
        total_mb = total / (1024 * 1024)
        self.status_label.setText(
            f"正在建立索引: {file_name} ({percent}%, {current_mb:.0f}/{total_mb:.0f} MB)"
        )

    def delayed_update_table(self):
        """delayed_update_table function."""
        self.instruction_view.initialize_table(500)

        if self.cache_worker and self.cache_worker.get_checkpoint_count() == 0:
            self.cache_worker.start_building_checkpoints()

        if self.string_cache_ready:
            count = self.parser.get_string_annotation_count() if self.parser else 0
            self.status_label.setText(f"就绪（字符串缓存已就绪，{count:,} 条）")
        else:
            self.status_label.setText("就绪（字符串缓存后台构建中...）")

        self.progress_bar.setVisible(False)
        self.setEnabled(True)

    def _start_offset_postings_warmup(self, parser: LazyLogParser):
        """Warm exact-offset postings in the background when missing."""
        if not hasattr(parser, "has_offset_postings_sidecar"):
            return
        if parser.has_offset_postings_sidecar():
            return

        def worker():
            try:
                parser._ensure_offset_postings(force_build=True)
            except Exception:
                pass

        self.offset_warmup_thread = threading.Thread(
            target=worker,
            name="offset-postings-warmup",
            daemon=True,
        )
        self.offset_warmup_thread.start()

    def _start_string_annotations_warmup(self, parser: LazyLogParser):
        """Warm cached string annotations in the background when missing."""
        if not hasattr(parser, "has_string_annotations_sidecar"):
            return
        if parser.has_string_annotations_sidecar():
            self.string_cache_status_signal.emit(True, parser.get_string_annotation_count(), "ready")
            return

        def worker():
            try:
                def progress(current: int, total: int):
                    self.string_cache_progress_signal.emit(current, total, "warmup")

                ready = parser._ensure_string_annotations_sidecar(
                    force_build=True,
                    progress_callback=progress,
                )
                count = parser.get_string_annotation_count() if ready else 0
                self.string_cache_status_signal.emit(bool(ready), int(count), "warmup")
            except Exception:
                self.string_cache_status_signal.emit(False, 0, "warmup_failed")

        self.string_annotations_warmup_thread = threading.Thread(
            target=worker,
            name="string-annotations-warmup",
            daemon=True,
        )
        self.string_annotations_warmup_thread.start()

    def _on_string_cache_status_changed(self, ready: bool, count: int, context: str):
        """Reflect background string-cache status in the main status bar."""
        self.string_cache_ready = bool(ready)
        if self.search_thread or self.parse_thread:
            return
        self.progress_bar.setVisible(False)
        if ready:
            self.status_label.setText(f"就绪（字符串缓存已就绪，{int(count):,} 条）")
        elif context == "rebuild_failed":
            self.status_label.setText("就绪（字符串缓存重建失败）")
        elif context == "warmup_failed":
            self.status_label.setText("就绪（字符串缓存后台构建失败）")
        else:
            self.status_label.setText("就绪（字符串缓存后台构建中...）")

    def _on_string_cache_progress(self, current: int, total: int, context: str):
        """Show progress for background string-cache warmup / rebuild tasks."""
        if self.search_thread or self.parse_thread:
            return

        if total and total > 0:
            percent = max(0, min(100, int(int(current) * 100 / int(total))))
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(percent)
            if context == "rebuild":
                self.status_label.setText(f"正在重建字符串缓存... {percent}%")
            else:
                self.status_label.setText(f"就绪（字符串缓存后台构建中... {percent}%）")
        else:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            if context == "rebuild":
                self.status_label.setText("正在重建字符串缓存...")
            else:
                self.status_label.setText("就绪（字符串缓存后台构建中...）")

    def _is_string_cache_task_running(self) -> bool:
        """Return whether warmup or rebuild of the string cache is still in flight."""
        return bool(
            (self.string_annotations_warmup_thread and self.string_annotations_warmup_thread.is_alive())
            or (self.string_cache_rebuild_thread and self.string_cache_rebuild_thread.is_alive())
        )

    def rebuild_string_cache(self):
        """Force a background rebuild of the cached string-annotation sidecar."""
        if self.parse_thread and self.parse_thread.isRunning():
            QMessageBox.information(self, "请稍候", "当前正在建立索引，请等待完成后再重建字符串缓存。")
            return
        if not self.parser:
            QMessageBox.information(self, "重建字符串缓存", "请先打开 trace 文件。")
            return
        if self._is_string_cache_task_running():
            QMessageBox.information(self, "重建字符串缓存", "字符串缓存任务正在运行，请稍候。")
            return

        self.status_label.setText("正在重建字符串缓存...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        def worker():
            try:
                def progress(current: int, total: int):
                    self.string_cache_progress_signal.emit(current, total, "rebuild")

                count = self.parser.rebuild_string_annotations_sidecar(
                    progress_callback=progress,
                )
                self.string_cache_status_signal.emit(True, int(count), "rebuild")
            except Exception:
                self.string_cache_status_signal.emit(False, 0, "rebuild_failed")

        self.string_cache_rebuild_thread = threading.Thread(
            target=worker,
            name="string-annotations-rebuild",
            daemon=True,
        )
        self.string_cache_rebuild_thread.start()

    def _stop_search_thread(self):
        """Cancel any in-flight background search."""
        if self.search_thread:
            self.search_thread.cancel()
            self.search_thread.wait()
            self.search_thread.deleteLater()
            self.search_thread = None

    def _stop_analysis_thread(self):
        """Wait for any in-flight analysis worker to finish."""
        if self.analysis_thread:
            self.analysis_thread.wait()
            self.analysis_thread.deleteLater()
            self.analysis_thread = None

    def _start_search_thread(self, mode: str, query: str, start_index: int = 0):
        """Launch a background search for large trace scans."""
        self._stop_search_thread()

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        if self.current_file_path:
            self.search_thread = SearchProcessThread(self.current_file_path, mode, query, start_index)
        else:
            self.search_thread = SearchThread(self.parser, mode, query, start_index)
        self.search_thread.progress.connect(self.on_search_progress)
        self.search_thread.finished.connect(self.on_search_finished)
        self.search_thread.error.connect(self.on_search_error)
        self.search_thread.start()

    def on_search_progress(self, current: int, total: int, text: str):
        """Update progress for background searches."""
        if total <= 0:
            self.progress_bar.setRange(0, 0)
        else:
            percent = max(0, min(100, int(current * 100 / total)))
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(percent)
            if "%" not in text:
                text = f"{text} ({percent}%)"
        self.status_label.setText(text)

    def on_search_finished(self, mode: str, result: Dict):
        """Handle background search completion."""
        finished_thread = self.sender()
        if finished_thread is not None and finished_thread is not self.search_thread:
            finished_thread.deleteLater()
            return

        self.search_thread = None
        self.progress_bar.setVisible(False)
        if finished_thread:
            finished_thread.deleteLater()

        if result.get("cancelled"):
            self.status_label.setText("搜索已取消")
            return

        if mode == SearchThread.MODE_FIND_FIRST:
            found_index = int(result.get("found_index", -1))
            query = result.get("query", "")
            hint = result.get("hint", "")
            if found_index >= 0:
                self.jump_to_instruction(found_index, add_history=True)
                self.status_label.setText(f"已定位到第 {found_index + 1} 条指令")
            else:
                message = hint or f"未找到匹配项: {query}"
                QMessageBox.information(self, "搜索结果", message)
                self.status_label.setText(f"搜索无结果: {query}")
            return

        if mode == SearchThread.MODE_ADDRESS_ALL:
            query = result.get("query", "")
            lazy_result = bool(result.get("lazy"))
            match_count = int(result.get("count", 0))
            matches = (
                AddressSearchResultsSource(self.parser, query, match_count)
                if lazy_result and self.parser
                else result.get("matches", [])
            )
            truncated = bool(result.get("truncated"))
            if (lazy_result and match_count <= 0) or (not lazy_result and not matches):
                QMessageBox.information(self, "地址全查", f"未找到匹配地址: {query}")
                self.status_label.setText(f"地址全查无结果: {query}")
            else:
                suffix = "（结果已截断）" if truncated else ""
                total_matches = match_count if lazy_result else len(matches)
                self.status_label.setText(f"地址全查完成: {total_matches} 条匹配{suffix}")
                self._show_address_matches_dialog(query, matches, truncated=truncated)
            return

        if mode == SearchThread.MODE_OFFSET_ALL:
            query = result.get("query", "")
            lazy_result = bool(result.get("lazy"))
            match_count = int(result.get("count", 0))
            matches = (
                OffsetSearchResultsSource(self.parser, query, match_count)
                if lazy_result and self.parser
                else result.get("matches", [])
            )
            truncated = bool(result.get("truncated"))
            if (lazy_result and match_count <= 0) or (not lazy_result and not matches):
                QMessageBox.information(self, "偏移搜索", f"未找到匹配偏移: {query}")
                self.status_label.setText(f"偏移搜索无结果: {query}")
            else:
                suffix = "（结果已截断）" if truncated else ""
                total_matches = match_count if lazy_result else len(matches)
                self.status_label.setText(f"偏移搜索完成: {total_matches} 条匹配{suffix}")
                self._show_offset_matches_dialog(query, matches, truncated=truncated)
            return

        if mode == SearchThread.MODE_MNEMONIC_ALL:
            query = result.get("query", "")
            lazy_result = bool(result.get("lazy"))
            match_count = int(result.get("count", 0))
            matches = (
                MnemonicSearchResultsSource(self.parser, query)
                if lazy_result and self.parser
                else result.get("matches", [])
            )
            truncated = bool(result.get("truncated"))
            if (lazy_result and match_count <= 0) or (not lazy_result and not matches):
                QMessageBox.information(self, "指令全查", f"未找到匹配助记符: {query}")
                self.status_label.setText(f"指令全查无结果: {query}")
            else:
                suffix = "（结果已截断）" if truncated else ""
                total_matches = match_count if lazy_result else len(matches)
                self.status_label.setText(f"指令全查完成: {total_matches} 条匹配{suffix}")
                self._show_mnemonic_matches_dialog(query, matches, truncated=truncated)
            return

        if mode == SearchThread.MODE_DATA_ALL:
            query = result.get("query", "")
            lazy_result = bool(result.get("lazy"))
            match_count = int(result.get("count", 0))
            matches = (
                DataSearchResultsSource(self.parser, query, match_count)
                if lazy_result and self.parser
                else result.get("matches", [])
            )
            truncated = bool(result.get("truncated"))
            if (lazy_result and match_count <= 0) or (not lazy_result and not matches):
                QMessageBox.information(self, "数据全查", f"未找到匹配数据: {query}")
                self.status_label.setText(f"数据全查无结果: {query}")
            else:
                suffix = "（结果已截断）" if truncated else ""
                total_matches = match_count if lazy_result else len(matches)
                self.status_label.setText(f"数据全查完成: {total_matches} 条匹配{suffix}")
                self._show_data_matches_dialog(query, matches, truncated=truncated)
            return

        if mode == SearchThread.MODE_STRING_ALL:
            query = result.get("query", "")
            lazy_result = bool(result.get("lazy"))
            match_count = int(result.get("count", 0))
            matches = (
                StringSearchResultsSource(self.parser, query, match_count)
                if lazy_result and self.parser
                else result.get("matches", [])
            )
            truncated = bool(result.get("truncated"))
            if (lazy_result and match_count <= 0) or (not lazy_result and not matches):
                QMessageBox.information(self, "字符串全查", f"未找到匹配字符串: {query}")
                self.status_label.setText(f"字符串全查无结果: {query}")
            else:
                suffix = "（结果已截断）" if truncated else ""
                total_matches = match_count if lazy_result else len(matches)
                self.status_label.setText(f"字符串全查完成: {total_matches} 条匹配{suffix}")
                self._show_string_matches_dialog(query, matches, truncated=truncated)
            return

    def on_search_error(self, error_msg: str):
        """Show background search failures."""
        errored_thread = self.sender()
        if errored_thread is not None and errored_thread is not self.search_thread:
            errored_thread.deleteLater()
            return

        if self.search_thread:
            self.search_thread.deleteLater()
        self.search_thread = None
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "搜索失败", error_msg)
        self.status_label.setText("搜索失败")

    def _start_analysis_thread(self, mode: str, register: str):
        """Run register analysis work without blocking the UI."""
        if not self.parser or not self.cache_worker or self.selected_index < 0:
            return

        self._stop_analysis_thread()

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        status_map = {
            AnalysisThread.MODE_TRACE_SOURCE: f"正在追踪寄存器来源: {register}",
            AnalysisThread.MODE_REVERSE_TAINT: f"正在执行反向污点分析: {register}",
            AnalysisThread.MODE_DATA_PROVENANCE: f"正在追踪数据来源: {register}",
        }
        self.status_label.setText(status_map.get(mode, "正在分析..."))

        self.analysis_thread = AnalysisThread(
            self.parser,
            self.cache_worker,
            mode,
            register,
            self.selected_index,
        )
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def on_analysis_finished(self, mode: str, result: Dict):
        """Handle background analysis completion."""
        finished_thread = self.sender()
        if finished_thread is not None and finished_thread is not self.analysis_thread:
            finished_thread.deleteLater()
            return

        self.analysis_thread = None
        self.progress_bar.setVisible(False)
        if finished_thread:
            finished_thread.deleteLater()

        register = result.get("register", "")
        if mode == AnalysisThread.MODE_TRACE_SOURCE:
            source_index = result.get("source_index")
            if isinstance(source_index, int) and source_index >= 0:
                self.jump_to_instruction(source_index, add_history=True)
                QTimer.singleShot(100, lambda: self.select_register_in_table(register))
                source_instr = self.parser.parse_instruction_at(source_index)
                if source_instr:
                    self.status_label.setText(
                        f"追踪: {register} 在第 {source_index + 1} 条指令被修改 ({source_instr.address})（PgUp 继续 / PgDn 返回）"
                    )
                else:
                    self.status_label.setText(f"追踪完成: {register} -> 第 {source_index + 1} 条指令")
            else:
                self.status_label.setText(f"未找到寄存器 {register} 的来源")
            return

        if mode == AnalysisThread.MODE_REVERSE_TAINT:
            chain = result.get("chain", [])
            if not chain:
                self.status_label.setText(f"反向污点分析无结果: {register}")
                return
            self.status_label.setText(
                f"反向污点分析完成: {register}，共 {len(chain)} 条指令"
            )
            self._show_reverse_taint_dialog(register, chain)
            return

        if mode == AnalysisThread.MODE_DATA_PROVENANCE:
            trace_result = result.get("trace_result", {})
            events = trace_result.get("events", [])
            message = trace_result.get("message", "")
            if not events:
                self.status_label.setText(f"数据来源追踪无结果: {register} ({message})")
                return
            self.status_label.setText(f"数据来源追踪完成: {register}，共 {len(events)} 条记录")
            self._show_data_provenance_dialog(register, trace_result)

    def on_analysis_error(self, error_msg: str):
        """Show background analysis failures."""
        errored_thread = self.sender()
        if errored_thread is not None and errored_thread is not self.analysis_thread:
            errored_thread.deleteLater()
            return

        if self.analysis_thread:
            self.analysis_thread.deleteLater()
        self.analysis_thread = None
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "分析失败", error_msg)
        self.status_label.setText("分析失败")

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

        app = QApplication.instance()
        theme = app.property("taTheme") if app is not None else "amber"
        if theme == "midnight":
            reg_color = QColor(116, 216, 255)
            changed_bg = QColor(22, 90, 133)
            changed_fg = QColor(245, 253, 255)
            changed_text = QColor(170, 232, 255)
            steady_text = QColor(207, 239, 255)
            empty_text = QColor(110, 143, 160)
        else:
            reg_color = QColor(106, 191, 255)
            changed_bg = QColor(185, 109, 15)
            changed_fg = QColor(255, 245, 215)
            changed_text = QColor(255, 216, 124)
            steady_text = QColor(255, 170, 92)
            empty_text = QColor(166, 145, 100)

        current_state, prev_state, changed_registers = self.register_calc.compute_state_for_display(index)
        
        
        self.register_table.setUpdatesEnabled(False)
        try:
            self.register_table.setRowCount(len(self.sorted_registers))
            
            for row, register in enumerate(self.sorted_registers):
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
                reg_item.setForeground(reg_color)
                self.register_table.setItem(row, 0, reg_item)
                
                
                x_item = QTableWidgetItem(x_value)
                if x_changed:
                    x_item.setBackground(changed_bg)
                    x_item.setForeground(changed_fg)
                elif x_value != x_prev:
                    x_item.setForeground(changed_text)
                else:
                    x_item.setForeground(steady_text)
                self.register_table.setItem(row, 1, x_item)
                
                
                if is_x_series:
                    w_item = QTableWidgetItem(w_value)
                    if w_changed:
                        w_item.setBackground(changed_bg)
                        w_item.setForeground(changed_fg)
                    elif w_value != w_prev:
                        w_item.setForeground(changed_text)
                    else:
                        w_item.setForeground(steady_text)
                    self.register_table.setItem(row, 2, w_item)
                else:
                    empty_item = QTableWidgetItem('')
                    empty_item.setForeground(empty_text)
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
    def _parse_possible_address(value: str) -> Optional[int]:
        """尽量把寄存器值解释成地址整数，用于在内存区展开字符串。"""
        text = (value or "").strip().lower()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None

    def _memory_bytes_per_row(self) -> int:
        """根据当前内存区宽度动态决定每行显示多少字节。"""
        if not self.memory_display:
            return 16

        viewport_width = max(
            0,
            self.memory_display.viewport().width(),
            self.memory_display.width() - 12,
        )
        metrics = self.memory_display.fontMetrics()
        char_width = max(1, metrics.horizontalAdvance("0"))
        viewport_chars = max(40, viewport_width // char_width)

        # 经验公式：地址/标记预留约 24 字符，HEX+ASCII 每字节约占 4 字符。
        raw_bytes = max(4, (viewport_chars - 24) // 4)
        capped = min(32, raw_bytes)
        aligned = max(4, (capped // 4) * 4)
        return aligned

    def _format_memory_block_lines(
        self,
        address_text: str,
        data_bytes: List[int],
        marker: str = "S",
    ) -> List[str]:
        """按当前内存区宽度把字节流切成规整内存行。"""
        lines: List[str] = []
        chunk_size = self._memory_bytes_per_row()
        base_addr = self._parse_possible_address(address_text)

        for offset in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[offset:offset + chunk_size]
            hex_data = " ".join(f"{byte:02X}" for byte in chunk)
            ascii_str = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            if base_addr is not None:
                address = f"0x{base_addr + offset:016x}"
            else:
                address = address_text if offset == 0 else f"{address_text}+0x{offset:x}"
            lines.append(f"{marker} {address:<18} {hex_data:<48} |{ascii_str}|")

        return lines

    def _build_string_memory_lines(self, string_hints: List[Tuple[str, str, str, str]]) -> List[str]:
        """把字符串注释同步成内存区里的规整块显示，避免打乱内存布局。"""
        lines: List[str] = []
        for reg, val, text, _hex_data in string_hints:
            data = text.encode("utf-8", errors="replace")
            base_addr = self._parse_possible_address(val)
            if not data:
                lines.append(f"S {val:<18} {'':<48} || [{reg}]")
                lines.append(f"    text: {text}")
                continue

            if base_addr is not None:
                addr_text = f"0x{base_addr:016x}"
            else:
                addr_text = val
            lines.append(f"[{reg}] base={addr_text} len={len(data)}")

            lines.extend(self._format_memory_block_lines(val, list(data), marker="S"))

            lines.append(f"    text: {text}")
            lines.append("")

        while lines and not lines[-1].strip():
            lines.pop()
        return lines

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
        string_memory_lines = self._build_string_memory_lines(string_hints)

        if instruction.memory_dump:
            lines = []
            for dump_line in instruction.memory_dump:
                marker = "*" if dump_line.is_modified else " "
                try:
                    data_bytes = [int(byte, 16) for byte in dump_line.data]
                except ValueError:
                    data_bytes = []
                if data_bytes:
                    lines.extend(self._format_memory_block_lines(dump_line.address, data_bytes, marker=marker))
                else:
                    lines.append(f"{marker} {dump_line.address}")
            if string_memory_lines:
                lines.append("")
                lines.append("String memory (from annotations):")
                lines.extend(string_memory_lines)
            if string_hints:
                lines.append("")
                lines.append("String annotations:")
                for reg, val, _text, hex_data in string_hints:
                    lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            self._highlight_memory_string_annotation(self.selected_register)
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
            if string_memory_lines:
                lines.append("")
                lines.append("String memory (from annotations):")
                lines.extend(string_memory_lines)
            if string_hints:
                lines.append("")
                lines.append("String annotations:")
                for reg, val, _text, hex_data in string_hints:
                    lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            self._highlight_memory_string_annotation(self.selected_register)
            return

        if string_hints:
            lines = ["String memory (from annotations):"]
            lines.extend(string_memory_lines)
            lines.append("")
            lines.append("String annotations:")
            for reg, val, _text, hex_data in string_hints:
                lines.append(f" - {reg}={val} -> {hex_data}")
            self.memory_display.setPlainText("\n".join(lines))
            self._highlight_memory_string_annotation(self.selected_register)
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
                self._highlight_memory_string_annotation(self.selected_register)

    def _highlight_memory_string_annotation(self, register: Optional[str]):
        """在右侧内存区中高亮当前寄存器对应的字符串注释。"""
        if not self.memory_display or not register:
            return

        target_patterns = [f"- {register}=", f"{register}="]
        document = self.memory_display.document()
        matched_cursor = None
        for pattern in target_patterns:
            cursor = document.find(pattern)
            if not cursor.isNull():
                matched_cursor = cursor
                break

        if matched_cursor is None:
            return
        line_cursor = QTextCursor(matched_cursor)
        line_cursor.movePosition(QTextCursor.StartOfLine)
        line_cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
        self.memory_display.setTextCursor(line_cursor)
        self.memory_display.ensureCursorVisible()

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

        self._start_analysis_thread(AnalysisThread.MODE_TRACE_SOURCE, register)

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
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"反向污点分析: {register}")
        self._configure_dialog_geometry(dialog, 1380, 760)
        layout = QVBoxLayout(dialog)

        summary = self._create_dialog_summary_label(
            f"目标寄存器: {register}，共回溯到 {len(chain)} 条指令，双击行可跳转，窗口会保持打开。"
        )
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
        self._configure_wrapped_item_view(table)

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

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

    def analyze_reverse_taint(self, register: Optional[str] = None):
        """analyze_reverse_taint function."""
        if self.selected_index < 0 or not self.register_calc:
            self.status_label.setText("请先选择一条指令")
            return

        target_register = register or self._current_selected_register()
        if not target_register:
            self.status_label.setText("请先在寄存器表格中选中目标寄存器")
            return

        self._start_analysis_thread(AnalysisThread.MODE_REVERSE_TAINT, target_register)

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
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"数据来源追踪: {register}")
        self._configure_dialog_geometry(dialog, 1480, 780)
        layout = QVBoxLayout(dialog)

        summary = self._create_dialog_summary_label(
            f"目标寄存器: {register}，共 {len(events)} 条记录（读取 -> 写入 -> 计算链）。双击可跳转，窗口会保持打开。"
        )
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
        self._configure_wrapped_item_view(table)

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

        table.cellDoubleClicked.connect(on_row_activated)
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

    def analyze_data_provenance(self, register: Optional[str] = None):
        """analyze_data_provenance function."""
        if self.selected_index < 0 or not self.register_calc:
            self.status_label.setText("请先选择一条指令")
            return

        target_register = register or self._current_selected_register()
        if not target_register:
            self.status_label.setText("请先在寄存器表格中选中目标寄存器")
            return

        self._start_analysis_thread(AnalysisThread.MODE_DATA_PROVENANCE, target_register)

    def select_register_in_table(self, register: str):
        """select_register_in_table function."""
        for row in range(self.register_table.rowCount()):
            item = self.register_table.item(row, 0)
            if item and item.text() == register:
                self.register_table.selectRow(row)
                self.register_table.scrollToItem(item)
                self.selected_register = register
                self._highlight_memory_string_annotation(register)
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
    def _selected_row_indices(table: QAbstractItemView) -> List[int]:
        selection_model = table.selectionModel()
        if selection_model is None:
            return []
        selected = sorted({index.row() for index in selection_model.selectedRows()})
        return selected

    def _copy_table_rows(self, table: QAbstractItemView, rows: Optional[List[int]] = None):
        model = table.model()
        if model is None or model.rowCount() == 0:
            return

        row_indices = rows if rows is not None else self._selected_row_indices(table)
        if not row_indices:
            row_indices = list(range(model.rowCount()))

        headers = []
        for c in range(model.columnCount()):
            header_text = model.headerData(c, Qt.Horizontal, Qt.DisplayRole)
            headers.append(str(header_text) if header_text is not None else f"col{c}")

        lines = ["\t".join(headers)]
        for r in row_indices:
            cells = []
            for c in range(model.columnCount()):
                value = model.data(model.index(r, c), Qt.DisplayRole)
                cells.append("" if value is None else str(value))
            lines.append("\t".join(cells))

        QApplication.clipboard().setText("\n".join(lines))

    def _bind_table_copy_actions(self, table: QAbstractItemView):
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
                model = table.model()
                if model is not None:
                    self._copy_table_rows(table, list(range(model.rowCount())))
            elif chosen == act_select_all:
                table.selectAll()

        table.customContextMenuRequested.connect(on_context_menu)

    def _configure_wrapped_item_view(self, table: QAbstractItemView):
        """Enable word wrap and auto row-height adjustment for popup result tables."""
        table.setObjectName("dialogResultsTable")
        if hasattr(table, "setWordWrap"):
            table.setWordWrap(True)
        if hasattr(table, "setTextElideMode"):
            table.setTextElideMode(Qt.ElideNone)
        if hasattr(table, "setAlternatingRowColors"):
            table.setAlternatingRowColors(True)
        header = table.horizontalHeader()
        vertical_header = table.verticalHeader()
        vertical_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        vertical_header.setDefaultSectionSize(24)

        if not getattr(table, "_adaptive_resize_hooked", False):
            def schedule_resize(*_args, current_table=table):
                QTimer.singleShot(0, current_table.resizeRowsToContents)

            header.sectionResized.connect(schedule_resize)
            table._adaptive_resize_hooked = True

        QTimer.singleShot(0, table.resizeRowsToContents)

    def _configure_compact_results_view(self, table: QTableView):
        """为大批量搜索结果弹窗使用轻量表格配置，避免自动换行导致卡顿。"""
        table.setObjectName("dialogResultsTable")
        table.setWordWrap(False)
        table.setTextElideMode(Qt.ElideRight)
        table.setAlternatingRowColors(True)
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        vertical_header = table.verticalHeader()
        vertical_header.setSectionResizeMode(QHeaderView.Fixed)
        vertical_header.setDefaultSectionSize(28)

    def _configure_dialog_geometry(
        self,
        dialog: QDialog,
        preferred_width: int,
        preferred_height: int,
        min_width: int = 760,
        min_height: int = 520,
    ):
        """Size popup dialogs relative to the current main window so smaller windows still fit."""
        dialog.setObjectName("floatingDialog")
        base_width = max(self.width(), min_width + 80)
        base_height = max(self.height(), min_height + 80)
        width = min(preferred_width, max(min_width, base_width - 80))
        height = min(preferred_height, max(min_height, base_height - 80))
        dialog.resize(width, height)
        dialog.setMinimumSize(min(width, min_width), min(height, min_height))
        dialog.setSizeGripEnabled(True)

    @staticmethod
    def _create_dialog_summary_label(text: str) -> QLabel:
        """Create a summary label that wraps naturally in narrower dialogs."""
        summary = QLabel(text)
        summary.setObjectName("dialogSummary")
        summary.setWordWrap(True)
        return summary

    def _make_result_column(
        self,
        header: str,
        key: str,
        sort_type: str = "text",
    ) -> Dict[str, Any]:
        def display(row: Dict[str, Any], data_key=key):
            return row.get(data_key, "")

        def sort_value(row: Dict[str, Any], data_key=key, data_sort=sort_type):
            value = row.get(data_key, "")
            if data_sort == "int":
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return -1
            if data_sort == "address":
                return self._address_sort_key(str(value))
            return str(value or "").lower()

        return {
            "header": header,
            "display": display,
            "sort": sort_value,
        }

    @staticmethod
    def _compact_byte_stream_text(value: Any) -> str:
        """将搜索结果里的原始字节流压缩成摘要，避免弹窗被大段 HEX 撑满。"""
        text = str(value or "").strip()
        if not text:
            return text

        compact = text.replace("...", "").strip()
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2})(?:\s+[0-9A-Fa-f]{2})+", compact):
            byte_count = len(re.findall(r"[0-9A-Fa-f]{2}", compact))
            suffix = "..." if "..." in text else ""
            return f"HEX {byte_count}B（已省略）{suffix}"
        return text

    def _make_compacted_bytes_result_column(
        self,
        header: str,
        key: str,
        sort_type: str = "text",
    ) -> Dict[str, Any]:
        def display(row: Dict[str, Any], data_key=key):
            return self._compact_byte_stream_text(row.get(data_key, ""))

        def sort_value(row: Dict[str, Any], data_key=key, data_sort=sort_type):
            value = row.get(data_key, "")
            if data_sort == "int":
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return -1
            if data_sort == "address":
                return self._address_sort_key(str(value))
            return str(value or "").lower()

        return {
            "header": header,
            "display": display,
            "sort": sort_value,
        }

    def _create_search_results_view(
        self,
        dialog: QDialog,
        columns: List[Dict[str, Any]],
        rows: List[Dict[str, Any]],
        jump_status_text: str,
        on_activate: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> QTableView:
        table = QTableView(dialog)
        model = SearchResultsTableModel(columns, rows, table)
        proxy = QSortFilterProxyModel(table)
        proxy.setSourceModel(model)
        proxy.setSortRole(Qt.UserRole)
        proxy.setDynamicSortFilter(False)
        table.setModel(proxy)
        self._bind_table_copy_actions(table)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(True)
        self._configure_compact_results_view(table)

        header = table.horizontalHeader()
        for column_index in range(len(columns)):
            header_name = str(columns[column_index].get("header", ""))
            stretch = header_name in {"指令", "详情", "数据", "字符串", "HEX", "命中位置"}
            header.setSectionResizeMode(
                column_index,
                QHeaderView.Stretch if stretch else QHeaderView.ResizeToContents,
            )

        def on_row_activated(proxy_index: QModelIndex):
            if not proxy_index.isValid():
                return
            source_index = proxy.mapToSource(proxy_index)
            instruction_index = model.instruction_index_at(source_index.row())
            if instruction_index >= 0:
                self.jump_to_instruction(instruction_index, add_history=True)
                self.status_label.setText(jump_status_text.format(index=instruction_index + 1))
                if on_activate is not None:
                    row_data = model._resolve_row(source_index.row())
                    QTimer.singleShot(0, lambda row_data=row_data: on_activate(row_data))

        table.doubleClicked.connect(on_row_activated)
        return table

    @staticmethod
    def _result_rows_count(rows) -> int:
        if isinstance(rows, list):
            return len(rows)
        if hasattr(rows, "row_count"):
            return int(rows.row_count())
        return 0

    def _show_address_matches_dialog(self, search_text: str, matches: list, truncated: bool = False):
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"地址全查: {search_text}")
        self._configure_dialog_geometry(dialog, 1150, 680)
        layout = QVBoxLayout(dialog)

        total_matches = self._result_rows_count(matches)
        summary_text = f"共找到 {total_matches} 条匹配，结果完整保留，双击任意行可跳转到对应指令，窗口会保持打开。"
        if truncated:
            summary_text += " 当前结果曾被后台截断。"
        summary = self._create_dialog_summary_label(summary_text)
        layout.addWidget(summary)

        columns = [
            self._make_result_column("行号", "line", "int"),
            self._make_result_column("指令地址", "instruction_address", "address"),
            self._make_result_column("类型", "access"),
            self._make_result_column("内存地址", "memory_address", "address"),
            self._make_compacted_bytes_result_column("数据", "data"),
        ]
        table = self._create_search_results_view(
            dialog,
            columns,
            matches,
            "地址全查跳转: 第 {index} 条指令",
        )
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

    def _show_offset_matches_dialog(self, query: str, matches: List[dict], truncated: bool = False):
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"偏移搜索: {query}")
        self._configure_dialog_geometry(dialog, 1380, 740)
        layout = QVBoxLayout(dialog)

        total_matches = self._result_rows_count(matches)
        summary_text = f"匹配模块偏移 {query}，共找到 {total_matches} 条结果，结果完整保留，双击可跳转，窗口会保持打开。"
        if truncated:
            summary_text += " 当前结果曾被后台截断。"
        summary = self._create_dialog_summary_label(summary_text)
        layout.addWidget(summary)

        columns = [
            self._make_result_column("行号", "line", "int"),
            self._make_result_column("指令地址", "instruction_address", "address"),
            self._make_result_column("偏移", "offset", "address"),
            self._make_result_column("助记符", "mnemonic"),
            self._make_result_column("指令", "instruction_text"),
            self._make_result_column("内存地址", "memory_address", "address"),
            self._make_compacted_bytes_result_column("详情", "data"),
        ]
        table = self._create_search_results_view(
            dialog,
            columns,
            matches,
            "偏移搜索跳转: 第 {index} 条指令",
        )
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

    def _show_data_matches_dialog(self, query: str, matches: List[dict], truncated: bool = False):
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"数据全查: {query}")
        self._configure_dialog_geometry(dialog, 1500, 760)
        layout = QVBoxLayout(dialog)

        total_matches = self._result_rows_count(matches)
        summary_text = f"匹配数据 {query}，共找到 {total_matches} 条结果，结果完整保留，双击可跳转，窗口会保持打开。"
        if truncated:
            summary_text += " 当前结果曾被后台截断。"
        summary = self._create_dialog_summary_label(summary_text)
        layout.addWidget(summary)

        columns = [
            self._make_result_column("行号", "line", "int"),
            self._make_result_column("指令地址", "instruction_address", "address"),
            self._make_result_column("偏移", "offset", "address"),
            self._make_result_column("助记符", "mnemonic"),
            self._make_result_column("指令", "instruction_text"),
            self._make_result_column("命中位置", "match_scope"),
            self._make_result_column("内存地址", "memory_address", "address"),
            self._make_compacted_bytes_result_column("详情", "data"),
        ]
        table = self._create_search_results_view(
            dialog,
            columns,
            matches,
            "数据全查跳转: 第 {index} 条指令",
        )
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

    def _show_string_matches_dialog(self, query: str, matches: List[dict], truncated: bool = False):
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"字符串全查: {query}")
        self._configure_dialog_geometry(dialog, 1560, 780)
        layout = QVBoxLayout(dialog)

        total_matches = self._result_rows_count(matches)
        summary_text = f"匹配字符串 {query}，共找到 {total_matches} 条结果，结果完整保留，双击可跳转，窗口会保持打开。"
        if truncated:
            summary_text += " 当前结果曾被后台截断。"
        summary = self._create_dialog_summary_label(summary_text)
        layout.addWidget(summary)

        columns = [
            self._make_result_column("行号", "line", "int"),
            self._make_result_column("指令地址", "instruction_address", "address"),
            self._make_result_column("偏移", "offset", "address"),
            self._make_result_column("助记符", "mnemonic"),
            self._make_result_column("指令", "instruction_text"),
            self._make_result_column("寄存器", "string_register"),
            self._make_result_column("寄存器值", "register_value"),
            self._make_result_column("字符串", "string_value"),
            self._make_compacted_bytes_result_column("HEX", "string_hex"),
        ]

        def activate_string_row(row_data: Dict[str, Any]):
            register = str(row_data.get("string_register", "") or "").upper()
            if register:
                self.select_register_in_table(register)

        table = self._create_search_results_view(
            dialog,
            columns,
            matches,
            "字符串全查跳转: 第 {index} 条指令",
            on_activate=activate_string_row,
        )
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

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
        self._start_search_thread(SearchThread.MODE_ADDRESS_ALL, search_text)

    def search_data_values(self):
        search_text = self.search_input.text().strip()
        if not search_text or not self.parser:
            return

        query = SearchThread._normalize_data_query(search_text)
        if not query:
            QMessageBox.information(
                self,
                "数据全查",
                "请输入要搜索的数据，例如 0x746d2a63。",
            )
            return

        self.status_label.setText(f"正在全量搜索数据: {query} ...")
        self._start_search_thread(SearchThread.MODE_DATA_ALL, query)

    def search_string_values(self):
        search_text = self.search_input.text().strip()
        if not search_text or not self.parser:
            return

        query = SearchThread._normalize_string_query(search_text)
        if not query:
            QMessageBox.information(
                self,
                "字符串全查",
                '请输入要搜索的字符串内容，例如 PR=A 或 "PR=A"。',
            )
            return

        self.status_label.setText(f"正在全量搜索字符串: {query} ...")
        self._start_search_thread(SearchThread.MODE_STRING_ALL, query)

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

    def _build_instruction_memory_summary(
        self,
        instruction: Optional[Instruction],
        fallback_text: str = "",
    ) -> Tuple[str, str]:
        if not instruction:
            detail_text = (fallback_text or "").strip()
            return "-", detail_text if detail_text else "-"

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

        detail_text = (fallback_text or "").strip()
        return "-", detail_text if detail_text else "-"

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

            full_info = self.parser.get_instruction_info(i, include_line_text=True)
            if not full_info:
                continue

            instruction = self.parser.parse_instruction_at(i)
            mem_addr, mem_data = self._build_instruction_memory_summary(
                instruction,
                full_info.comment,
            )
            matches.append({
                "index": i,
                "line": i + 1,
                "instruction_address": self._format_address_for_display(full_info.address),
                "mnemonic": full_info.mnemonic,
                "instruction_text": f"{full_info.mnemonic} {full_info.operands}".strip(),
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

    def _show_mnemonic_matches_dialog(self, query: str, matches: List[dict], truncated: bool = False):
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.setWindowTitle(f"指令全查: {query}")
        self._configure_dialog_geometry(dialog, 1320, 720)
        layout = QVBoxLayout(dialog)

        total_matches = self._result_rows_count(matches)
        summary_text = f"匹配助记符 `{query}`，共找到 {total_matches} 条结果，结果完整保留，双击可跳转，窗口会保持打开。"
        if truncated:
            summary_text += " 当前结果曾被后台截断。"
        summary = self._create_dialog_summary_label(summary_text)
        layout.addWidget(summary)

        columns = [
            self._make_result_column("行号", "line", "int"),
            self._make_result_column("指令地址", "instruction_address", "address"),
            self._make_result_column("助记符", "mnemonic"),
            self._make_result_column("指令", "instruction_text"),
            self._make_result_column("内存地址", "memory_address", "address"),
            self._make_compacted_bytes_result_column("详情", "data"),
        ]
        table = self._create_search_results_view(
            dialog,
            columns,
            matches,
            "指令全查跳转: 第 {index} 条指令",
        )
        layout.addWidget(table)
        self._show_persistent_dialog(dialog, table)

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
        self._start_search_thread(SearchThread.MODE_MNEMONIC_ALL, query)

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

            if SearchThread._is_probable_offset_query(search_text):
                self.status_label.setText(f"正在全量搜索偏移: {search_text} ...")
                self._start_search_thread(SearchThread.MODE_OFFSET_ALL, search_text)
                return

            start_index = self.selected_index + 1 if self.selected_index >= 0 else 0
            self._start_search_thread(SearchThread.MODE_FIND_FIRST, search_text, start_index)
            return

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
        QShortcut(QKeySequence("Ctrl+Shift+D"), self).activated.connect(self.search_data_values)
        QShortcut(QKeySequence("Ctrl+Shift+S"), self).activated.connect(self.search_string_values)
        QShortcut(QKeySequence("Ctrl+Shift+M"), self).activated.connect(self.search_instructions_by_mnemonic)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self.quick_data_provenance)
        QShortcut(QKeySequence("Ctrl+Shift+T"), self).activated.connect(self.quick_reverse_taint)
        QShortcut(QKeySequence("Ctrl+O"), self).activated.connect(self.load_file)
        QShortcut(QKeySequence("Ctrl+Shift+K"), self).activated.connect(self.clear_trace_cache)
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
        self._stop_search_thread()
        self._stop_analysis_thread()
        if self.cache_worker:
            self.cache_worker.stop()
        if self.parser:
            self.parser.close()
        if self.virtual_table:
            self.virtual_table.clear()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setProperty("taTheme", "amber")
    app.setStyleSheet(get_theme_stylesheet("amber"))
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    #.\venv\Scripts\Activate.ps1
    main()
