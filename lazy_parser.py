"""lazy_parser module."""

import bisect
import json
import mmap
import os
import re
import sys
import threading
from collections import OrderedDict
from pathlib import Path
from struct import Struct
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from parser import (
    Instruction,
    MemoryDumpLine,
    MemoryOperation,
    infer_memory_operation_from_instruction,
    parse_instruction_fields,
    parse_memory_dump_line,
    parse_memory_operation,
    parse_register_changes_from_line,
)
from register import Register, RegisterState


class InstructionIndex:
    """InstructionIndex class."""

    __slots__ = (
        "line_number",
        "file_offset",
        "next_file_offset",
        "address",
        "offset",
        "mnemonic",
        "operands",
        "comment",
    )

    def __init__(
        self,
        line_number: int,
        file_offset: int,
        address: str,
        offset: str,
        mnemonic: str,
        operands: str,
        comment: str = "",
        next_file_offset: Optional[int] = None,
    ):
        self.line_number = line_number
        self.file_offset = file_offset
        self.next_file_offset = next_file_offset
        self.address = address
        self.offset = offset
        self.mnemonic = mnemonic
        self.operands = operands
        self.comment = comment


class LazyLogParser:
    """LazyLogParser class."""

    INDEX_VERSION = 8
    INDEX_RECORD = Struct("<QQQH")
    MNEMONIC_POSTING_ENTRY = Struct("<I")
    OFFSET_POSTING_ENTRY = Struct("<I")
    REGISTER_WRITE_MASK_ENTRY = Struct("<I")
    REGISTER_POSTING_ENTRY = Struct("<I")
    MEMORY_ACCESS_ENTRY = Struct("<QIHBB")
    MEMORY_ACCESS_TEMP_ENTRY = Struct("<QIHBBI")

    CHECKPOINT_MAGIC = b"TRCP"
    CHECKPOINT_VERSION = 1
    CHECKPOINT_HEADER = Struct("<4sIIQ")
    CHECKPOINT_RECORD_HEADER = Struct("<QH")
    CHECKPOINT_REGISTER_ENTRY = Struct("<BQ")

    INVALID_HEX = (1 << 64) - 1
    CHECKPOINT_REGISTERS = [*(f"X{i}" for i in range(31)), "SP", "FP", "LR"]
    CHECKPOINT_REGISTER_IDS = {
        name: idx for idx, name in enumerate(CHECKPOINT_REGISTERS)
    }
    ANALYSIS_REGISTERS = [*(f"X{i}" for i in range(31)), "SP"]
    ANALYSIS_REGISTER_IDS = {
        name: idx for idx, name in enumerate(ANALYSIS_REGISTERS)
    }
    MEMORY_BUCKET_PREFIX_LEN = 6
    MEMORY_KIND_READ = 0
    MEMORY_KIND_WRITE = 1
    MEMORY_KIND_DUMP = 2
    MEMORY_KIND_DUMP_MODIFIED = 3

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = 0
        self.checkpoint_interval = 500
        self.initial_sp: Optional[str] = None
        self.prebuilt_checkpoints: Dict[int, RegisterState] = {}
        self.used_cached_index = False

        self._instruction_count = 0
        self._mnemonic_table: List[str] = []
        self._mnemonic_counts: List[int] = []
        self._mnemonic_offsets: List[int] = []
        self._offset_posting_counts: Dict[int, int] = {}
        self._offset_posting_offsets: Dict[int, int] = {}
        self._offset_posting_values: List[int] = []
        self._register_write_table: List[str] = []
        self._register_write_counts: List[int] = []
        self._register_write_offsets: List[int] = []
        self._memory_bucket_counts: Dict[int, int] = {}
        self._memory_bucket_offsets: Dict[int, int] = {}
        self._memory_bucket_ids: List[int] = []
        self._memory_record_count = 0
        self._memory_write_bucket_counts: Dict[int, int] = {}
        self._memory_write_bucket_offsets: Dict[int, int] = {}
        self._memory_write_bucket_ids: List[int] = []
        self._memory_write_record_count = 0

        self._instruction_cache: "OrderedDict[int, Instruction]" = OrderedDict()
        self._instruction_cache_max_size = 2048
        self._cache_lock = threading.Lock()

        self._info_cache: "OrderedDict[int, InstructionIndex]" = OrderedDict()
        self._info_cache_max_size = 4096
        self._info_cache_lock = threading.Lock()

        self._file_lock = threading.Lock()
        self._thread_files: Dict[int, object] = {}
        self._offset_postings_lock = threading.Lock()

        self._index_file = None
        self._index_mmap: Optional[mmap.mmap] = None
        self._mnemonic_postings_file = None
        self._mnemonic_postings_mmap: Optional[mmap.mmap] = None
        self._offset_postings_file = None
        self._offset_postings_mmap: Optional[mmap.mmap] = None
        self._register_postings_file = None
        self._register_postings_mmap: Optional[mmap.mmap] = None
        self._memory_postings_file = None
        self._memory_postings_mmap: Optional[mmap.mmap] = None
        self._memory_write_postings_file = None
        self._memory_write_postings_mmap: Optional[mmap.mmap] = None

        self._source_mmap_file = None
        self._source_mmap: Optional[mmap.mmap] = None
        self._source_mmap_lock = threading.Lock()

        self._index_base_path = Path(f"{self.file_path}.traceidx")
        self._index_data_path = Path(f"{self._index_base_path}.dat")
        self._index_meta_path = Path(f"{self._index_base_path}.json")
        self._checkpoint_data_path = Path(f"{self._index_base_path}.chk")
        self._mnemonic_postings_path = Path(f"{self._index_base_path}.mnx")
        self._offset_postings_path = Path(f"{self._index_base_path}.ofx")
        self._offset_postings_meta_path = Path(f"{self._index_base_path}.ofm")
        self._register_postings_path = Path(f"{self._index_base_path}.rgx")
        self._memory_postings_path = Path(f"{self._index_base_path}.mem")
        self._memory_write_postings_path = Path(f"{self._index_base_path}.mwr")
        self._legacy_offsets_path = Path(f"{self._index_base_path}.ofs")

    def build_index(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        checkpoint_interval: int = 500,
    ) -> Tuple[int, Optional[str]]:
        """Build the instruction index and seed register checkpoints."""
        print("Building instruction index...")

        self.close()
        source_stat = os.stat(self.file_path)
        self.file_size = source_stat.st_size
        self.checkpoint_interval = max(1, int(checkpoint_interval))
        self.initial_sp = None
        self.prebuilt_checkpoints.clear()
        self.used_cached_index = False
        self._instruction_count = 0
        self._mnemonic_table = []
        self._mnemonic_counts = []
        self._mnemonic_offsets = []
        self._offset_posting_counts = {}
        self._offset_posting_offsets = {}
        self._offset_posting_values = []
        self._register_write_table = list(self.ANALYSIS_REGISTERS)
        self._register_write_counts = []
        self._register_write_offsets = []
        self._memory_bucket_counts = {}
        self._memory_bucket_offsets = {}
        self._memory_bucket_ids = []
        self._memory_record_count = 0
        self._memory_write_bucket_counts = {}
        self._memory_write_bucket_offsets = {}
        self._memory_write_bucket_ids = []
        self._memory_write_record_count = 0

        with self._cache_lock:
            self._instruction_cache.clear()
        with self._info_cache_lock:
            self._info_cache.clear()

        if self._try_load_existing_index(source_stat):
            self.used_cached_index = True
            if progress_callback:
                progress_callback(self.file_size, self.file_size)
            print(f"[LazyLogParser] reused disk index, {self._instruction_count} instructions")
            return self._instruction_count, self.initial_sp

        if progress_callback:
            progress_callback(0, self.file_size)

        self._build_sidecar_index(source_stat, progress_callback)
        self._open_index_storage()

        print(
            f"[LazyLogParser] index ready, {self._instruction_count} instructions, "
            f"{len(self.prebuilt_checkpoints)} checkpoints"
        )
        return self._instruction_count, self.initial_sp

    def load_file_lines(self):
        """Compatibility shim retained for older call sites."""
        return None

    @staticmethod
    def _parse_hex_token(text: str) -> int:
        token = (text or "").strip().lower()
        if token.startswith("0x"):
            token = token[2:]
        if not token:
            return LazyLogParser.INVALID_HEX
        try:
            return int(token, 16)
        except ValueError:
            return LazyLogParser.INVALID_HEX

    @staticmethod
    def _format_hex_token(value: int) -> str:
        if value == LazyLogParser.INVALID_HEX:
            return ""
        return f"0x{value:x}"

    @staticmethod
    def _normalize_exact_address_query(query: str) -> str:
        token = (query or "").strip().lower()
        if not token.startswith("0x"):
            return ""
        body = token[2:]
        if len(body) < 8 or not re.fullmatch(r"[0-9a-f]+", body):
            return ""
        return f"0x{body}"

    @staticmethod
    def _normalize_hex_query(query: str) -> str:
        token = (query or "").strip().lower()
        if not token.startswith("0x"):
            return ""
        body = token[2:]
        if not body or not re.fullmatch(r"[0-9a-f]+", body):
            return ""
        return f"0x{body}"

    @classmethod
    def _canonical_analysis_register(cls, reg_name: str) -> Optional[str]:
        token = (reg_name or "").strip().upper()
        if not token or token in {"XZR", "WZR", "ZR"}:
            return None
        if token == "FP":
            token = "X29"
        elif token == "LR":
            token = "X30"
        elif token.startswith("W") and token[1:].isdigit():
            token = "X" + token[1:]

        if token == "SP":
            return "SP"
        if token.startswith("X") and token[1:].isdigit():
            reg_num = int(token[1:])
            if 0 <= reg_num <= 30:
                return token
        return None

    @classmethod
    def _normalize_memory_address_text(cls, address: str) -> str:
        value = (address or "").strip().lower()
        return value[2:] if value.startswith("0x") else value

    @classmethod
    def _memory_bucket_id_from_text(cls, address_text: str) -> Optional[int]:
        normalized = cls._normalize_memory_address_text(address_text)
        if not normalized or not re.fullmatch(r"[0-9a-f]+", normalized):
            return None
        prefix = normalized[: cls.MEMORY_BUCKET_PREFIX_LEN].ljust(
            cls.MEMORY_BUCKET_PREFIX_LEN,
            "0",
        )
        return int(prefix, 16)

    @classmethod
    def _memory_bucket_id_from_value(cls, address_value: int) -> int:
        normalized = f"{max(0, int(address_value)):x}"
        prefix = normalized[: cls.MEMORY_BUCKET_PREFIX_LEN].ljust(
            cls.MEMORY_BUCKET_PREFIX_LEN,
            "0",
        )
        return int(prefix, 16)

    def _build_sidecar_index(
        self,
        source_stat: os.stat_result,
        progress_callback: Optional[Callable[[int, int], None]],
    ):
        """Scan the trace once and persist compact sidecar indexes."""
        data_tmp = Path(f"{self._index_data_path}.tmp")
        meta_tmp = Path(f"{self._index_meta_path}.tmp")
        mnemonic_tmp = Path(f"{self._mnemonic_postings_path}.tmp")
        register_masks_tmp = Path(f"{self._register_postings_path}.mask.tmp")
        register_tmp = Path(f"{self._register_postings_path}.tmp")
        memory_tmp = Path(f"{self._memory_postings_path}.tmp")
        memory_write_tmp = Path(f"{self._memory_write_postings_path}.tmp")
        memory_raw_tmp = Path(f"{self._memory_postings_path}.raw.tmp")

        state = RegisterState()
        mnemonic_to_id: Dict[str, int] = {}
        mnemonic_table: List[str] = []
        mnemonic_counts: List[int] = []
        register_counts: List[int] = [0] * len(self.ANALYSIS_REGISTERS)
        memory_bucket_counts: Dict[int, int] = {}
        memory_write_bucket_counts: Dict[int, int] = {}
        progress_step = max(8 * 1024 * 1024, min(self.file_size, 64 * 1024 * 1024))
        next_progress = progress_step

        try:
            with (
                open(self.file_path, "rb") as source_file,
                open(data_tmp, "wb") as data_file,
                open(register_masks_tmp, "wb") as register_mask_file,
                open(memory_raw_tmp, "wb") as memory_raw_file,
            ):
                current_fields: Optional[Dict[str, str]] = None
                current_line = ""
                current_line_offset = 0
                current_memory_ops: List[MemoryOperation] = []
                current_memory_dump: List[MemoryDumpLine] = []

                def flush_current_instruction():
                    nonlocal current_fields
                    nonlocal current_line
                    nonlocal current_line_offset
                    nonlocal current_memory_ops
                    nonlocal current_memory_dump

                    if not current_fields:
                        return

                    mnemonic = sys.intern(current_fields["mnemonic"])
                    mnemonic_id = mnemonic_to_id.get(mnemonic)
                    if mnemonic_id is None:
                        mnemonic_id = len(mnemonic_table)
                        mnemonic_to_id[mnemonic] = mnemonic_id
                        mnemonic_table.append(mnemonic)
                        mnemonic_counts.append(0)

                    instruction_index = self._instruction_count
                    data_file.write(
                        self.INDEX_RECORD.pack(
                            int(current_line_offset),
                            self._parse_hex_token(current_fields["address"]),
                            self._parse_hex_token(current_fields["offset"]),
                            int(mnemonic_id),
                        )
                    )
                    self._instruction_count += 1
                    mnemonic_counts[mnemonic_id] += 1

                    register_mask = 0
                    for change in parse_register_changes_from_line(current_line):
                        state.update(change.register, change.new_value)
                        canonical_reg = self._canonical_analysis_register(change.register)
                        if canonical_reg is None:
                            continue
                        reg_id = self.ANALYSIS_REGISTER_IDS[canonical_reg]
                        register_mask |= 1 << reg_id

                    register_mask_file.write(
                        self.REGISTER_WRITE_MASK_ENTRY.pack(register_mask)
                    )
                    mask_bits = register_mask
                    while mask_bits:
                        lsb = mask_bits & -mask_bits
                        reg_id = lsb.bit_length() - 1
                        register_counts[reg_id] += 1
                        mask_bits ^= lsb

                    resolved_memory_ops = list(current_memory_ops)
                    if not resolved_memory_ops:
                        inferred = infer_memory_operation_from_instruction(
                            line=current_line,
                            mnemonic=current_fields["mnemonic"],
                            operands=current_fields["operands"],
                            instruction_address=current_fields["address"],
                        )
                        if inferred:
                            resolved_memory_ops.append(inferred)

                    for slot, mem_op in enumerate(resolved_memory_ops):
                        if slot >= 0x100:
                            break
                        address_value = self._parse_hex_token(mem_op.address)
                        if address_value == self.INVALID_HEX:
                            continue
                        bucket_id = self._memory_bucket_id_from_value(address_value)
                        kind = (
                            self.MEMORY_KIND_READ
                            if mem_op.type == "read"
                            else self.MEMORY_KIND_WRITE
                        )
                        memory_raw_file.write(
                            self.MEMORY_ACCESS_TEMP_ENTRY.pack(
                                address_value,
                                instruction_index,
                                max(0, min(int(mem_op.data_size), 0xFFFF)),
                                kind,
                                slot,
                                bucket_id,
                            )
                        )
                        memory_bucket_counts[bucket_id] = memory_bucket_counts.get(bucket_id, 0) + 1
                        self._memory_record_count += 1
                        if kind == self.MEMORY_KIND_WRITE:
                            memory_write_bucket_counts[bucket_id] = (
                                memory_write_bucket_counts.get(bucket_id, 0) + 1
                            )
                            self._memory_write_record_count += 1

                    for slot, dump_line in enumerate(current_memory_dump):
                        if slot >= 0x100:
                            break
                        address_value = self._parse_hex_token(dump_line.address)
                        if address_value == self.INVALID_HEX:
                            continue
                        bucket_id = self._memory_bucket_id_from_value(address_value)
                        kind = (
                            self.MEMORY_KIND_DUMP_MODIFIED
                            if dump_line.is_modified
                            else self.MEMORY_KIND_DUMP
                        )
                        memory_raw_file.write(
                            self.MEMORY_ACCESS_TEMP_ENTRY.pack(
                                address_value,
                                instruction_index,
                                max(0, min(len(dump_line.data), 0xFFFF)),
                                kind,
                                slot,
                                bucket_id,
                            )
                        )
                        memory_bucket_counts[bucket_id] = memory_bucket_counts.get(bucket_id, 0) + 1
                        self._memory_record_count += 1

                    if instruction_index % self.checkpoint_interval == 0:
                        self.prebuilt_checkpoints[instruction_index] = state.copy()

                    current_fields = None
                    current_line = ""
                    current_line_offset = 0
                    current_memory_ops = []
                    current_memory_dump = []

                while True:
                    line_offset = source_file.tell()
                    raw_line = source_file.readline()
                    if not raw_line:
                        break

                    line = raw_line.decode("utf-8", errors="ignore")
                    trimmed = line.strip()

                    if trimmed.startswith("Original SP:"):
                        match = re.search(r"Original SP:\s*(0x[0-9a-f]+)", trimmed, re.IGNORECASE)
                        if match:
                            self.initial_sp = match.group(1)
                        current_offset = source_file.tell()
                        if progress_callback and current_offset >= next_progress:
                            progress_callback(current_offset, self.file_size)
                            next_progress = current_offset + progress_step
                        continue

                    mem_op = parse_memory_operation(trimmed)
                    if mem_op and current_fields is not None:
                        current_memory_ops.append(mem_op)
                        current_offset = source_file.tell()
                        if progress_callback and current_offset >= next_progress:
                            progress_callback(current_offset, self.file_size)
                            next_progress = current_offset + progress_step
                        continue

                    dump_line = parse_memory_dump_line(trimmed)
                    if dump_line and current_fields is not None:
                        current_memory_dump.append(dump_line)
                        current_offset = source_file.tell()
                        if progress_callback and current_offset >= next_progress:
                            progress_callback(current_offset, self.file_size)
                            next_progress = current_offset + progress_step
                        continue

                    fields = parse_instruction_fields(trimmed)
                    if fields:
                        flush_current_instruction()
                        current_fields = fields
                        current_line = line
                        current_line_offset = line_offset

                    current_offset = source_file.tell()
                    if progress_callback and current_offset >= next_progress:
                        progress_callback(current_offset, self.file_size)
                        next_progress = current_offset + progress_step

                flush_current_instruction()

            mnemonic_offsets = self._build_mnemonic_postings(
                data_tmp,
                mnemonic_tmp,
                mnemonic_counts,
            )
            register_offsets = self._build_register_write_postings(
                register_masks_tmp,
                register_tmp,
                register_counts,
            )
            memory_bucket_offsets = self._build_memory_postings(
                memory_raw_tmp,
                memory_tmp,
                memory_bucket_counts,
            )
            memory_write_bucket_offsets = self._build_memory_postings(
                memory_raw_tmp,
                memory_write_tmp,
                memory_write_bucket_counts,
                allowed_kinds=(self.MEMORY_KIND_WRITE,),
            )

            meta = {
                "version": self.INDEX_VERSION,
                "instruction_count": self._instruction_count,
                "initial_sp": self.initial_sp,
                "source_size": self.file_size,
                "source_mtime_ns": source_stat.st_mtime_ns,
                "mnemonics": mnemonic_table,
                "mnemonic_counts": mnemonic_counts,
                "mnemonic_offsets": mnemonic_offsets,
                "register_writes": list(self.ANALYSIS_REGISTERS),
                "register_write_counts": register_counts,
                "register_write_offsets": register_offsets,
                "memory_record_count": self._memory_record_count,
                "memory_bucket_index": [
                    [bucket_id, memory_bucket_offsets[bucket_id], bucket_count]
                    for bucket_id, bucket_count in sorted(memory_bucket_counts.items())
                ],
                "memory_write_record_count": self._memory_write_record_count,
                "memory_write_bucket_index": [
                    [bucket_id, memory_write_bucket_offsets[bucket_id], bucket_count]
                    for bucket_id, bucket_count in sorted(memory_write_bucket_counts.items())
                ],
            }
            with open(meta_tmp, "w", encoding="utf-8") as meta_file:
                json.dump(meta, meta_file)

            os.replace(data_tmp, self._index_data_path)
            os.replace(meta_tmp, self._index_meta_path)
            os.replace(mnemonic_tmp, self._mnemonic_postings_path)
            os.replace(register_tmp, self._register_postings_path)
            os.replace(memory_tmp, self._memory_postings_path)
            os.replace(memory_write_tmp, self._memory_write_postings_path)

            self._mnemonic_table = mnemonic_table
            self._mnemonic_counts = mnemonic_counts
            self._mnemonic_offsets = mnemonic_offsets
            self._register_write_table = list(self.ANALYSIS_REGISTERS)
            self._register_write_counts = register_counts
            self._register_write_offsets = register_offsets
            self._memory_bucket_counts = dict(memory_bucket_counts)
            self._memory_bucket_offsets = memory_bucket_offsets
            self._memory_bucket_ids = sorted(memory_bucket_counts.keys())
            self._memory_write_bucket_counts = dict(memory_write_bucket_counts)
            self._memory_write_bucket_offsets = memory_write_bucket_offsets
            self._memory_write_bucket_ids = sorted(memory_write_bucket_counts.keys())
            self.save_checkpoint_sidecar(self.prebuilt_checkpoints, self.checkpoint_interval)

            if self._legacy_offsets_path.exists():
                try:
                    self._legacy_offsets_path.unlink()
                except OSError:
                    pass
        finally:
            for temp_path in (
                data_tmp,
                meta_tmp,
                mnemonic_tmp,
                register_masks_tmp,
                register_tmp,
                memory_tmp,
                memory_write_tmp,
                memory_raw_tmp,
            ):
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass

        if progress_callback:
            progress_callback(self.file_size, self.file_size)

    def _build_mnemonic_postings(
        self,
        data_path: Path,
        postings_path: Path,
        mnemonic_counts: List[int],
    ) -> List[int]:
        """Build per-mnemonic posting lists in trace order."""
        offsets: List[int] = []
        total = 0
        for count in mnemonic_counts:
            offsets.append(total)
            total += count

        if total == 0:
            with open(postings_path, "wb"):
                pass
            return offsets

        with open(data_path, "rb") as data_file, open(postings_path, "w+b") as postings_file:
            total_bytes = total * self.MNEMONIC_POSTING_ENTRY.size
            postings_file.truncate(total_bytes)
            postings_map = mmap.mmap(postings_file.fileno(), total_bytes, access=mmap.ACCESS_WRITE)
            try:
                positions = offsets.copy()
                for instruction_index in range(self._instruction_count):
                    raw_record = data_file.read(self.INDEX_RECORD.size)
                    if len(raw_record) != self.INDEX_RECORD.size:
                        raise OSError("incomplete mnemonic posting source data")
                    _, _, _, mnemonic_id = self.INDEX_RECORD.unpack(raw_record)
                    write_pos = positions[mnemonic_id] * self.MNEMONIC_POSTING_ENTRY.size
                    postings_map[write_pos:write_pos + self.MNEMONIC_POSTING_ENTRY.size] = (
                        self.MNEMONIC_POSTING_ENTRY.pack(instruction_index)
                    )
                    positions[mnemonic_id] += 1
                postings_map.flush()
            finally:
                postings_map.close()

        return offsets

    def _build_offset_postings(
        self,
        data_path: Path,
        postings_path: Path,
        meta_path: Path,
    ) -> Tuple[Dict[int, int], Dict[int, int], List[int]]:
        """Build exact-offset posting lists from the compact instruction index."""
        offset_counts: Dict[int, int] = {}
        with open(data_path, "rb") as data_file:
            for _instruction_index in range(self._instruction_count):
                raw_record = data_file.read(self.INDEX_RECORD.size)
                if len(raw_record) != self.INDEX_RECORD.size:
                    raise OSError("incomplete offset posting source data")
                _, _, offset_value, _ = self.INDEX_RECORD.unpack(raw_record)
                offset_value = int(offset_value)
                if offset_value == self.INVALID_HEX:
                    continue
                offset_counts[offset_value] = offset_counts.get(offset_value, 0) + 1

        offset_values = sorted(offset_counts.keys())
        posting_offsets: Dict[int, int] = {}
        total = 0
        for offset_value in offset_values:
            posting_offsets[offset_value] = total
            total += int(offset_counts[offset_value])

        if total == 0:
            with open(postings_path, "wb"):
                pass
        else:
            with open(data_path, "rb") as data_file, open(postings_path, "w+b") as postings_file:
                total_bytes = total * self.OFFSET_POSTING_ENTRY.size
                postings_file.truncate(total_bytes)
                postings_map = mmap.mmap(postings_file.fileno(), total_bytes, access=mmap.ACCESS_WRITE)
                try:
                    positions = dict(posting_offsets)
                    for instruction_index in range(self._instruction_count):
                        raw_record = data_file.read(self.INDEX_RECORD.size)
                        if len(raw_record) != self.INDEX_RECORD.size:
                            raise OSError("incomplete offset posting source data")
                        _, _, offset_value, _ = self.INDEX_RECORD.unpack(raw_record)
                        offset_value = int(offset_value)
                        if offset_value == self.INVALID_HEX:
                            continue
                        write_pos = positions[offset_value] * self.OFFSET_POSTING_ENTRY.size
                        postings_map[
                            write_pos:write_pos + self.OFFSET_POSTING_ENTRY.size
                        ] = self.OFFSET_POSTING_ENTRY.pack(instruction_index)
                        positions[offset_value] += 1
                    postings_map.flush()
                finally:
                    postings_map.close()

        meta = {
            "version": 1,
            "instruction_count": self._instruction_count,
            "source_size": self.file_size,
            "source_mtime_ns": int(os.stat(self.file_path).st_mtime_ns),
            "offset_index": [
                [int(offset_value), int(posting_offsets[offset_value]), int(offset_counts[offset_value])]
                for offset_value in offset_values
            ],
        }
        with open(meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(meta, meta_file)

        return offset_counts, posting_offsets, offset_values

    def _build_register_write_postings(
        self,
        mask_path: Path,
        postings_path: Path,
        register_counts: List[int],
    ) -> List[int]:
        """Build per-register write posting lists in trace order."""
        offsets: List[int] = []
        total = 0
        for count in register_counts:
            offsets.append(total)
            total += count

        if total == 0:
            with open(postings_path, "wb"):
                pass
            return offsets

        with open(mask_path, "rb") as mask_file, open(postings_path, "w+b") as postings_file:
            total_bytes = total * self.REGISTER_POSTING_ENTRY.size
            postings_file.truncate(total_bytes)
            postings_map = mmap.mmap(postings_file.fileno(), total_bytes, access=mmap.ACCESS_WRITE)
            try:
                positions = offsets.copy()
                for instruction_index in range(self._instruction_count):
                    raw_mask = mask_file.read(self.REGISTER_WRITE_MASK_ENTRY.size)
                    if len(raw_mask) != self.REGISTER_WRITE_MASK_ENTRY.size:
                        raise OSError("incomplete register posting source data")
                    mask_bits = self.REGISTER_WRITE_MASK_ENTRY.unpack(raw_mask)[0]
                    while mask_bits:
                        lsb = mask_bits & -mask_bits
                        reg_id = lsb.bit_length() - 1
                        write_pos = positions[reg_id] * self.REGISTER_POSTING_ENTRY.size
                        postings_map[
                            write_pos:write_pos + self.REGISTER_POSTING_ENTRY.size
                        ] = self.REGISTER_POSTING_ENTRY.pack(instruction_index)
                        positions[reg_id] += 1
                        mask_bits ^= lsb
                postings_map.flush()
            finally:
                postings_map.close()

        return offsets

    def _build_memory_postings(
        self,
        raw_path: Path,
        postings_path: Path,
        bucket_counts: Dict[int, int],
        allowed_kinds: Optional[Tuple[int, ...]] = None,
    ) -> Dict[int, int]:
        """Build per-address-prefix memory access postings in trace order."""
        offsets: Dict[int, int] = {}
        total = 0
        for bucket_id in sorted(bucket_counts.keys()):
            offsets[bucket_id] = total
            count = int(bucket_counts[bucket_id])
            total += count

        if total == 0:
            with open(postings_path, "wb"):
                pass
            return offsets

        with open(raw_path, "rb") as raw_file, open(postings_path, "w+b") as postings_file:
            total_bytes = total * self.MEMORY_ACCESS_ENTRY.size
            postings_file.truncate(total_bytes)
            postings_map = mmap.mmap(postings_file.fileno(), total_bytes, access=mmap.ACCESS_WRITE)
            try:
                positions = offsets.copy()
                allowed_kind_set = set(allowed_kinds) if allowed_kinds is not None else None
                while True:
                    raw_record = raw_file.read(self.MEMORY_ACCESS_TEMP_ENTRY.size)
                    if not raw_record:
                        break
                    if len(raw_record) != self.MEMORY_ACCESS_TEMP_ENTRY.size:
                        raise OSError("incomplete memory posting source data")
                    address_value, instruction_index, data_size, kind, slot, bucket_id = (
                        self.MEMORY_ACCESS_TEMP_ENTRY.unpack(raw_record)
                    )
                    if allowed_kind_set is not None and int(kind) not in allowed_kind_set:
                        continue
                    write_pos = positions[int(bucket_id)] * self.MEMORY_ACCESS_ENTRY.size
                    postings_map[
                        write_pos:write_pos + self.MEMORY_ACCESS_ENTRY.size
                    ] = self.MEMORY_ACCESS_ENTRY.pack(
                        address_value,
                        instruction_index,
                        data_size,
                        kind,
                        slot,
                    )
                    positions[int(bucket_id)] += 1
                postings_map.flush()
            finally:
                postings_map.close()

        return offsets

    def _try_load_existing_index(self, source_stat: os.stat_result) -> bool:
        """Reuse previously built sidecar indexes when the source is unchanged."""
        if not (
            self._index_meta_path.exists()
            and self._index_data_path.exists()
            and self._mnemonic_postings_path.exists()
            and self._register_postings_path.exists()
            and self._memory_postings_path.exists()
            and self._memory_write_postings_path.exists()
        ):
            return False

        try:
            with open(self._index_meta_path, "r", encoding="utf-8") as meta_file:
                meta = json.load(meta_file)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

        if meta.get("version") != self.INDEX_VERSION:
            return False
        if int(meta.get("source_size", -1)) != int(source_stat.st_size):
            return False
        if int(meta.get("source_mtime_ns", -1)) != int(source_stat.st_mtime_ns):
            return False

        self.initial_sp = meta.get("initial_sp")
        self._instruction_count = int(meta.get("instruction_count", 0))
        self._mnemonic_table = [sys.intern(item) for item in meta.get("mnemonics", [])]
        self._mnemonic_counts = [int(item) for item in meta.get("mnemonic_counts", [])]
        self._mnemonic_offsets = [int(item) for item in meta.get("mnemonic_offsets", [])]
        self._register_write_table = [str(item).upper() for item in meta.get("register_writes", [])]
        self._register_write_counts = [int(item) for item in meta.get("register_write_counts", [])]
        self._register_write_offsets = [int(item) for item in meta.get("register_write_offsets", [])]
        self._memory_bucket_counts = {}
        self._memory_bucket_offsets = {}
        self._memory_bucket_ids = []
        self._memory_record_count = int(meta.get("memory_record_count", 0))
        for bucket_entry in meta.get("memory_bucket_index", []):
            if not isinstance(bucket_entry, list) or len(bucket_entry) != 3:
                return False
            bucket_id, bucket_offset, bucket_count = bucket_entry
            bucket_id = int(bucket_id)
            if bucket_id < 0:
                return False
            self._memory_bucket_offsets[bucket_id] = int(bucket_offset)
            self._memory_bucket_counts[bucket_id] = int(bucket_count)
        self._memory_bucket_ids = sorted(self._memory_bucket_counts.keys())
        self._memory_write_bucket_counts = {}
        self._memory_write_bucket_offsets = {}
        self._memory_write_bucket_ids = []
        self._memory_write_record_count = int(meta.get("memory_write_record_count", 0))
        for bucket_entry in meta.get("memory_write_bucket_index", []):
            if not isinstance(bucket_entry, list) or len(bucket_entry) != 3:
                return False
            bucket_id, bucket_offset, bucket_count = bucket_entry
            bucket_id = int(bucket_id)
            if bucket_id < 0:
                return False
            self._memory_write_bucket_offsets[bucket_id] = int(bucket_offset)
            self._memory_write_bucket_counts[bucket_id] = int(bucket_count)
        self._memory_write_bucket_ids = sorted(self._memory_write_bucket_counts.keys())
        self.prebuilt_checkpoints = self._load_checkpoint_sidecar(self.checkpoint_interval)

        if len(self._mnemonic_table) != len(self._mnemonic_counts):
            return False
        if len(self._mnemonic_table) != len(self._mnemonic_offsets):
            return False
        if self._register_write_table != list(self.ANALYSIS_REGISTERS):
            return False
        if len(self._register_write_table) != len(self._register_write_counts):
            return False
        if len(self._register_write_table) != len(self._register_write_offsets):
            return False
        if sum(self._memory_bucket_counts.values()) != self._memory_record_count:
            return False
        if sum(self._memory_write_bucket_counts.values()) != self._memory_write_record_count:
            return False

        try:
            self._open_index_storage()
        except OSError:
            return False
        return True

    def _load_offset_postings_metadata(self, source_stat: Optional[os.stat_result] = None) -> bool:
        """Load lazily built exact-offset posting metadata when available."""
        if not (self._offset_postings_meta_path.exists() and self._offset_postings_path.exists()):
            return False

        try:
            with open(self._offset_postings_meta_path, "r", encoding="utf-8") as meta_file:
                meta = json.load(meta_file)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

        if int(meta.get("version", -1)) != 1:
            return False
        if int(meta.get("instruction_count", -1)) != self._instruction_count:
            return False
        if source_stat is not None and int(meta.get("source_size", -1)) != int(source_stat.st_size):
            return False
        if source_stat is not None and int(meta.get("source_mtime_ns", -1)) != int(source_stat.st_mtime_ns):
            return False

        offset_counts: Dict[int, int] = {}
        offset_offsets: Dict[int, int] = {}
        for offset_entry in meta.get("offset_index", []):
            if not isinstance(offset_entry, list) or len(offset_entry) != 3:
                return False
            offset_value, posting_offset, posting_count = offset_entry
            offset_value = int(offset_value)
            offset_offsets[offset_value] = int(posting_offset)
            offset_counts[offset_value] = int(posting_count)

        self._offset_posting_counts = offset_counts
        self._offset_posting_offsets = offset_offsets
        self._offset_posting_values = sorted(offset_counts.keys())
        return True

    def has_offset_postings_sidecar(self) -> bool:
        """Return whether exact-offset posting sidecars are already present."""
        return self._offset_postings_meta_path.exists() and self._offset_postings_path.exists()

    def _ensure_offset_postings(self, force_build: bool = True) -> bool:
        """Open or build the lazy exact-offset posting sidecar on demand."""
        acquired = self._offset_postings_lock.acquire(blocking=force_build)
        if not acquired:
            return False
        try:
            if self._offset_postings_mmap is not None:
                return True

            source_stat = os.stat(self.file_path)
            if not self._load_offset_postings_metadata(source_stat):
                if not force_build:
                    return False
                postings_tmp = Path(f"{self._offset_postings_path}.tmp")
                meta_tmp = Path(f"{self._offset_postings_meta_path}.tmp")
                try:
                    offset_counts, offset_offsets, offset_values = self._build_offset_postings(
                        self._index_data_path,
                        postings_tmp,
                        meta_tmp,
                    )
                    os.replace(postings_tmp, self._offset_postings_path)
                    os.replace(meta_tmp, self._offset_postings_meta_path)
                    self._offset_posting_counts = offset_counts
                    self._offset_posting_offsets = offset_offsets
                    self._offset_posting_values = offset_values
                finally:
                    for temp_path in (postings_tmp, meta_tmp):
                        if temp_path.exists():
                            try:
                                temp_path.unlink()
                            except OSError:
                                pass

            self._offset_postings_file = open(self._offset_postings_path, "rb")
            if os.path.getsize(self._offset_postings_path) > 0:
                self._offset_postings_mmap = mmap.mmap(
                    self._offset_postings_file.fileno(),
                    0,
                    access=mmap.ACCESS_READ,
                )
            else:
                self._offset_postings_mmap = None
            return True
        finally:
            self._offset_postings_lock.release()

    def _load_checkpoint_sidecar(self, expected_interval: int) -> Dict[int, RegisterState]:
        """Load persisted checkpoints that match the active checkpoint interval."""
        if not self._checkpoint_data_path.exists():
            return {}

        checkpoints: Dict[int, RegisterState] = {}
        try:
            with open(self._checkpoint_data_path, "rb") as checkpoint_file:
                header = checkpoint_file.read(self.CHECKPOINT_HEADER.size)
                if len(header) != self.CHECKPOINT_HEADER.size:
                    return {}

                magic, version, interval, checkpoint_count = self.CHECKPOINT_HEADER.unpack(header)
                if magic != self.CHECKPOINT_MAGIC or version != self.CHECKPOINT_VERSION:
                    return {}
                if int(interval) != int(expected_interval):
                    return {}

                for _ in range(int(checkpoint_count)):
                    record_header = checkpoint_file.read(self.CHECKPOINT_RECORD_HEADER.size)
                    if len(record_header) != self.CHECKPOINT_RECORD_HEADER.size:
                        return {}
                    checkpoint_index, register_count = self.CHECKPOINT_RECORD_HEADER.unpack(record_header)
                    state = RegisterState()
                    for _ in range(int(register_count)):
                        entry = checkpoint_file.read(self.CHECKPOINT_REGISTER_ENTRY.size)
                        if len(entry) != self.CHECKPOINT_REGISTER_ENTRY.size:
                            return {}
                        reg_id, reg_value = self.CHECKPOINT_REGISTER_ENTRY.unpack(entry)
                        if reg_id >= len(self.CHECKPOINT_REGISTERS):
                            continue
                        reg_name = self.CHECKPOINT_REGISTERS[reg_id]
                        state.registers[reg_name] = Register(reg_name, reg_value)
                    checkpoints[int(checkpoint_index)] = state
        except OSError:
            return {}

        return checkpoints

    def save_checkpoint_sidecar(
        self,
        checkpoints: Dict[int, RegisterState],
        checkpoint_interval: Optional[int] = None,
    ) -> bool:
        """Persist checkpoints to a compact reusable sidecar file."""
        if not checkpoints:
            return False

        target_interval = max(1, int(checkpoint_interval or self.checkpoint_interval))
        temp_path = Path(f"{self._checkpoint_data_path}.tmp")

        try:
            with open(temp_path, "wb") as checkpoint_file:
                checkpoint_file.write(
                    self.CHECKPOINT_HEADER.pack(
                        self.CHECKPOINT_MAGIC,
                        self.CHECKPOINT_VERSION,
                        target_interval,
                        len(checkpoints),
                    )
                )

                for checkpoint_index in sorted(checkpoints.keys()):
                    state = checkpoints[checkpoint_index]
                    register_items = []
                    for reg_name, reg in state.registers.items():
                        reg_id = self.CHECKPOINT_REGISTER_IDS.get(reg_name)
                        if reg_id is None:
                            continue
                        register_items.append((reg_id, reg.value))
                    register_items.sort(key=lambda item: item[0])

                    checkpoint_file.write(
                        self.CHECKPOINT_RECORD_HEADER.pack(
                            int(checkpoint_index),
                            len(register_items),
                        )
                    )
                    for reg_id, reg_value in register_items:
                        checkpoint_file.write(
                            self.CHECKPOINT_REGISTER_ENTRY.pack(reg_id, reg_value)
                        )

            os.replace(temp_path, self._checkpoint_data_path)
            return True
        except OSError:
            return False
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    def _open_index_storage(self):
        """Open the sidecar index files for random access."""
        self._close_index_storage()

        self._index_file = open(self._index_data_path, "rb")
        self._index_mmap = mmap.mmap(self._index_file.fileno(), 0, access=mmap.ACCESS_READ)

        self._mnemonic_postings_file = open(self._mnemonic_postings_path, "rb")
        if os.path.getsize(self._mnemonic_postings_path) > 0:
            self._mnemonic_postings_mmap = mmap.mmap(
                self._mnemonic_postings_file.fileno(),
                0,
                access=mmap.ACCESS_READ,
            )
        else:
            self._mnemonic_postings_mmap = None

        self._register_postings_file = open(self._register_postings_path, "rb")
        if os.path.getsize(self._register_postings_path) > 0:
            self._register_postings_mmap = mmap.mmap(
                self._register_postings_file.fileno(),
                0,
                access=mmap.ACCESS_READ,
            )
        else:
            self._register_postings_mmap = None

        self._memory_postings_file = open(self._memory_postings_path, "rb")
        if os.path.getsize(self._memory_postings_path) > 0:
            self._memory_postings_mmap = mmap.mmap(
                self._memory_postings_file.fileno(),
                0,
                access=mmap.ACCESS_READ,
            )
        else:
            self._memory_postings_mmap = None

        self._memory_write_postings_file = open(self._memory_write_postings_path, "rb")
        if os.path.getsize(self._memory_write_postings_path) > 0:
            self._memory_write_postings_mmap = mmap.mmap(
                self._memory_write_postings_file.fileno(),
                0,
                access=mmap.ACCESS_READ,
            )
        else:
            self._memory_write_postings_mmap = None

        if self._load_offset_postings_metadata():
            self._offset_postings_file = open(self._offset_postings_path, "rb")
            if os.path.getsize(self._offset_postings_path) > 0:
                self._offset_postings_mmap = mmap.mmap(
                    self._offset_postings_file.fileno(),
                    0,
                    access=mmap.ACCESS_READ,
                )
            else:
                self._offset_postings_mmap = None

    def _ensure_source_mmap(self):
        """Open a shared read-only mmap for fast address search."""
        with self._source_mmap_lock:
            if self._source_mmap is None:
                self._source_mmap_file = open(self.file_path, "rb")
                self._source_mmap = mmap.mmap(
                    self._source_mmap_file.fileno(),
                    0,
                    access=mmap.ACCESS_READ,
                )
            return self._source_mmap

    def _close_index_storage(self):
        """Close sidecar metadata and source mmap handles."""
        if self._offset_postings_mmap is not None:
            try:
                self._offset_postings_mmap.close()
            except OSError:
                pass
            self._offset_postings_mmap = None

        if self._offset_postings_file is not None:
            try:
                self._offset_postings_file.close()
            except OSError:
                pass
            self._offset_postings_file = None

        if self._memory_write_postings_mmap is not None:
            try:
                self._memory_write_postings_mmap.close()
            except OSError:
                pass
            self._memory_write_postings_mmap = None

        if self._memory_write_postings_file is not None:
            try:
                self._memory_write_postings_file.close()
            except OSError:
                pass
            self._memory_write_postings_file = None

        if self._memory_postings_mmap is not None:
            try:
                self._memory_postings_mmap.close()
            except OSError:
                pass
            self._memory_postings_mmap = None

        if self._memory_postings_file is not None:
            try:
                self._memory_postings_file.close()
            except OSError:
                pass
            self._memory_postings_file = None

        if self._register_postings_mmap is not None:
            try:
                self._register_postings_mmap.close()
            except OSError:
                pass
            self._register_postings_mmap = None

        if self._register_postings_file is not None:
            try:
                self._register_postings_file.close()
            except OSError:
                pass
            self._register_postings_file = None

        if self._mnemonic_postings_mmap is not None:
            try:
                self._mnemonic_postings_mmap.close()
            except OSError:
                pass
            self._mnemonic_postings_mmap = None

        if self._mnemonic_postings_file is not None:
            try:
                self._mnemonic_postings_file.close()
            except OSError:
                pass
            self._mnemonic_postings_file = None

        if self._index_mmap is not None:
            try:
                self._index_mmap.close()
            except OSError:
                pass
            self._index_mmap = None

        if self._index_file is not None:
            try:
                self._index_file.close()
            except OSError:
                pass
            self._index_file = None

        with self._source_mmap_lock:
            if self._source_mmap is not None:
                try:
                    self._source_mmap.close()
                except OSError:
                    pass
                self._source_mmap = None

            if self._source_mmap_file is not None:
                try:
                    self._source_mmap_file.close()
                except OSError:
                    pass
                self._source_mmap_file = None

    def _get_thread_file(self):
        thread_id = threading.get_ident()
        with self._file_lock:
            file_obj = self._thread_files.get(thread_id)
            if file_obj is None or file_obj.closed:
                file_obj = open(self.file_path, "rb", buffering=1024 * 1024)
                self._thread_files[thread_id] = file_obj
            return file_obj

    def _read_line_at(self, start_offset: int) -> str:
        file_obj = self._get_thread_file()
        file_obj.seek(start_offset)
        raw_line = file_obj.readline()
        return raw_line.decode("utf-8", errors="ignore") if raw_line else ""

    def _read_block_lines(self, start_offset: int, end_offset: Optional[int]) -> List[str]:
        file_obj = self._get_thread_file()
        file_obj.seek(start_offset)

        lines: List[str] = []
        while True:
            current_offset = file_obj.tell()
            if end_offset is not None and current_offset >= end_offset and lines:
                break

            raw_line = file_obj.readline()
            if not raw_line:
                break

            lines.append(raw_line.decode("utf-8", errors="ignore"))

        return lines

    def _get_cached_instruction(self, index: int) -> Optional[Instruction]:
        with self._cache_lock:
            instruction = self._instruction_cache.get(index)
            if instruction is None:
                return None
            self._instruction_cache.move_to_end(index)
            return instruction

    def _cache_instruction(self, index: int, instruction: Instruction):
        with self._cache_lock:
            self._instruction_cache[index] = instruction
            self._instruction_cache.move_to_end(index)
            while len(self._instruction_cache) > self._instruction_cache_max_size:
                self._instruction_cache.popitem(last=False)

    def _get_cached_info(self, index: int) -> Optional[InstructionIndex]:
        with self._info_cache_lock:
            info = self._info_cache.get(index)
            if info is None:
                return None
            self._info_cache.move_to_end(index)
            return info

    def _cache_info(self, index: int, info: InstructionIndex):
        with self._info_cache_lock:
            self._info_cache[index] = info
            self._info_cache.move_to_end(index)
            while len(self._info_cache) > self._info_cache_max_size:
                self._info_cache.popitem(last=False)

    def _read_record(self, index: int) -> Tuple[int, int, int, int]:
        if self._index_mmap is None:
            raise OSError("index map is not open")
        return self.INDEX_RECORD.unpack_from(self._index_mmap, index * self.INDEX_RECORD.size)

    def _next_instruction_offset(self, index: int) -> int:
        if index + 1 >= self._instruction_count:
            return self.file_size
        return self._read_record(index + 1)[0]

    def _build_summary_info(self, index: int) -> InstructionIndex:
        file_offset, address_value, offset_value, mnemonic_id = self._read_record(index)
        mnemonic = self._mnemonic_table[mnemonic_id] if 0 <= mnemonic_id < len(self._mnemonic_table) else ""
        return InstructionIndex(
            line_number=index + 1,
            file_offset=file_offset,
            next_file_offset=None,
            address=self._format_hex_token(address_value),
            offset=self._format_hex_token(offset_value),
            mnemonic=mnemonic,
            operands="",
            comment="",
        )

    def get_instruction_info(self, index: int, include_line_text: bool = False) -> Optional[InstructionIndex]:
        """Return instruction metadata, loading operands/comment only when needed."""
        if index < 0 or index >= self._instruction_count:
            return None

        if include_line_text:
            cached = self._get_cached_info(index)
            if cached is not None:
                return cached

        info = self._build_summary_info(index)
        if not include_line_text:
            return info

        instruction_line = self._read_line_at(info.file_offset)
        fields = parse_instruction_fields(instruction_line.strip())
        if fields:
            info.address = fields["address"]
            info.offset = fields["offset"]
            info.mnemonic = sys.intern(fields["mnemonic"])
            info.operands = fields["operands"]
            info.comment = fields["comment"]

        info.next_file_offset = self._next_instruction_offset(index)
        self._cache_info(index, info)
        return info

    def parse_instruction_at(self, index: int) -> Optional[Instruction]:
        """parse_instruction_at function."""
        if index < 0 or index >= self._instruction_count:
            return None

        cached = self._get_cached_instruction(index)
        if cached is not None:
            return cached

        info = self.get_instruction_info(index, include_line_text=True)
        if info is None:
            return None

        block_lines = self._read_block_lines(info.file_offset, info.next_file_offset)
        if not block_lines:
            return None

        instruction_line = block_lines[0]
        register_changes = parse_register_changes_from_line(instruction_line)

        memory_ops: List[MemoryOperation] = []
        memory_dump: List[MemoryDumpLine] = []

        for raw_line in block_lines[1:]:
            line_trimmed = raw_line.strip()
            if not line_trimmed:
                continue

            mem_op = parse_memory_operation(line_trimmed)
            if mem_op:
                memory_ops.append(mem_op)
                continue

            dump_line = parse_memory_dump_line(line_trimmed)
            if dump_line:
                memory_dump.append(dump_line)
                continue

            if parse_instruction_fields(line_trimmed):
                break

            break

        if not memory_ops:
            inferred = infer_memory_operation_from_instruction(
                line=instruction_line,
                mnemonic=info.mnemonic,
                operands=info.operands,
                instruction_address=info.address,
            )
            if inferred:
                memory_ops.append(inferred)

        instruction = Instruction(
            address=info.address,
            offset=info.offset,
            mnemonic=info.mnemonic,
            operands=info.operands,
            register_changes=register_changes,
            memory_ops=memory_ops,
            memory_dump=memory_dump,
            line_number=info.line_number,
            raw_line=instruction_line,
        )
        self._cache_instruction(index, instruction)
        return instruction

    def _matching_mnemonic_ids(self, prefix: str) -> List[int]:
        query = (prefix or "").strip().lower()
        if query.endswith("*"):
            query = query[:-1]
        if not query:
            return []
        return [
            idx
            for idx, mnemonic in enumerate(self._mnemonic_table)
            if mnemonic.lower().startswith(query)
        ]

    def count_instruction_indices_for_mnemonic_prefix(self, prefix: str) -> int:
        """Return how many instructions match a mnemonic prefix."""
        total = 0
        for mnemonic_id in self._matching_mnemonic_ids(prefix):
            if mnemonic_id < len(self._mnemonic_counts):
                total += self._mnemonic_counts[mnemonic_id]
        return total

    def get_mnemonic_prefix_segments(self, prefix: str) -> List[Tuple[int, int]]:
        """Return posting slices (offset, count) for a mnemonic prefix."""
        segments: List[Tuple[int, int]] = []
        for mnemonic_id in self._matching_mnemonic_ids(prefix):
            if mnemonic_id >= len(self._mnemonic_counts) or mnemonic_id >= len(self._mnemonic_offsets):
                continue
            count = self._mnemonic_counts[mnemonic_id]
            if count <= 0:
                continue
            segments.append((self._mnemonic_offsets[mnemonic_id], count))
        return segments

    def get_instruction_index_for_mnemonic_prefix_position(self, prefix: str, position: int) -> int:
        """Return the Nth instruction index matching a mnemonic prefix."""
        if self._mnemonic_postings_mmap is None or position < 0:
            return -1

        remaining = position
        for offset, count in self.get_mnemonic_prefix_segments(prefix):
            if remaining >= count:
                remaining -= count
                continue
            read_pos = (offset + remaining) * self.MNEMONIC_POSTING_ENTRY.size
            return self.MNEMONIC_POSTING_ENTRY.unpack_from(
                self._mnemonic_postings_mmap,
                read_pos,
            )[0]

        return -1

    def iter_instruction_indices_for_mnemonic_prefix(
        self,
        prefix: str,
        limit: Optional[int] = None,
    ) -> Iterator[int]:
        """Yield trace indices matching a mnemonic prefix from posting lists."""
        if self._mnemonic_postings_mmap is None:
            return

        yielded = 0
        for mnemonic_id in self._matching_mnemonic_ids(prefix):
            if mnemonic_id >= len(self._mnemonic_counts) or mnemonic_id >= len(self._mnemonic_offsets):
                continue
            count = self._mnemonic_counts[mnemonic_id]
            offset = self._mnemonic_offsets[mnemonic_id]
            for pos in range(count):
                read_pos = (offset + pos) * self.MNEMONIC_POSTING_ENTRY.size
                index = self.MNEMONIC_POSTING_ENTRY.unpack_from(
                    self._mnemonic_postings_mmap,
                    read_pos,
                )[0]
                yield index
                yielded += 1
                if limit is not None and yielded >= limit:
                    return

    def _register_posting_info(self, register: str) -> Optional[Tuple[int, int, int]]:
        canonical = self._canonical_analysis_register(register)
        if canonical is None:
            return None
        reg_id = self.ANALYSIS_REGISTER_IDS.get(canonical)
        if reg_id is None:
            return None
        if reg_id >= len(self._register_write_counts) or reg_id >= len(self._register_write_offsets):
            return None
        return reg_id, self._register_write_offsets[reg_id], self._register_write_counts[reg_id]

    def count_instruction_indices_for_register(self, register: str) -> int:
        """Return how many instructions write the requested register."""
        posting = self._register_posting_info(register)
        if posting is None:
            return 0
        return posting[2]

    def find_previous_write_to_register(self, register: str, before_index: int) -> int:
        """Find the last instruction index at or before `before_index` that writes `register`."""
        if self._register_postings_mmap is None:
            return -1

        posting = self._register_posting_info(register)
        if posting is None:
            return -1

        _, offset, count = posting
        if count <= 0:
            return -1

        target = min(before_index, self._instruction_count - 1)
        if target < 0:
            return -1

        low = 0
        high = count - 1
        best = -1
        while low <= high:
            mid = (low + high) // 2
            read_pos = (offset + mid) * self.REGISTER_POSTING_ENTRY.size
            mid_index = self.REGISTER_POSTING_ENTRY.unpack_from(
                self._register_postings_mmap,
                read_pos,
            )[0]
            if mid_index <= target:
                best = mid_index
                low = mid + 1
            else:
                high = mid - 1

        return best

    def _bucket_ids_for_numeric_range(
        self,
        bucket_ids: List[int],
        start: int,
        end: int,
    ) -> List[int]:
        left = bisect.bisect_left(bucket_ids, start)
        right = bisect.bisect_left(bucket_ids, end)
        return bucket_ids[left:right]

    def _memory_bucket_ids_for_query(self, query: str) -> List[int]:
        normalized = self._normalize_memory_address_text(query)
        if not normalized or not re.fullmatch(r"[0-9a-f]+", normalized):
            return []

        prefix_len = min(len(normalized), self.MEMORY_BUCKET_PREFIX_LEN)
        if prefix_len >= self.MEMORY_BUCKET_PREFIX_LEN:
            bucket_id = int(normalized[: self.MEMORY_BUCKET_PREFIX_LEN], 16)
            return [bucket_id] if bucket_id in self._memory_bucket_counts else []

        span = 16 ** (self.MEMORY_BUCKET_PREFIX_LEN - prefix_len)
        start = int(normalized, 16) * span
        end = start + span
        return self._bucket_ids_for_numeric_range(self._memory_bucket_ids, start, end)

    @staticmethod
    def _memory_address_value_matches_prefix(address_value: int, query: str) -> bool:
        normalized = LazyLogParser._normalize_memory_address_text(query)
        if not normalized:
            return False
        return f"{address_value:x}".startswith(normalized)

    def _read_memory_record_from_map(
        self,
        memory_map: Optional[mmap.mmap],
        record_index: int,
    ) -> Tuple[int, int, int, int, int]:
        if memory_map is None:
            raise OSError("memory posting map is not open")
        address_value, instruction_index, data_size, kind, slot = self.MEMORY_ACCESS_ENTRY.unpack_from(
            memory_map,
            record_index * self.MEMORY_ACCESS_ENTRY.size,
        )
        return instruction_index, address_value, data_size, kind, slot

    def _read_memory_record(self, record_index: int) -> Tuple[int, int, int, int, int]:
        return self._read_memory_record_from_map(self._memory_postings_mmap, record_index)

    def estimate_memory_record_candidates(self, query: str) -> int:
        """Estimate candidate memory records for an address prefix."""
        total = 0
        for bucket_id in self._memory_bucket_ids_for_query(query):
            total += self._memory_bucket_counts.get(bucket_id, 0)
        return total

    def iter_memory_records_for_address_prefix(
        self,
        query: str,
        limit: Optional[int] = None,
        kinds: Optional[Tuple[int, ...]] = None,
    ) -> Iterator[Tuple[int, int, int, int, int]]:
        """Yield memory records whose address matches the requested hex prefix."""
        if self._memory_postings_mmap is None:
            return

        query_norm = self._normalize_memory_address_text(query)
        if not query_norm or not re.fullmatch(r"[0-9a-f]+", query_norm):
            return

        kind_filter = set(kinds) if kinds is not None else None
        yielded = 0
        for bucket_id in self._memory_bucket_ids_for_query(query_norm):
            count = self._memory_bucket_counts.get(bucket_id, 0)
            if count <= 0:
                continue
            offset = self._memory_bucket_offsets[bucket_id]
            for pos in range(count):
                record = self._read_memory_record(offset + pos)
                instruction_index, address_value, _data_size, kind, _slot = record
                if kind_filter is not None and kind not in kind_filter:
                    continue
                if not self._memory_address_value_matches_prefix(address_value, query_norm):
                    continue
                yield record
                yielded += 1
                if limit is not None and yielded >= limit:
                    return

    def _find_memory_record_pos_for_instruction(
        self,
        memory_map: Optional[mmap.mmap],
        bucket_offset: int,
        bucket_count: int,
        target_index: int,
    ) -> int:
        low = 0
        high = bucket_count - 1
        best = -1

        while low <= high:
            mid = (low + high) // 2
            instruction_index, _, _, _, _ = self._read_memory_record_from_map(
                memory_map,
                bucket_offset + mid,
            )
            if instruction_index <= target_index:
                best = mid
                low = mid + 1
            else:
                high = mid - 1

        return best

    def find_next_instruction_index_by_memory_address(self, query: str, start_index: int = 0) -> int:
        """Find the next instruction touching a matching memory address prefix."""
        if self._memory_postings_mmap is None or self._instruction_count <= 0:
            return -1

        query_norm = self._normalize_memory_address_text(query)
        if not query_norm or not re.fullmatch(r"[0-9a-f]+", query_norm):
            return -1

        start = max(0, min(start_index, self._instruction_count - 1))
        bucket_ids = self._memory_bucket_ids_for_query(query_norm)
        best_after = -1
        best_wrap = -1

        for bucket_id in bucket_ids:
            count = self._memory_bucket_counts.get(bucket_id, 0)
            if count <= 0:
                continue
            offset = self._memory_bucket_offsets[bucket_id]
            start_pos = self._find_memory_record_pos_for_instruction(
                self._memory_postings_mmap,
                offset,
                count,
                start - 1,
            ) + 1
            for pos in range(start_pos, count):
                instruction_index, address_value, _, _, _ = self._read_memory_record(offset + pos)
                if self._memory_address_value_matches_prefix(address_value, query_norm):
                    if best_after < 0 or instruction_index < best_after:
                        best_after = instruction_index
                    break

            for pos in range(min(start_pos, count)):
                instruction_index, address_value, _, _, _ = self._read_memory_record(offset + pos)
                if self._memory_address_value_matches_prefix(address_value, query_norm):
                    if best_wrap < 0 or instruction_index < best_wrap:
                        best_wrap = instruction_index
                    break

        if best_after >= 0:
            return best_after
        return best_wrap

    def find_previous_memory_write(
        self,
        start_index: int,
        target_addr: int,
        target_size: int,
        target_bytes: Optional[bytes],
        max_records: int = 50000,
    ) -> Optional[Dict]:
        """Find the nearest prior write overlapping the requested address range."""
        if self._memory_write_postings_mmap is None or start_index < 0:
            return None

        access_window = max(16, target_size, 32)
        range_start = max(0, target_addr - access_window + 1)
        range_end = max(range_start, target_addr + max(1, target_size) - 1)
        start_bucket = self._memory_bucket_id_from_value(range_start)
        end_bucket = self._memory_bucket_id_from_value(range_end)
        bucket_ids = self._bucket_ids_for_numeric_range(
            self._memory_write_bucket_ids,
            start_bucket,
            end_bucket + 1,
        )

        state_entries: List[Dict[str, int]] = []
        for bucket_id in bucket_ids:
            count = self._memory_write_bucket_counts.get(bucket_id, 0)
            if count <= 0:
                continue
            offset = self._memory_write_bucket_offsets[bucket_id]
            pos = self._find_memory_record_pos_for_instruction(
                self._memory_write_postings_mmap,
                offset,
                count,
                start_index,
            )
            if pos < 0:
                continue
            record_index = offset + pos
            instruction_index, address_value, data_size, kind, slot = self._read_memory_record_from_map(
                self._memory_write_postings_mmap,
                record_index,
            )
            state_entries.append({
                "offset": offset,
                "pos": pos,
                "instruction_index": instruction_index,
                "address_value": address_value,
                "data_size": data_size,
                "kind": kind,
                "slot": slot,
            })

        scanned = 0
        while state_entries and scanned < max_records:
            state_entries.sort(key=lambda item: int(item["instruction_index"]), reverse=True)
            current = state_entries[0]
            scanned += 1

            instruction_index = int(current["instruction_index"])
            address_value = int(current["address_value"])
            data_size = int(current["data_size"])
            kind = int(current["kind"])
            slot = int(current["slot"])

            current["pos"] -= 1
            if current["pos"] >= 0:
                record_index = int(current["offset"]) + int(current["pos"])
                next_record = self._read_memory_record_from_map(
                    self._memory_write_postings_mmap,
                    record_index,
                )
                (
                    current["instruction_index"],
                    current["address_value"],
                    current["data_size"],
                    current["kind"],
                    current["slot"],
                ) = next_record
            else:
                state_entries.pop(0)

            if kind != self.MEMORY_KIND_WRITE:
                continue

            write_size = max(1, data_size)
            overlap_start = max(target_addr, address_value)
            overlap_end = min(target_addr + target_size, address_value + write_size)
            if overlap_end <= overlap_start:
                continue

            instruction = self.parse_instruction_at(instruction_index)
            if not instruction or slot >= len(instruction.memory_ops):
                continue
            op = instruction.memory_ops[slot]
            if op.type != "write":
                continue

            write_bytes = None
            source_regs: List[str] = []
            write_hex = ""
            if target_bytes is not None:
                from register_calc import RegisterCalculator

                write_bytes, source_regs, write_hex = RegisterCalculator._extract_store_value_bytes(
                    mnemonic=instruction.mnemonic,
                    operands=instruction.operands,
                    data_size=write_size,
                    data_value=op.data_value,
                )

                target_slice = target_bytes[
                    (overlap_start - target_addr):(overlap_end - target_addr)
                ]
                write_slice = (
                    write_bytes[(overlap_start - address_value):(overlap_end - address_value)]
                    if write_bytes is not None
                    else None
                )
                if write_slice is None or target_slice != write_slice:
                    continue
                match_type = (
                    "exact byte match"
                    if overlap_start == target_addr
                    and (overlap_end - overlap_start) == target_size
                    and target_size <= write_size
                    else "overlap byte match"
                )
            else:
                from register_calc import RegisterCalculator

                write_bytes, source_regs, write_hex = RegisterCalculator._extract_store_value_bytes(
                    mnemonic=instruction.mnemonic,
                    operands=instruction.operands,
                    data_size=write_size,
                    data_value=op.data_value,
                )
                match_type = "address overlap"

            return {
                "index": instruction_index,
                "instruction": instruction,
                "op": op,
                "address": address_value,
                "size": write_size,
                "value_bytes": write_bytes,
                "value_hex": write_hex,
                "match_type": match_type,
                "source_registers": source_regs,
            }

        return None

    def find_instruction_index_by_file_offset(self, file_offset: int) -> int:
        """Find the instruction index for an exact line offset, or nearest lower index."""
        low = 0
        high = self._instruction_count - 1
        best = -1

        while low <= high:
            mid = (low + high) // 2
            mid_offset = self._read_record(mid)[0]
            if mid_offset == file_offset:
                return mid
            if mid_offset < file_offset:
                best = mid
                low = mid + 1
            else:
                high = mid - 1

        return best

    def find_next_instruction_index_by_address(self, query: str, start_index: int = 0) -> int:
        """Find the next exact instruction-address match using source mmap search."""
        normalized = self._normalize_exact_address_query(query)
        if not normalized or self._instruction_count <= 0:
            return -1

        start = max(0, min(start_index, self._instruction_count - 1))
        start_info = self.get_instruction_info(start)
        start_offset = start_info.file_offset if start_info else 0

        source_map = self._ensure_source_mmap()
        query_bytes = normalized.encode("ascii", errors="ignore")
        ranges = [
            (start_offset, self.file_size),
            (0, start_offset),
        ]

        for range_start, range_end in ranges:
            pos = range_start
            while pos < range_end:
                found = source_map.find(query_bytes, pos, range_end)
                if found < 0:
                    break

                line_start = source_map.rfind(b"\n", range_start, found)
                line_start = 0 if line_start < 0 else line_start + 1
                line_end = source_map.find(b"\n", found, range_end)
                if line_end < 0:
                    line_end = range_end

                raw_line = bytes(source_map[line_start:line_end]).decode("utf-8", errors="ignore")
                fields = parse_instruction_fields(raw_line.strip())
                if fields and fields["address"].lower() == normalized:
                    index = self.find_instruction_index_by_file_offset(line_start)
                    if index >= 0:
                        return index

                pos = found + len(query_bytes)

        return -1

    def find_next_instruction_index_by_offset(self, query: str, start_index: int = 0) -> int:
        """Find the next instruction whose parsed offset matches the requested hex token."""
        normalized = self._normalize_hex_query(query)
        if not normalized or self._instruction_count <= 0:
            return -1
        if not self._ensure_offset_postings(force_build=False):
            return self._find_next_instruction_index_by_offset_source_scan(normalized, start_index)

        offset_value = self._parse_hex_token(normalized)
        count = self._offset_posting_counts.get(offset_value, 0)
        posting_offset = self._offset_posting_offsets.get(offset_value, -1)
        if count <= 0 or posting_offset < 0 or self._offset_postings_mmap is None:
            return -1

        start = max(0, min(start_index, self._instruction_count - 1))
        low = 0
        high = count - 1
        best_after = -1
        while low <= high:
            mid = (low + high) // 2
            read_pos = (posting_offset + mid) * self.OFFSET_POSTING_ENTRY.size
            mid_index = self.OFFSET_POSTING_ENTRY.unpack_from(
                self._offset_postings_mmap,
                read_pos,
            )[0]
            if mid_index < start:
                low = mid + 1
            else:
                best_after = mid
                high = mid - 1

        target_pos = best_after if best_after >= 0 else 0
        read_pos = (posting_offset + target_pos) * self.OFFSET_POSTING_ENTRY.size
        return self.OFFSET_POSTING_ENTRY.unpack_from(
            self._offset_postings_mmap,
            read_pos,
        )[0]

    def _find_next_instruction_index_by_offset_source_scan(self, normalized: str, start_index: int) -> int:
        """Fallback exact-offset search using source mmap scanning."""
        start = max(0, min(start_index, self._instruction_count - 1))
        start_info = self.get_instruction_info(start)
        start_offset = start_info.file_offset if start_info else 0

        source_map = self._ensure_source_mmap()
        query_bytes = normalized.encode("ascii", errors="ignore")
        patterns = (
            query_bytes + b"]",
            b"\t" + query_bytes + b"\t",
        )
        ranges = [
            (start_offset, self.file_size),
            (0, start_offset),
        ]

        for range_start, range_end in ranges:
            pos = range_start
            while pos < range_end:
                candidates = []
                for pattern in patterns:
                    found = source_map.find(pattern, pos, range_end)
                    if found >= 0:
                        candidates.append(found)

                if not candidates:
                    break

                found = min(candidates)
                line_start = source_map.rfind(b"\n", range_start, found)
                line_start = 0 if line_start < 0 else line_start + 1
                line_end = source_map.find(b"\n", found, range_end)
                if line_end < 0:
                    line_end = range_end

                raw_line = bytes(source_map[line_start:line_end]).decode("utf-8", errors="ignore")
                fields = parse_instruction_fields(raw_line.strip())
                if fields and fields["offset"].lower() == normalized:
                    index = self.find_instruction_index_by_file_offset(line_start)
                    if index >= 0:
                        return index

                pos = found + 1

        return -1

    def iter_instruction_indices_by_offset(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[int]:
        """Yield instruction indices whose parsed module offset exactly matches query."""
        normalized = self._normalize_hex_query(query)
        if not normalized or self._instruction_count <= 0:
            return
        if not self._ensure_offset_postings(force_build=False):
            yield from self._iter_instruction_indices_by_offset_source_scan(normalized, limit)
            return

        offset_value = self._parse_hex_token(normalized)
        count = self._offset_posting_counts.get(offset_value, 0)
        posting_offset = self._offset_posting_offsets.get(offset_value, -1)
        if count <= 0 or posting_offset < 0 or self._offset_postings_mmap is None:
            return

        yielded = 0
        for pos in range(count):
            read_pos = (posting_offset + pos) * self.OFFSET_POSTING_ENTRY.size
            yield self.OFFSET_POSTING_ENTRY.unpack_from(
                self._offset_postings_mmap,
                read_pos,
            )[0]
            yielded += 1
            if limit is not None and yielded >= limit:
                return

    def _iter_instruction_indices_by_offset_source_scan(
        self,
        normalized: str,
        limit: Optional[int] = None,
    ) -> Iterator[int]:
        """Fallback exact-offset scan using the source mmap."""
        source_map = self._ensure_source_mmap()
        query_bytes = normalized.encode("ascii", errors="ignore")
        patterns = (
            query_bytes + b"]",
            b"\t" + query_bytes + b"\t",
        )

        pos = 0
        emitted = 0
        last_line_start = -1
        while pos < self.file_size:
            candidates = []
            for pattern in patterns:
                found = source_map.find(pattern, pos, self.file_size)
                if found >= 0:
                    candidates.append(found)

            if not candidates:
                break

            found = min(candidates)
            line_start = source_map.rfind(b"\n", 0, found)
            line_start = 0 if line_start < 0 else line_start + 1
            if line_start == last_line_start:
                pos = found + 1
                continue
            last_line_start = line_start

            line_end = source_map.find(b"\n", found, self.file_size)
            if line_end < 0:
                line_end = self.file_size

            raw_line = bytes(source_map[line_start:line_end]).decode("utf-8", errors="ignore")
            fields = parse_instruction_fields(raw_line.strip())
            if fields and fields["offset"].lower() == normalized:
                index = self.find_instruction_index_by_file_offset(line_start)
                if index >= 0:
                    yield index
                    emitted += 1
                    if limit is not None and emitted >= limit:
                        return

            pos = found + 1

    def count_instruction_indices_for_offset(self, query: str) -> int:
        """Return how many instructions match an exact module offset."""
        normalized = self._normalize_hex_query(query)
        if not normalized or not self._ensure_offset_postings(force_build=False):
            return 0
        offset_value = self._parse_hex_token(normalized)
        return int(self._offset_posting_counts.get(offset_value, 0))

    def get_instruction_index_for_offset_position(self, query: str, position: int) -> int:
        """Return the Nth instruction index matching an exact module offset."""
        normalized = self._normalize_hex_query(query)
        if not normalized or position < 0 or not self._ensure_offset_postings(force_build=False):
            return -1

        offset_value = self._parse_hex_token(normalized)
        count = self._offset_posting_counts.get(offset_value, 0)
        posting_offset = self._offset_posting_offsets.get(offset_value, -1)
        if (
            count <= 0
            or posting_offset < 0
            or position >= count
            or self._offset_postings_mmap is None
        ):
            return -1

        read_pos = (posting_offset + position) * self.OFFSET_POSTING_ENTRY.size
        return self.OFFSET_POSTING_ENTRY.unpack_from(
            self._offset_postings_mmap,
            read_pos,
        )[0]

    def iter_instruction_indices_by_text_tokens(
        self,
        tokens: List[str],
        limit: Optional[int] = None,
    ) -> Iterator[int]:
        """Yield instruction indices whose raw source lines contain any requested token."""
        if self._instruction_count <= 0:
            return

        normalized_tokens: List[Tuple[str, bytes]] = []
        seen_tokens = set()
        for token in tokens:
            normalized = (token or "").strip().lower()
            if not normalized or normalized in seen_tokens:
                continue
            token_bytes = normalized.encode("utf-8", errors="ignore")
            if not token_bytes:
                continue
            seen_tokens.add(normalized)
            normalized_tokens.append((normalized, token_bytes))

        if not normalized_tokens:
            return

        source_map = self._ensure_source_mmap()
        yielded = 0
        seen_indices = set()

        for normalized, token_bytes in normalized_tokens:
            pos = 0
            last_line_start = -1
            step = max(1, len(token_bytes))
            while pos < self.file_size:
                found = source_map.find(token_bytes, pos, self.file_size)
                if found < 0:
                    break

                line_start = source_map.rfind(b"\n", 0, found)
                line_start = 0 if line_start < 0 else line_start + 1
                if line_start == last_line_start:
                    pos = found + step
                    continue
                last_line_start = line_start

                line_end = source_map.find(b"\n", found, self.file_size)
                if line_end < 0:
                    line_end = self.file_size

                raw_line = bytes(source_map[line_start:line_end]).decode("utf-8", errors="ignore")
                if normalized in raw_line.lower():
                    index = self.find_instruction_index_by_file_offset(line_start)
                    if index >= 0 and index not in seen_indices:
                        seen_indices.add(index)
                        yield index
                        yielded += 1
                        if limit is not None and yielded >= limit:
                            return

                pos = found + step

    def parse_batch(self, start_index: int, count: int) -> List[Instruction]:
        """parse_batch function."""
        instructions: List[Instruction] = []
        end_index = min(start_index + count, self._instruction_count)
        for i in range(start_index, end_index):
            instr = self.parse_instruction_at(i)
            if instr:
                instructions.append(instr)
        return instructions

    def get_instruction_count(self) -> int:
        """get_instruction_count function."""
        return self._instruction_count

    def get_prebuilt_checkpoints(self) -> Dict[int, RegisterState]:
        """Return a defensive copy of seeded checkpoints."""
        return {index: state.copy() for index, state in self.prebuilt_checkpoints.items()}

    def take_prebuilt_checkpoints(self) -> Dict[int, RegisterState]:
        """Transfer checkpoint ownership to the cache worker."""
        checkpoints = self.prebuilt_checkpoints
        self.prebuilt_checkpoints = {}
        return checkpoints

    def close(self):
        """Close any per-thread file handles."""
        with self._file_lock:
            for file_obj in self._thread_files.values():
                try:
                    file_obj.close()
                except OSError:
                    pass
            self._thread_files.clear()

        self._close_index_storage()
        with self._cache_lock:
            self._instruction_cache.clear()
        with self._info_cache_lock:
            self._info_cache.clear()
