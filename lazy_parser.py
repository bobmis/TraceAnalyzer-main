"""lazy_parser module."""

import re
from typing import List, Optional, Tuple

from parser import (
    Instruction,
    MemoryOperation,
    MemoryDumpLine,
    parse_instruction_fields,
    parse_register_changes_from_line,
    infer_memory_operation_from_instruction,
    parse_memory_operation,
    parse_memory_dump_line,
)


class InstructionIndex:
    """InstructionIndex class."""

    def __init__(
        self,
        line_number: int,
        file_offset: int,
        address: str,
        offset: str,
        mnemonic: str,
        operands: str,
        comment: str = "",
    ):
        self.line_number = line_number
        self.file_offset = file_offset
        self.address = address
        self.offset = offset
        self.mnemonic = mnemonic
        self.operands = operands
        self.comment = comment
        self.parsed_instruction: Optional[Instruction] = None


class LazyLogParser:
    """LazyLogParser class."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.instruction_indices: List[InstructionIndex] = []
        self.initial_sp: Optional[str] = None
        self._file_lines: Optional[List[str]] = None

    def build_index(self) -> Tuple[int, Optional[str]]:
        """build_index function."""
        print("Building instruction index...")

        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            current_offset = 0
            line_number = 0

            for line in f:
                line_number += 1
                line_len = len(line.encode("utf-8"))
                trimmed = line.strip()

                if trimmed.startswith("Original SP:"):
                    match = re.search(r"Original SP:\s*(0x[0-9a-f]+)", trimmed, re.IGNORECASE)
                    if match:
                        self.initial_sp = match.group(1)

                fields = parse_instruction_fields(trimmed)
                if fields:
                    self.instruction_indices.append(
                        InstructionIndex(
                            line_number=line_number,
                            file_offset=current_offset,
                            address=fields["address"],
                            offset=fields["offset"],
                            mnemonic=fields["mnemonic"],
                            operands=fields["operands"],
                            comment=fields["comment"],
                        )
                    )

                current_offset += line_len

        print(f"索引建立完成，共 {len(self.instruction_indices)} 条指令")
        return len(self.instruction_indices), self.initial_sp

    def load_file_lines(self):
        """load_file_lines function."""
        if self._file_lines is None:
            print("Loading file lines into memory...")
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                self._file_lines = f.readlines()
            print(f"文件已加载，共 {len(self._file_lines)} 行")

    def parse_instruction_at(self, index: int) -> Optional[Instruction]:
        """parse_instruction_at function."""
        if index < 0 or index >= len(self.instruction_indices):
            return None

        instr_index = self.instruction_indices[index]
        if instr_index.parsed_instruction is not None:
            return instr_index.parsed_instruction

        if self._file_lines is None:
            self.load_file_lines()

        line_num = instr_index.line_number - 1
        instruction_line = self._file_lines[line_num]
        register_changes = parse_register_changes_from_line(instruction_line)

        memory_ops: List[MemoryOperation] = []
        memory_dump: List[MemoryDumpLine] = []

        i = line_num + 1
        while i < len(self._file_lines):
            line_trimmed = self._file_lines[i].strip()

            if parse_instruction_fields(line_trimmed):
                break

            mem_op = parse_memory_operation(line_trimmed)
            if mem_op:
                memory_ops.append(mem_op)
                i += 1
                continue

            dump_line = parse_memory_dump_line(line_trimmed)
            if dump_line:
                memory_dump.append(dump_line)
                i += 1
                continue

            if not line_trimmed:
                i += 1
                continue

            break

        if not memory_ops:
            inferred = infer_memory_operation_from_instruction(
                line=instruction_line,
                mnemonic=instr_index.mnemonic,
                operands=instr_index.operands,
                instruction_address=instr_index.address,
            )
            if inferred:
                memory_ops.append(inferred)

        instruction = Instruction(
            address=instr_index.address,
            offset=instr_index.offset,
            mnemonic=instr_index.mnemonic,
            operands=instr_index.operands,
            register_changes=register_changes,
            memory_ops=memory_ops,
            memory_dump=memory_dump,
            line_number=instr_index.line_number,
            raw_line=instruction_line,
        )
        instr_index.parsed_instruction = instruction
        return instruction

    def parse_batch(self, start_index: int, count: int) -> List[Instruction]:
        """parse_batch function."""
        instructions: List[Instruction] = []
        end_index = min(start_index + count, len(self.instruction_indices))
        for i in range(start_index, end_index):
            instr = self.parse_instruction_at(i)
            if instr:
                instructions.append(instr)
        return instructions

    def get_instruction_count(self) -> int:
        """get_instruction_count function."""
        return len(self.instruction_indices)

    def get_instruction_info(self, index: int) -> Optional[InstructionIndex]:
        """get_instruction_info function."""
        if 0 <= index < len(self.instruction_indices):
            return self.instruction_indices[index]
        return None
