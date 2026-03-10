"""parser module."""

from typing import Dict, List, Optional, Tuple
import re


class RegisterChange:
    """RegisterChange class."""

    def __init__(self, register: str, old_value: str, new_value: str):
        self.register = register
        self.old_value = old_value
        self.new_value = new_value


class MemoryOperation:
    """MemoryOperation class."""

    def __init__(self, op_type: str, address: str, instruction_address: str, data_size: int, data_value: str):
        self.type = op_type
        self.address = address
        self.instruction_address = instruction_address
        self.data_size = data_size
        self.data_value = data_value


class MemoryDumpLine:
    """MemoryDumpLine class."""

    def __init__(self, address: str, data: List[str], is_modified: bool):
        self.address = address
        self.data = data
        self.is_modified = is_modified


class Instruction:
    """Instruction class."""

    def __init__(
        self,
        address: str,
        offset: str,
        mnemonic: str,
        operands: str,
        register_changes: List[RegisterChange],
        memory_ops: List[MemoryOperation],
        memory_dump: List[MemoryDumpLine],
        line_number: int,
        raw_line: str,
    ):
        self.address = address
        self.offset = offset
        self.mnemonic = mnemonic
        self.operands = operands
        self.register_changes = register_changes
        self.memory_ops = memory_ops
        self.memory_dump = memory_dump
        self.line_number = line_number
        self.raw_line = raw_line


def parse_register_changes(register_str: str) -> List[RegisterChange]:
    """parse_register_changes function."""
    changes: List[RegisterChange] = []
    if not register_str:
        return changes

    pattern = r"(\w+)=([^\s,]+?)\s*->\s*([^\s,]+)"
    for match in re.finditer(pattern, register_str):
        changes.append(
            RegisterChange(
                register=match.group(1).upper(),
                old_value=match.group(2),
                new_value=match.group(3),
            )
        )
    return changes


def _parse_register_assignments(register_str: str) -> Dict[str, str]:
    """_parse_register_assignments function."""
    assignments: Dict[str, str] = {}
    if not register_str:
        return assignments

    pattern = r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)"
    for match in re.finditer(pattern, register_str):
        reg = match.group(1).upper()
        value = match.group(2)
        assignments[reg] = value
    return assignments


def parse_register_changes_from_transition(before_str: str, after_str: str) -> List[RegisterChange]:
    """parse_register_changes_from_transition function."""
    before_map = _parse_register_assignments(before_str)
    after_map = _parse_register_assignments(after_str)

    changes: List[RegisterChange] = []
    for reg, new_value in after_map.items():
        old_value = before_map.get(reg, "")
        if old_value != new_value:
            changes.append(RegisterChange(reg, old_value, new_value))
    return changes


def parse_register_changes_from_line(line: str) -> List[RegisterChange]:
    """parse_register_changes_from_line function."""
    trimmed = line.strip()
    if not trimmed:
        return []

    semicolon_index = trimmed.find(";")
    if semicolon_index != -1:
        register_str = trimmed[semicolon_index + 1 :].strip()
        return parse_register_changes(register_str)

    trace_match = re.search(r':\s*"[^"]*"\s*(.*)$', trimmed)
    trace_part = trace_match.group(1).strip() if trace_match else trimmed
    if "=>" in trace_part:
        before_part, after_part = trace_part.split("=>", 1)
        return parse_register_changes_from_transition(before_part.strip(), after_part.strip())

    return []


def _parse_register_string_annotations(register_str: str) -> Dict[str, str]:
    """_parse_register_string_annotations function."""
    annotations: Dict[str, str] = {}
    if not register_str:
        return annotations

    pattern = r'\b([A-Za-z][\w.]*)\s*=\s*[^\s,]+\s*\(string:\s*"([^"]*)"\)'
    for match in re.finditer(pattern, register_str):
        reg = match.group(1).upper()
        string_value = match.group(2)
        annotations[reg] = string_value
    return annotations


def _string_to_hex_bytes(text: str) -> str:
    """_string_to_hex_bytes function."""
    if text is None:
        return ""
    data = text.encode("utf-8", errors="replace")
    return " ".join(f"{byte:02X}" for byte in data)


def _extract_trace_snapshots(line: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str]]:
    """_extract_trace_snapshots function."""
    trimmed = line.strip()
    trace_match = re.search(r':\s*"[^"]*"\s*(.*)$', trimmed)
    trace_part = trace_match.group(1).strip() if trace_match else trimmed
    if "=>" not in trace_part:
        return _extract_legacy_comment_snapshots(trimmed)
    before_part, after_part = trace_part.split("=>", 1)
    before_part = before_part.strip()
    after_part = after_part.strip()
    return (
        _parse_register_assignments(before_part),
        _parse_register_assignments(after_part),
        _parse_register_string_annotations(before_part),
        _parse_register_string_annotations(after_part),
    )


def _extract_legacy_comment_snapshots(
    line: str,
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str]]:
    """_extract_legacy_comment_snapshots function."""
    semicolon_index = line.find(";")
    if semicolon_index == -1:
        return {}, {}, {}, {}

    register_str = line[semicolon_index + 1 :].strip()
    if not register_str:
        return {}, {}, {}, {}

    before_map: Dict[str, str] = {}
    after_map: Dict[str, str] = {}

    transition_pattern = re.compile(r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+?)\s*->\s*([^\s,]+)")
    consumed_ranges: List[Tuple[int, int]] = []
    for match in transition_pattern.finditer(register_str):
        reg = match.group(1).upper()
        before_map[reg] = match.group(2)
        after_map[reg] = match.group(3)
        consumed_ranges.append((match.start(), match.end()))

    if consumed_ranges:
        chars = list(register_str)
        for start, end in consumed_ranges:
            for idx in range(start, end):
                chars[idx] = " "
        assignment_source = "".join(chars)
    else:
        assignment_source = register_str

    assignment_pattern = re.compile(r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)")
    for match in assignment_pattern.finditer(assignment_source):
        reg = match.group(1).upper()
        value = match.group(2)
        if reg not in before_map:
            before_map[reg] = value
        if reg not in after_map:
            after_map[reg] = value

    hints = _parse_register_string_annotations(register_str)
    return before_map, after_map, hints, hints


def _parse_int_token(token: str) -> Optional[int]:
    value = token.strip().rstrip("!").strip()
    if value.startswith("#"):
        value = value[1:].strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _lookup_reg_value(reg_name: str, before_map: Dict[str, str], after_map: Dict[str, str]) -> Optional[int]:
    reg = reg_name.upper()
    candidates = [reg]
    if reg == "FP":
        candidates.append("X29")
    elif reg == "LR":
        candidates.append("X30")
    elif reg.startswith("X") and reg[1:].isdigit():
        candidates.append("W" + reg[1:])
    elif reg.startswith("W") and reg[1:].isdigit():
        candidates.append("X" + reg[1:])

    for name in candidates:
        raw = before_map.get(name, "")
        parsed = _parse_int_token(raw) if raw else None
        if parsed is not None:
            return parsed

    for name in candidates:
        raw = after_map.get(name, "")
        parsed = _parse_int_token(raw) if raw else None
        if parsed is not None:
            return parsed

    return None


def _sign_extend_32(value: int) -> int:
    v = value & 0xFFFFFFFF
    if v & 0x80000000:
        return v - 0x100000000
    return v


def _register_width_bytes(reg_name: str) -> int:
    reg = reg_name.upper()
    if reg in ("SP", "FP", "LR") or (reg.startswith("X") and reg[1:].isdigit()):
        return 8
    if reg.startswith("W") and reg[1:].isdigit():
        return 4
    if reg.startswith("Q"):
        return 16
    if reg.startswith("D"):
        return 8
    if reg.startswith("S"):
        return 4
    if reg.startswith("H"):
        return 2
    if reg.startswith("B"):
        return 1
    return 8


def _extract_target_regs(operands: str) -> List[str]:
    if "[" not in operands:
        return []
    left = operands.split("[", 1)[0].strip().rstrip(",").strip()
    if not left:
        return []
    return [token.strip().upper() for token in left.split(",") if token.strip()]


def _infer_mem_size(mnemonic: str, target_regs: List[str]) -> int:
    m = mnemonic.lower()
    if m.startswith(("ldp", "stp", "ldnp", "stnp")) and target_regs:
        size = sum(_register_width_bytes(reg) for reg in target_regs[:2])
        return size if size > 0 else 16

    size = _register_width_bytes(target_regs[0]) if target_regs else 8
    if m.startswith(("ldrb", "strb")):
        return 1
    if m.startswith(("ldrh", "strh")):
        return 2
    if m.startswith("ldrsw"):
        return 4
    return size


def _format_data_values(
    target_regs: List[str],
    before_map: Dict[str, str],
    after_map: Dict[str, str],
    before_strings: Dict[str, str],
    after_strings: Dict[str, str],
    is_read: bool,
) -> str:
    if not target_regs:
        return ""

    source_map = after_map if is_read else before_map
    source_strings = after_strings if is_read else before_strings
    values: List[str] = []
    for reg in target_regs[:2]:
        raw = source_map.get(reg, "")
        if not raw:
            val = _lookup_reg_value(reg, before_map, after_map)
            if val is None:
                continue
            raw = f"0x{val & 0xFFFFFFFFFFFFFFFF:x}"
        text = f"{reg}={raw}"
        str_hint = source_strings.get(reg, "")
        if str_hint:
            text += f" (string_hex: {_string_to_hex_bytes(str_hint)})"
        values.append(text)
    return ", ".join(values)


def _compute_effective_address(operands: str, before_map: Dict[str, str], after_map: Dict[str, str]) -> Optional[int]:
    left_bracket = operands.find("[")
    right_bracket = operands.find("]", left_bracket + 1)
    if left_bracket < 0 or right_bracket < 0:
        return None

    inside = operands[left_bracket + 1:right_bracket].strip()
    if not inside:
        return None

    tokens = [token.strip() for token in inside.split(",") if token.strip()]
    if not tokens:
        return None

    base_reg = tokens[0].upper()
    base_value = _lookup_reg_value(base_reg, before_map, after_map)
    if base_value is None:
        return None

    offset = 0
    if len(tokens) >= 2:
        second = tokens[1]
        if second.startswith("#"):
            imm = _parse_int_token(second)
            if imm is not None:
                offset = imm
        else:
            index_reg = second.upper()
            index_val = _lookup_reg_value(index_reg, before_map, after_map)
            if index_val is None:
                index_val = 0

            extend_part = ",".join(tokens[2:]).lower()
            shift = 0
            shift_match = re.search(r"#\s*(-?0x[0-9a-fA-F]+|-?\d+)", extend_part)
            if shift_match:
                shift = int(shift_match.group(1), 0)

            if "sxtw" in extend_part:
                index_effective = _sign_extend_32(index_val)
            elif "uxtw" in extend_part:
                index_effective = index_val & 0xFFFFFFFF
            elif index_reg.startswith("W") and index_reg[1:].isdigit():
                index_effective = index_val & 0xFFFFFFFF
            else:
                index_effective = index_val

            if shift > 0:
                index_effective <<= shift
            offset = index_effective

    return (base_value + offset) & 0xFFFFFFFFFFFFFFFF


def infer_memory_operation_from_instruction(
    line: str,
    mnemonic: str,
    operands: str,
    instruction_address: str,
) -> Optional[MemoryOperation]:
    """infer_memory_operation_from_instruction function."""
    if "[" not in operands or "]" not in operands:
        return None

    m = mnemonic.lower()
    if not (m.startswith("ld") or m.startswith("st")):
        return None

    before_map, after_map, before_strings, after_strings = _extract_trace_snapshots(line)
    if not before_map and not after_map:
        return None

    address_int = _compute_effective_address(operands, before_map, after_map)
    if address_int is None:
        return None

    target_regs = _extract_target_regs(operands)
    is_read = m.startswith("ld")
    op_type = "read" if is_read else "write"
    data_size = _infer_mem_size(mnemonic, target_regs)
    data_value = _format_data_values(
        target_regs=target_regs,
        before_map=before_map,
        after_map=after_map,
        before_strings=before_strings,
        after_strings=after_strings,
        is_read=is_read,
    )

    return MemoryOperation(
        op_type=op_type,
        address=f"0x{address_int:x}",
        instruction_address=instruction_address,
        data_size=data_size,
        data_value=data_value,
    )


def parse_memory_operation(line: str) -> Optional[MemoryOperation]:
    """parse_memory_operation function."""
    write_pattern = (
        r"memory write at (0x[0-9a-f]+), instruction address = (0x[0-9a-f]+), "
        r"data size = (\d+), data value = ([0-9a-f]+)"
    )
    write_match = re.search(write_pattern, line, re.IGNORECASE)
    if write_match:
        return MemoryOperation(
            op_type="write",
            address=write_match.group(1),
            instruction_address=write_match.group(2),
            data_size=int(write_match.group(3)),
            data_value=write_match.group(4),
        )

    read_pattern = (
        r"memory read at (0x[0-9a-f]+), instruction address = (0x[0-9a-f]+), "
        r"data size = (\d+), data value = ([0-9a-f]+)"
    )
    read_match = re.search(read_pattern, line, re.IGNORECASE)
    if read_match:
        return MemoryOperation(
            op_type="read",
            address=read_match.group(1),
            instruction_address=read_match.group(2),
            data_size=int(read_match.group(3)),
            data_value=read_match.group(4),
        )

    return None


def parse_memory_dump_line(line: str) -> Optional[MemoryDumpLine]:
    """parse_memory_dump_line function."""
    trimmed = line.strip()
    if not trimmed:
        return None

    if not re.match(r"^[*\s]?[0-9a-f]+\s+[0-9a-f\s]+\|", trimmed, re.IGNORECASE):
        return None

    is_modified = trimmed.startswith("*")
    clean_line = trimmed[1:].strip() if is_modified else trimmed
    parts = clean_line.split()
    if len(parts) < 2:
        return None

    address = parts[0]
    hex_data: List[str] = []
    for part in parts[1:]:
        if part.startswith("|"):
            break
        if re.match(r"^[0-9a-f]{2}$", part, re.IGNORECASE):
            hex_data.append(part)

    return MemoryDumpLine(address=address, data=hex_data, is_modified=is_modified)


def parse_instruction_fields(line: str) -> Optional[Dict[str, str]]:
    """parse_instruction_fields function."""
    trimmed = line.strip()
    if not trimmed:
        return None

    if trimmed.startswith("0x"):
        parts = [p for p in re.split(r"\t+", trimmed) if p]
        if len(parts) < 3:
            return None

        address = parts[0]
        offset = parts[1]
        rest = "\t".join(parts[2:])

        semicolon_index = rest.find(";")
        if semicolon_index != -1:
            instruction_str = rest[:semicolon_index].strip()
            comment = rest[semicolon_index + 1 :].strip()
        else:
            instruction_str = rest.strip()
            comment = ""

        instruction_parts = instruction_str.split(maxsplit=1)
        mnemonic = instruction_parts[0] if instruction_parts else ""
        operands = instruction_parts[1] if len(instruction_parts) > 1 else ""

        return {
            "address": address,
            "offset": offset,
            "mnemonic": mnemonic,
            "operands": operands,
            "comment": comment,
        }

    sub_match = re.match(
        r'^(?:\[[^\]]+\]\s*)+\s*(0x[0-9a-fA-F]+):\s*"([^"]*)"(?:\s*(.*))?$',
        trimmed,
    )
    if not sub_match:
        return None

    address = sub_match.group(1)
    instruction_str = sub_match.group(2).strip()
    trace_comment = (sub_match.group(3) or "").strip()

    offset = ""
    for group in re.findall(r"\[([^\]]+)\]", trimmed):
        offset_match = re.search(r"(0x[0-9a-fA-F]+)\s*$", group)
        if offset_match:
            offset = offset_match.group(1)
            break
    if not offset:
        offset = address

    instruction_parts = instruction_str.split(maxsplit=1)
    mnemonic = instruction_parts[0] if instruction_parts else ""
    operands = instruction_parts[1] if len(instruction_parts) > 1 else ""

    return {
        "address": address,
        "offset": offset,
        "mnemonic": mnemonic,
        "operands": operands,
        "comment": trace_comment,
    }


def parse_instruction_line(line: str, line_number: int) -> Optional[Instruction]:
    """parse_instruction_line function."""
    fields = parse_instruction_fields(line)
    if not fields:
        return None

    inferred_mem_ops: List[MemoryOperation] = []
    inferred = infer_memory_operation_from_instruction(
        line=line,
        mnemonic=fields["mnemonic"],
        operands=fields["operands"],
        instruction_address=fields["address"],
    )
    if inferred:
        inferred_mem_ops.append(inferred)

    return Instruction(
        address=fields["address"],
        offset=fields["offset"],
        mnemonic=fields["mnemonic"],
        operands=fields["operands"],
        register_changes=parse_register_changes_from_line(line),
        memory_ops=inferred_mem_ops,
        memory_dump=[],
        line_number=line_number,
        raw_line=line,
    )


def parse_log_file(file_path: str) -> Tuple[List[Instruction], Optional[str]]:
    """parse_log_file function."""
    instructions: List[Instruction] = []
    initial_sp: Optional[str] = None

    current_instruction: Optional[Instruction] = None
    memory_dump_lines: List[MemoryDumpLine] = []
    memory_ops: List[MemoryOperation] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            trimmed = line.strip()

            if trimmed.startswith("Original SP:"):
                match = re.search(r"Original SP:\s*(0x[0-9a-f]+)", trimmed, re.IGNORECASE)
                if match:
                    initial_sp = match.group(1)
                continue

            if trimmed.startswith("Return value"):
                continue

            memory_op = parse_memory_operation(trimmed)
            if memory_op:
                memory_ops.append(memory_op)
                continue

            dump_line = parse_memory_dump_line(trimmed)
            if dump_line:
                memory_dump_lines.append(dump_line)
                continue

            instruction = parse_instruction_line(trimmed, line_num)
            if instruction:
                if current_instruction:
                    if memory_ops:
                        current_instruction.memory_ops = memory_ops
                    current_instruction.memory_dump = memory_dump_lines
                    instructions.append(current_instruction)

                current_instruction = instruction
                memory_ops = []
                memory_dump_lines = []

    if current_instruction:
        if memory_ops:
            current_instruction.memory_ops = memory_ops
        current_instruction.memory_dump = memory_dump_lines
        instructions.append(current_instruction)

    return instructions, initial_sp
