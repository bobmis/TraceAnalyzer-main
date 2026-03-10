"""register_calc module."""
import bisect
import time
import re
from typing import Dict, Optional, Set, List, Tuple, TYPE_CHECKING

from register import Register, RegisterState

if TYPE_CHECKING:
    from lazy_parser import LazyLogParser
    from cache_worker import CacheWorker


class RegisterCalculator:
    """RegisterCalculator class."""
    
    def __init__(self, parser: 'LazyLogParser', cache_worker: 'CacheWorker'):
        self.parser = parser
        self.cache_worker = cache_worker
        
        self._local_cache: Dict[int, RegisterState] = {}
        self._local_cache_max_size = 50
    
    def set_parser(self, parser: 'LazyLogParser'):
        """set_parser function."""
        self.parser = parser
        self._local_cache.clear()
    
    def compute_state_at(self, index: int, registers_to_show: Optional[Set[str]] = None) -> RegisterState:
        """compute_state_at function."""
        compute_start = time.time()
        
        if index < 0 or not self.parser:
            return RegisterState()
        
        if index in self._local_cache:
            return self._local_cache[index].copy()
        
        checkpoint_index = self.cache_worker.find_nearest_checkpoint(index)
        
        if checkpoint_index >= 0:
            checkpoint_state = self.cache_worker.get_checkpoint(checkpoint_index)
            if checkpoint_state:
                state = checkpoint_state.copy()
                start_index = checkpoint_index + 1
            else:
                state = RegisterState()
                start_index = 0
        else:
            state = RegisterState()
            start_index = 0
        
        instructions_processed = 0
        for i in range(start_index, index + 1):
            instruction = self.parser.parse_instruction_at(i)
            if instruction:
                for change in instruction.register_changes:
                    if registers_to_show is None:
                        state.update(change.register, change.new_value)
                    else:
                        normalized = Register.normalize_name(change.register)
                        if normalized in registers_to_show:
                            state.update(change.register, change.new_value)
                instructions_processed += 1
        
        self._add_to_local_cache(index, state.copy())
        
        compute_time = (time.time() - compute_start) * 1000
        if compute_time > 50:
            print(
                f"[RegisterCalc] compute index {index}, from checkpoint {checkpoint_index}, "
                f"processed {instructions_processed} instructions, took {compute_time:.1f}ms"
            )
        
        return state
    
    def compute_state_for_display(self, index: int) -> tuple:
        """compute_state_for_display function."""
        if index < 0 or not self.parser:
            return RegisterState(), RegisterState(), set()
        
        all_registers = self.get_all_arm64_registers()
        
        current_state = self.compute_state_at(index, all_registers)
        
        prev_state = RegisterState()
        if index > 0:
            prev_state = self.compute_state_at(index - 1, all_registers)
        
        changed_registers = set()
        instruction = self.parser.parse_instruction_at(index)
        if instruction:
            for change in instruction.register_changes:
                normalized = Register.normalize_name(change.register)
                changed_registers.add(normalized)
                if Register.is_w_register(change.register):
                    changed_registers.add('W_' + normalized)
                else:
                    changed_registers.add('X_' + normalized)
        
        return current_state, prev_state, changed_registers
    
    def trace_register_source(self, register: str, from_index: int) -> Optional[int]:
        """trace_register_source function."""
        if from_index < 0 or not self.parser:
            return None
        
        related_registers = self.get_related_registers(register)
        
        for i in range(from_index - 1, -1, -1):
            instruction = self.parser.parse_instruction_at(i)
            if instruction:
                for change in instruction.register_changes:
                    if change.register in related_registers:
                        return i
        
        return None

    @staticmethod
    def _normalize_taint_register(reg_name: str) -> Optional[str]:
        """_normalize_taint_register function."""
        if not reg_name:
            return None

        reg = reg_name.strip().upper()
        if reg in ['XZR', 'WZR', 'ZR']:
            return None
        if reg == 'FP':
            return 'X29'
        if reg == 'LR':
            return 'X30'
        if reg.startswith('W') and reg[1:].isdigit():
            return 'X' + reg[1:]
        if reg.startswith('X') and reg[1:].isdigit():
            return reg
        if reg == 'SP':
            return 'SP'
        return None

    @staticmethod
    def _extract_registers_from_operand_token(token: str) -> Set[str]:
        regs: Set[str] = set()
        for match in re.finditer(r'\b([xw]\d+|sp|fp|lr|xzr|wzr)\b', token, re.IGNORECASE):
            normalized = RegisterCalculator._normalize_taint_register(match.group(1))
            if normalized:
                regs.add(normalized)
        return regs

    @staticmethod
    def _extract_read_registers(mnemonic: str, operands: str, writes: Set[str]) -> Set[str]:
        """_extract_read_registers function."""
        read_regs: Set[str] = set()
        if not operands:
            return read_regs

        tokens = [t.strip() for t in operands.split(',') if t.strip()]
        token_regs: List[Set[str]] = []
        for tok in tokens:
            regs = RegisterCalculator._extract_registers_from_operand_token(tok)
            token_regs.append(regs)
            read_regs.update(regs)

        m = (mnemonic or '').lower()
        is_store = m.startswith('st')

        if not is_store and token_regs:
            dest_slots = 1
            if m.startswith('ldp') or m.startswith('ldnp'):
                dest_slots = 2

            for i in range(min(dest_slots, len(token_regs))):
                for reg in token_regs[i]:
                    if reg in writes:
                        read_regs.discard(reg)

        return read_regs

    def reverse_taint_trace(self, register: str, from_index: int, max_steps: int = 300) -> List[Dict]:
        """reverse_taint_trace function."""
        if from_index < 0 or not self.parser:
            return []

        target = self._normalize_taint_register(register)
        if not target:
            return []

        tainted: Set[str] = {target}
        chain: List[Dict] = []

        for i in range(from_index, -1, -1):
            instruction = self.parser.parse_instruction_at(i)
            if not instruction:
                continue

            writes = {
                normalized
                for change in instruction.register_changes
                for normalized in [self._normalize_taint_register(change.register)]
                if normalized
            }
            if not writes:
                continue

            hit_writes = tainted & writes
            if not hit_writes:
                continue

            taint_before = set(tainted)
            read_regs = self._extract_read_registers(
                instruction.mnemonic,
                instruction.operands,
                writes
            )

            tainted = (tainted - hit_writes) | read_regs

            chain.append({
                'index': i,
                'address': instruction.address,
                'mnemonic': instruction.mnemonic,
                'operands': instruction.operands,
                'hit_writes': sorted(hit_writes),
                'read_regs': sorted(read_regs),
                'taint_before': sorted(taint_before),
                'taint_after': sorted(tainted),
            })

            if len(chain) >= max_steps:
                break
            if not tainted:
                break

        return chain

    @staticmethod
    def _parse_int_value(text: str) -> Optional[int]:
        token = (text or "").strip().rstrip(",")
        if not token:
            return None
        if token.startswith("#"):
            token = token[1:].strip()
        try:
            return int(token, 0)
        except ValueError:
            return None

    @staticmethod
    def _parse_hex_bytes(text: str) -> Optional[bytes]:
        token = (text or "").strip()
        if not token:
            return None
        compact = re.sub(r"\s+", "", token)
        if compact.startswith("0x") or compact.startswith("0X"):
            compact = compact[2:]
        if not compact or len(compact) % 2 != 0:
            return None
        if not re.fullmatch(r"[0-9a-fA-F]+", compact):
            return None
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return None

    @staticmethod
    def _parse_reg_assignments(text: str) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for match in re.finditer(r"\b([A-Za-z][\w.]*)\s*=\s*([^\s,]+)", text or ""):
            reg = match.group(1).upper()
            value = RegisterCalculator._parse_int_value(match.group(2))
            if value is not None:
                result[reg] = value
        return result

    @staticmethod
    def _related_register_names(register: Optional[str]) -> Set[str]:
        if not register:
            return set()
        reg = register.strip().upper()
        names = {reg}
        if reg == "FP":
            names.add("X29")
        elif reg == "LR":
            names.add("X30")
        elif reg == "X29":
            names.add("FP")
        elif reg == "X30":
            names.add("LR")
        if reg.startswith("X") and reg[1:].isdigit():
            names.add("W" + reg[1:])
        elif reg.startswith("W") and reg[1:].isdigit():
            names.add("X" + reg[1:])
        return names

    @staticmethod
    def _assignment_value_for_register(assignments: Dict[str, int], register: Optional[str]) -> Optional[int]:
        for name in RegisterCalculator._related_register_names(register):
            if name in assignments:
                return assignments[name]
        return None

    @staticmethod
    def _register_width_bytes(register: str) -> int:
        reg = (register or "").upper()
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

    @staticmethod
    def _access_unit_size(mnemonic: str, register: str) -> int:
        m = (mnemonic or "").lower()
        if m.startswith(("ldrb", "strb")):
            return 1
        if m.startswith(("ldrh", "strh")):
            return 2
        if m.startswith("ldrsw"):
            return 4
        return RegisterCalculator._register_width_bytes(register)

    @staticmethod
    def _extract_target_regs(operands: str) -> List[str]:
        if "[" not in operands:
            return []
        left = operands.split("[", 1)[0].strip().rstrip(",").strip()
        if not left:
            return []
        return [item.strip().upper() for item in left.split(",") if item.strip()]

    @staticmethod
    def _extract_store_value_bytes(
        mnemonic: str,
        operands: str,
        data_size: int,
        data_value: str,
    ) -> Tuple[Optional[bytes], List[str], str]:
        raw_bytes = RegisterCalculator._parse_hex_bytes(data_value)
        if raw_bytes is not None:
            sized = raw_bytes[: data_size] if data_size > 0 else raw_bytes
            return sized, [], sized.hex(" ").upper()

        assignments = RegisterCalculator._parse_reg_assignments(data_value)
        regs = RegisterCalculator._extract_target_regs(operands)
        stream = bytearray()
        used_regs: List[str] = []
        for reg in regs:
            value = RegisterCalculator._assignment_value_for_register(assignments, reg)
            if value is None:
                continue
            unit_size = RegisterCalculator._access_unit_size(mnemonic, reg)
            if unit_size <= 0:
                continue
            mask = (1 << (unit_size * 8)) - 1
            stream.extend((value & mask).to_bytes(unit_size, byteorder="little", signed=False))
            used_regs.append(reg)

        if not stream and assignments:
            first_reg, first_value = next(iter(assignments.items()))
            unit_size = max(1, data_size)
            mask = (1 << (unit_size * 8)) - 1
            stream.extend((first_value & mask).to_bytes(unit_size, byteorder="little", signed=False))
            used_regs.append(first_reg)

        if not stream:
            return None, [], ""

        sized = bytes(stream[: data_size]) if data_size > 0 else bytes(stream)
        return sized, used_regs, sized.hex(" ").upper()

    @staticmethod
    def _extract_load_value_bytes(
        mnemonic: str,
        operands: str,
        data_size: int,
        data_value: str,
        focus_register: Optional[str],
    ) -> Tuple[Optional[bytes], int, Optional[str], str]:
        raw_bytes = RegisterCalculator._parse_hex_bytes(data_value)
        assignments = RegisterCalculator._parse_reg_assignments(data_value)
        target_regs = RegisterCalculator._extract_target_regs(operands)

        focus_aliases = RegisterCalculator._related_register_names(focus_register)
        chosen_reg: Optional[str] = None
        if target_regs and focus_aliases:
            for reg in target_regs:
                if reg in focus_aliases:
                    chosen_reg = reg
                    break
        if chosen_reg is None and target_regs:
            chosen_reg = target_regs[0]
        if chosen_reg is None and focus_register and focus_aliases:
            chosen_reg = next(iter(focus_aliases))

        offset = 0
        if target_regs and chosen_reg in target_regs:
            reg_pos = target_regs.index(chosen_reg)
            for reg in target_regs[:reg_pos]:
                offset += RegisterCalculator._access_unit_size(mnemonic, reg)

        unit_size = max(1, data_size)
        if chosen_reg:
            unit_size = RegisterCalculator._access_unit_size(mnemonic, chosen_reg)
            if data_size > 0:
                unit_size = min(unit_size, max(1, data_size - offset))

        if assignments and chosen_reg:
            value = RegisterCalculator._assignment_value_for_register(assignments, chosen_reg)
            if value is not None:
                mask = (1 << (unit_size * 8)) - 1
                b = (value & mask).to_bytes(unit_size, byteorder="little", signed=False)
                return b, offset, chosen_reg, b.hex(" ").upper()

        if raw_bytes is not None:
            if offset < len(raw_bytes):
                end = offset + unit_size
                b = raw_bytes[offset:end]
                return b, offset, chosen_reg, b.hex(" ").upper()
            return raw_bytes, 0, chosen_reg, raw_bytes.hex(" ").upper()

        if assignments:
            first_reg, first_value = next(iter(assignments.items()))
            unit_size = max(1, data_size)
            mask = (1 << (unit_size * 8)) - 1
            b = (first_value & mask).to_bytes(unit_size, byteorder="little", signed=False)
            return b, 0, first_reg, b.hex(" ").upper()

        return None, offset, chosen_reg, ""

    @staticmethod
    def _range_overlap(a_addr: int, a_size: int, b_addr: int, b_size: int) -> Optional[Tuple[int, int]]:
        start = max(a_addr, b_addr)
        end = min(a_addr + a_size, b_addr + b_size)
        if end <= start:
            return None
        return start, end

    @staticmethod
    def _format_address(addr: int) -> str:
        return f"0x{addr:x}"

    @staticmethod
    def _instruction_text(instruction) -> str:
        return f"{instruction.mnemonic} {instruction.operands}".strip()

    def _instruction_writes_register(self, instruction, register: str) -> bool:
        aliases = self._related_register_names(register)
        if not aliases:
            return False
        for change in instruction.register_changes:
            if change.register.upper() in aliases:
                return True
        return False

    def _resolve_load_context(self, register: Optional[str], from_index: int, lookback: int = 120) -> Optional[Dict]:
        if from_index < 0 or not self.parser:
            return None

        start = max(0, from_index - max(0, lookback))
        for idx in range(from_index, start - 1, -1):
            instruction = self.parser.parse_instruction_at(idx)
            if not instruction:
                continue

            if register and idx != from_index and not self._instruction_writes_register(instruction, register):
                continue

            for op in instruction.memory_ops:
                if op.type != "read":
                    continue

                op_addr = self._parse_int_value(op.address)
                if op_addr is None:
                    continue
                op_size = max(1, int(op.data_size))
                load_bytes, offset, hit_reg, load_hex = self._extract_load_value_bytes(
                    mnemonic=instruction.mnemonic,
                    operands=instruction.operands,
                    data_size=op_size,
                    data_value=op.data_value,
                    focus_register=register,
                )
                target_addr = op_addr + max(0, offset)
                target_size = len(load_bytes) if load_bytes else max(1, op_size - max(0, offset))

                return {
                    "index": idx,
                    "instruction": instruction,
                    "op": op,
                    "address": target_addr,
                    "size": target_size,
                    "value_bytes": load_bytes,
                    "value_hex": load_hex,
                    "register": hit_reg or (register.upper() if register else None),
                }
        return None

    def _find_previous_matching_write(
        self,
        start_index: int,
        target_addr: int,
        target_size: int,
        target_bytes: Optional[bytes],
        max_scan: int = 20000,
    ) -> Optional[Dict]:
        if not self.parser:
            return None

        scanned = 0
        for idx in range(start_index, -1, -1):
            scanned += 1
            if scanned > max_scan:
                break

            instruction = self.parser.parse_instruction_at(idx)
            if not instruction:
                continue

            for op in instruction.memory_ops:
                if op.type != "write":
                    continue

                write_addr = self._parse_int_value(op.address)
                if write_addr is None:
                    continue
                write_size = max(1, int(op.data_size))
                overlap = self._range_overlap(target_addr, target_size, write_addr, write_size)
                if not overlap:
                    continue

                write_bytes, source_regs, write_hex = self._extract_store_value_bytes(
                    mnemonic=instruction.mnemonic,
                    operands=instruction.operands,
                    data_size=write_size,
                    data_value=op.data_value,
                )

                match_type = "地址重叠"
                if target_bytes is not None and write_bytes is not None:
                    ov_start, ov_end = overlap
                    target_slice = target_bytes[(ov_start - target_addr):(ov_end - target_addr)]
                    write_slice = write_bytes[(ov_start - write_addr):(ov_end - write_addr)]
                    if target_slice != write_slice:
                        continue
                    if (
                        ov_start == target_addr
                        and (ov_end - ov_start) == target_size
                        and target_size <= write_size
                    ):
                        match_type = "字节精确匹配"
                    else:
                        match_type = "重叠字节匹配"

                return {
                    "index": idx,
                    "instruction": instruction,
                    "op": op,
                    "address": write_addr,
                    "size": write_size,
                    "value_bytes": write_bytes,
                    "value_hex": write_hex,
                    "match_type": match_type,
                    "source_registers": source_regs,
                }

        return None

    def trace_data_provenance(
        self,
        register: str,
        from_index: int,
        max_scan: int = 20000,
        max_calc_steps: int = 120,
    ) -> Dict:
        """trace_data_provenance function."""
        result: Dict = {
            "target_register": (register or "").upper(),
            "query_index": from_index,
            "events": [],
            "message": "",
        }

        if from_index < 0 or not self.parser:
            result["message"] = "无效位置或解析器未初始化"
            return result

        load_ctx = self._resolve_load_context(register, from_index)
        if not load_ctx:
            result["message"] = "当前行附近未找到与目标寄存器相关的内存读取"
            return result

        load_instruction = load_ctx["instruction"]
        load_idx = int(load_ctx["index"])
        target_addr = int(load_ctx["address"])
        target_size = int(load_ctx["size"])
        target_bytes = load_ctx["value_bytes"]
        target_hex = load_ctx["value_hex"] or ("?" if target_bytes is None else target_bytes.hex(" ").upper())
        hit_register = load_ctx.get("register") or (register or "").upper()

        result["events"].append({
            "kind": "load",
            "index": load_idx,
            "instruction_address": load_instruction.address,
            "instruction_text": self._instruction_text(load_instruction),
            "memory_address": self._format_address(target_addr),
            "memory_size": target_size,
            "value_hex": target_hex,
            "detail": f"读取结果: {hit_register}",
        })

        write_ctx = self._find_previous_matching_write(
            start_index=load_idx - 1,
            target_addr=target_addr,
            target_size=target_size,
            target_bytes=target_bytes,
            max_scan=max_scan,
        )

        if not write_ctx:
            result["message"] = "未找到匹配的历史写入（可能超出回溯范围或日志缺少写入数据）"
            return result

        write_instruction = write_ctx["instruction"]
        write_idx = int(write_ctx["index"])
        write_hex = write_ctx["value_hex"] or "?"
        source_regs = write_ctx.get("source_registers") or []
        source_text = ", ".join(source_regs) if source_regs else "-"

        result["events"].append({
            "kind": "write",
            "index": write_idx,
            "instruction_address": write_instruction.address,
            "instruction_text": self._instruction_text(write_instruction),
            "memory_address": self._format_address(int(write_ctx["address"])),
            "memory_size": int(write_ctx["size"]),
            "value_hex": write_hex,
            "detail": f"{write_ctx['match_type']} | 写入源寄存器: {source_text}",
        })

        if source_regs:
            calc_chain = self.reverse_taint_trace(
                source_regs[0],
                max(0, write_idx - 1),
                max_steps=max_calc_steps,
            )
            for node in calc_chain:
                result["events"].append({
                    "kind": "calc",
                    "index": int(node["index"]),
                    "instruction_address": node["address"],
                    "instruction_text": f'{node["mnemonic"]} {node["operands"]}'.strip(),
                    "memory_address": "-",
                    "memory_size": 0,
                    "value_hex": "-",
                    "detail": (
                        f"计算链: 命中写寄存器 {', '.join(node['hit_writes']) or '-'}; "
                        f"读取寄存器 {', '.join(node['read_regs']) or '-'}"
                    ),
                })

        result["message"] = "ok"
        return result

    def _add_to_local_cache(self, index: int, state: RegisterState):
        """_add_to_local_cache function."""
        if len(self._local_cache) >= self._local_cache_max_size:
            if self._local_cache:
                oldest_key = next(iter(self._local_cache))
                del self._local_cache[oldest_key]
        
        self._local_cache[index] = state
    
    def clear_local_cache(self):
        """clear_local_cache function."""
        self._local_cache.clear()
    
    @staticmethod
    def get_related_registers(register: str) -> List[str]:
        """get_related_registers function."""
        registers = [register]
        
        if register.startswith('W') and register[1:].isdigit():
            registers.append('X' + register[1:])
        elif register.startswith('X') and register[1:].isdigit():
            registers.append('W' + register[1:])
        
        return registers
    
    @staticmethod
    def get_all_arm64_registers() -> Set[str]:
        """get_all_arm64_registers function."""
        registers = set()
        for i in range(31):
            registers.add(f'X{i}')
        registers.add('SP')
        registers.add('FP')
        registers.add('LR')
        return registers
    
    @staticmethod
    def get_register_sort_key(register: str) -> tuple:
        """get_register_sort_key function."""
        special_order = {
            'SP': (0, 0),
            'FP': (0, 1),
            'LR': (0, 2),
            'PC': (0, 3),
        }
        
        if register in special_order:
            return special_order[register]
        
        if register.startswith('X') and register[1:].isdigit():
            num = int(register[1:])
            return (1, -num)
        
        if register.startswith('W') and register[1:].isdigit():
            num = int(register[1:])
            return (1, -num)
        
        if register in ['XZR', 'WZR']:
            return (2, 0)
        
        return (3, register)

