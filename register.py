"""register module."""


class Register:
    """Register class."""
    
    def __init__(self, name: str, value: int = 0):
        """__init__ function."""
        self.name = name
        self._value = value & 0xFFFFFFFFFFFFFFFF
    
    @property
    def value(self) -> int:
        """value function."""
        return self._value
    
    @value.setter
    def value(self, val: int):
        """value function."""
        self._value = val & 0xFFFFFFFFFFFFFFFF
    
    def get_x_value(self) -> str:
        """get_x_value function."""
        return f'0x{self._value:x}'
    
    def get_w_value(self) -> str:
        """get_w_value function."""
        w_val = self._value & 0xFFFFFFFF
        return f'0x{w_val:x}'
    
    def set_from_string(self, value_str: str):
        """set_from_string function."""
        if not value_str:
            return
        
        if value_str.startswith('0x') or value_str.startswith('0X'):
            value_str = value_str[2:]
        
        try:
            self._value = int(value_str, 16) & 0xFFFFFFFFFFFFFFFF
        except ValueError:
            pass
    
    def update_x(self, value_str: str):
        """update_x function."""
        self.set_from_string(value_str)
    
    def update_w(self, value_str: str):
        """update_w function."""
        if not value_str:
            return
        
        if value_str.startswith('0x') or value_str.startswith('0X'):
            value_str = value_str[2:]
        
        try:
            w_val = int(value_str, 16) & 0xFFFFFFFF
            high_bits = self._value & 0xFFFFFFFF00000000
            self._value = high_bits | w_val
        except ValueError:
            pass
    
    @staticmethod
    def normalize_name(reg_name: str) -> str:
        """normalize_name function."""
        if reg_name.startswith('W') and reg_name[1:].isdigit():
            return 'X' + reg_name[1:]
        return reg_name
    
    @staticmethod
    def is_w_register(reg_name: str) -> bool:
        """is_w_register function."""
        return reg_name.startswith('W') and reg_name[1:].isdigit()
    
    @staticmethod
    def is_x_register(reg_name: str) -> bool:
        """is_x_register function."""
        return reg_name.startswith('X') and reg_name[1:].isdigit()
    
    def __repr__(self):
        return f"Register({self.name}, {self.get_x_value()})"


class RegisterState:
    """RegisterState class."""
    
    def __init__(self):
        self.registers: dict[str, Register] = {}
    
    def update(self, reg_name: str, value_str: str):
        """update function."""
        normalized_name = Register.normalize_name(reg_name)
        
        if normalized_name not in self.registers:
            self.registers[normalized_name] = Register(normalized_name)
        
        reg = self.registers[normalized_name]
        
        if Register.is_w_register(reg_name):
            reg.update_w(value_str)
        else:
            reg.update_x(value_str)
    
    def get_register(self, reg_name: str) -> Register:
        """get_register function."""
        normalized_name = Register.normalize_name(reg_name)
        if normalized_name not in self.registers:
            self.registers[normalized_name] = Register(normalized_name)
        return self.registers[normalized_name]
    
    def get_x_value(self, reg_name: str) -> str:
        """get_x_value function."""
        return self.get_register(reg_name).get_x_value()
    
    def get_w_value(self, reg_name: str) -> str:
        """get_w_value function."""
        return self.get_register(reg_name).get_w_value()
    
    def get_all_registers(self) -> list[str]:
        """get_all_registers function."""
        return sorted(self.registers.keys())
    
    def copy(self) -> 'RegisterState':
        """copy function."""
        new_state = RegisterState()
        for name, reg in self.registers.items():
            new_state.registers[name] = Register(name, reg.value)
        return new_state
    
    def __repr__(self):
        return f"RegisterState({len(self.registers)} registers)"
