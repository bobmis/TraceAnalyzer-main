"""cache_worker module."""
import bisect
import time
from queue import PriorityQueue, Empty
from typing import Dict, Optional, Set, TYPE_CHECKING
from PySide6.QtCore import QThread, Signal, QMutex, QMutexLocker

from register import Register, RegisterState

if TYPE_CHECKING:
    from lazy_parser import LazyLogParser


class CacheWorker(QThread):
    """CacheWorker class."""
    
    checkpoint_ready = Signal(int, object)
    cache_ready = Signal(int, object)
    progress = Signal(int, int)
    all_checkpoints_ready = Signal()
    
    def __init__(self, parser: 'LazyLogParser', checkpoint_interval: int = 500):
        super().__init__()
        self.parser = parser
        self.checkpoint_interval = checkpoint_interval
        
        self.checkpoints: Dict[int, RegisterState] = {}
        self._checkpoint_indices: list = []
        
        self.task_queue: PriorityQueue = PriorityQueue()
        
        self._running = False
        self._paused = False
        self._mutex = QMutex()
        
        self._processed_checkpoints: Set[int] = set()
        
        self._current_building_index = -1
        
    def set_parser(self, parser: 'LazyLogParser'):
        """set_parser function."""
        with QMutexLocker(self._mutex):
            self.parser = parser
            self.checkpoints.clear()
            self._checkpoint_indices.clear()
            self._processed_checkpoints.clear()
            while not self.task_queue.empty():
                try:
                    self.task_queue.get_nowait()
                except Empty:
                    break
    
    def start_building_checkpoints(self):
        """start_building_checkpoints function."""
        if not self.parser:
            return
        
        instruction_count = self.parser.get_instruction_count()
        
        for i in range(0, instruction_count, self.checkpoint_interval):
            if i not in self._processed_checkpoints:
                self.task_queue.put((2, i))
        
        if not self.isRunning():
            self._running = True
            self.start()
    
    def request_cache_at(self, index: int, high_priority: bool = True):
        """request_cache_at function."""
        priority = 0 if high_priority else 1
        self.task_queue.put((priority, index))
        
        if not self.isRunning():
            self._running = True
            self.start()
    
    def request_range_cache(self, start: int, end: int):
        """request_range_cache function."""
        for i in range(start, end + 1, self.checkpoint_interval):
            checkpoint = (i // self.checkpoint_interval) * self.checkpoint_interval
            if checkpoint not in self._processed_checkpoints:
                self.task_queue.put((1, checkpoint))
        
        if not self.isRunning():
            self._running = True
            self.start()
    
    def find_nearest_checkpoint(self, index: int) -> int:
        """find_nearest_checkpoint function."""
        with QMutexLocker(self._mutex):
            if not self._checkpoint_indices:
                return -1
            
            pos = bisect.bisect_right(self._checkpoint_indices, index)
            if pos > 0:
                return self._checkpoint_indices[pos - 1]
            return -1
    
    def get_checkpoint(self, index: int) -> Optional[RegisterState]:
        """get_checkpoint function."""
        with QMutexLocker(self._mutex):
            return self.checkpoints.get(index)
    
    def has_checkpoint(self, index: int) -> bool:
        """has_checkpoint function."""
        with QMutexLocker(self._mutex):
            return index in self.checkpoints
    
    def get_checkpoint_count(self) -> int:
        """get_checkpoint_count function."""
        with QMutexLocker(self._mutex):
            return len(self.checkpoints)
    
    def get_total_checkpoints_needed(self) -> int:
        """get_total_checkpoints_needed function."""
        if not self.parser:
            return 0
        count = self.parser.get_instruction_count()
        return (count + self.checkpoint_interval - 1) // self.checkpoint_interval
    
    def pause(self):
        """pause function."""
        self._paused = True
    
    def resume(self):
        """resume function."""
        self._paused = False
    
    def stop(self):
        """stop function."""
        self._running = False
        self.wait()
    
    def run(self):
        """run function."""
        print("[CacheWorker] 线程启动")
        
        while self._running:
            if self._paused:
                self.msleep(100)
                continue
            
            try:
                priority, index = self.task_queue.get(timeout=0.1)
            except Empty:
                if self._all_checkpoints_built():
                    print("[CacheWorker] 所有检查点已构建完成")
                    self.all_checkpoints_ready.emit()
                    break
                continue
            
            checkpoint_index = (index // self.checkpoint_interval) * self.checkpoint_interval
            
            if priority >= 2 and checkpoint_index in self._processed_checkpoints:
                continue
            
            self._build_cache_to(index)
    
    def _all_checkpoints_built(self) -> bool:
        """_all_checkpoints_built function."""
        if not self.parser:
            return True
        
        total = self.get_total_checkpoints_needed()
        built = self.get_checkpoint_count()
        return built >= total
    
    def _build_cache_to(self, target_index: int):
        """_build_cache_to function."""
        if not self.parser:
            return
        
        build_start = time.time()
        
        nearest = self.find_nearest_checkpoint(target_index)
        
        if nearest >= 0:
            state = self.checkpoints[nearest].copy()
            start_index = nearest + 1
        else:
            state = RegisterState()
            start_index = 0
        
        instructions_processed = 0
        for i in range(start_index, target_index + 1):
            instruction = self.parser.parse_instruction_at(i)
            if instruction:
                for change in instruction.register_changes:
                    state.update(change.register, change.new_value)
            
            instructions_processed += 1
            
            if i % self.checkpoint_interval == 0 and i not in self._processed_checkpoints:
                self._save_checkpoint(i, state.copy())
        
        if target_index % self.checkpoint_interval == 0:
            if target_index not in self._processed_checkpoints:
                self._save_checkpoint(target_index, state.copy())
        
        self.cache_ready.emit(target_index, state)
        
        build_time = (time.time() - build_start) * 1000
        if build_time > 100:
            print(f"[CacheWorker] 构建缓存到 {target_index}, 处理 {instructions_processed} 条指令, 耗时 {build_time:.1f}ms")
    
    def _save_checkpoint(self, index: int, state: RegisterState):
        """_save_checkpoint function."""
        with QMutexLocker(self._mutex):
            self.checkpoints[index] = state
            self._processed_checkpoints.add(index)
            
            if index not in self._checkpoint_indices:
                bisect.insort(self._checkpoint_indices, index)
        
        self.checkpoint_ready.emit(index, state)
        self.progress.emit(len(self.checkpoints), self.get_total_checkpoints_needed())


