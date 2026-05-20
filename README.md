# TraceAnalyzer

ARM64 执行日志分析工具，基于 `PySide6` 实现，适合加载超大 `.txt` trace，浏览指令序列，并联动查看寄存器状态、内存访问、寄存器来源、数据来源追踪和反向污点分析。

## 现状

- 支持大文件侧边索引，避免整文件一次性读入内存
- 已实测 `dy_trace.txt` 这类 `6GB+` trace 的加载、复用和搜索
- 二次打开同一份 trace 时可复用索引和检查点
- 搜索、追踪、污点分析等重操作已经搬到后台线程，界面不再直接卡死

## 主要功能

- 指令浏览
  - 虚拟滚动指令表，适合百万到千万级指令浏览
  - 左侧显示行号、地址、偏移、指令、操作数、注释
  - 右侧显示寄存器状态与内存相关信息

- 搜索
  - `查找`
    - 支持行号
    - 支持完整指令地址
    - 支持模块偏移
    - 支持助记符输入后自动转到“指令全查”
  - `地址全查`
    - 搜索内存访问地址前缀
  - `指令全查`
    - 搜索助记符前缀，如 `ldr`、`str`、`add`
  - `数据全查`
    - 直接搜索数据值，如 `0x746d2a63`
    - 会匹配寄存器变化、内存读写值、dump 字节、部分操作数字段

- 分析
  - 寄存器来源追踪
  - 数据来源追踪
  - 反向污点分析

- 结果表
  - 搜索结果表独立窗口显示
  - 双击结果只跳转，不自动关闭窗口
  - 支持 `Ctrl+A` / `Ctrl+C`
  - 支持右键复制选中、复制全部、全选

## 大文件优化

当前版本已经做了几轮大文件优化：

- 按需解析，不再 `readlines()` 整文件
- 指令索引落盘到 `.traceidx.*` 侧边文件
- 寄存器检查点可持久化复用
- 助记符、寄存器写入、内存访问、偏移等都引入了额外索引
- 高频搜索路径已尽量避免 Python 层全表扫描

常见侧边文件说明：

- `.traceidx.dat`：主指令索引
- `.traceidx.json`：主索引元数据
- `.traceidx.chk`：寄存器检查点
- `.traceidx.mnx`：助记符 posting
- `.traceidx.rgx`：寄存器写入 posting
- `.traceidx.mem`：内存访问 posting
- `.traceidx.mwr`：内存写入 posting
- `.traceidx.ofx` / `.traceidx.ofm`：偏移 posting

这些文件会在首次打开 trace 时自动生成，后续复用。

## 运行环境

- Python `3.10+` 推荐
- `PySide6`

项目当前通过启动脚本优先使用本地 `venv`，并主动规避被第三方程序注入的 Python 路径污染。

## 启动方式

### Windows

```bat
run.bat
```

### Linux / macOS

```bash
./run.sh
```

### 直接运行

```bash
python main.py
```

如果你在 IDE 里启动，建议解释器直接选项目自己的：

```text
venv/Scripts/python.exe
```

## 打包

默认使用项目里的打包脚本：

```bat
build_exe.bat
```

单文件模式：

```bat
build_exe.bat --onefile
```

打包依赖见：

- [requirements-build.txt](requirements-build.txt)
- [TraceAnalyzer.spec](TraceAnalyzer.spec)

默认输出：

- 目录版：`dist/TraceAnalyzer/TraceAnalyzer.exe`
- 单文件版：`dist/TraceAnalyzer.exe`

## 快捷键

- `Ctrl+O`：打开 trace
- `Ctrl+F`：聚焦搜索框
- `F3`：执行查找 / 下一个
- `Ctrl+Shift+F`：地址全查
- `Ctrl+Shift+D`：数据全查
- `Ctrl+Shift+M`：指令全查
- `Ctrl+T`：快速数据来源追踪
- `Ctrl+Shift+T`：快速反向污点分析
- `PgUp`：追踪当前寄存器来源
- `PgDn`：返回历史跳转

## 结果表说明

- 偏移全查、地址全查、指令全查、数据全查都支持完整结果保留
- 为了避免大结果直接撑爆内存，部分结果表已改成惰性模型，滚到某行时才取详情
- 偏移 posting 会在后台预热；首次查询若 sidecar 尚未准备好，会自动回退到旧逻辑，不会卡住等待

## 项目结构

```text
TraceAnalyzer/
  main.py               主窗口、搜索入口、分析线程、结果表
  lazy_parser.py        大文件延迟解析与侧边索引
  parser.py             指令/寄存器/内存操作解析
  register.py           寄存器与寄存器状态定义
  register_calc.py      寄存器状态计算、来源追踪、污点分析
  cache_worker.py       检查点后台构建
  instruction_view.py   虚拟滚动指令视图
  ui_components.py      UI 组件与样式
  run.bat / run.sh      启动脚本
  build_exe.bat         打包脚本
```

## 示例文件

- `log.txt`
- `test.txt`
- `dy_trace.txt` 仅用于本地大文件测试，不建议提交到仓库

## 关联项目

- https://github.com/jiqiu2022/vm-trace-release
- https://github.com/lxz-jiandan/TraceAnalyzer
