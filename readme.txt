================================================================================
TraceAnalyzer README
================================================================================

GitHub 展示版说明见 README.md。

【简介】
TraceAnalyzer 是一个 ARM64 执行日志分析工具，支持超大 trace 的加载、浏览、
搜索和数据流分析。当前版本已经支持侧边索引、后台缓存、结果表独立窗口、
数据全查、地址全查、指令全查、寄存器来源追踪、数据来源追踪和反向污点分析。

【主要特性】
- 大文件按需解析，不再一次性读入整份日志
- 侧边索引复用，二次打开同一份 trace 明显加快
- 支持：
  - 查找（行号 / 指令地址 / 模块偏移 / 助记符）
  - 地址全查
  - 指令全查
  - 数据全查（例如 0x746d2a63）
  - 寄存器来源追踪
  - 数据来源追踪
  - 反向污点分析
- 结果表支持独立窗口、双击跳转、复制选中、复制全部、全选

【启动方式】
- Windows: run.bat
- Linux/macOS: run.sh
- 也可以直接执行 python main.py

【打包】
- build_exe.bat
- build_exe.bat --onefile

【快捷键】
- Ctrl+O：打开 trace
- Ctrl+F：聚焦搜索框
- F3：查找 / 下一个
- Ctrl+Shift+F：地址全查
- Ctrl+Shift+D：数据全查
- Ctrl+Shift+M：指令全查
- Ctrl+T：快速数据来源追踪
- Ctrl+Shift+T：快速反向污点分析
- PgUp：追踪寄存器来源
- PgDn：返回历史

【侧边索引】
程序会自动生成 .traceidx.* 文件用于复用：
- .traceidx.dat / .traceidx.json
- .traceidx.chk
- .traceidx.mnx
- .traceidx.rgx
- .traceidx.mem
- .traceidx.mwr
- .traceidx.ofx / .traceidx.ofm

【说明】
建议优先阅读 README.md，内容更完整，也更适合 GitHub 展示。

================================================================================
