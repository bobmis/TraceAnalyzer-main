@echo off
setlocal
echo Starting TraceAnalyzer...
set "SCRIPT_DIR=%~dp0"
set "PYTHONPATH="
set "PYTHONHOME="

if exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    "%SCRIPT_DIR%venv\Scripts\python.exe" "%SCRIPT_DIR%main.py"
) else (
    python "%SCRIPT_DIR%main.py"
)

pause
