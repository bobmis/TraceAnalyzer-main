#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Starting TraceAnalyzer..."
unset PYTHONPATH
unset PYTHONHOME

if [ -x "$SCRIPT_DIR/venv/bin/python3" ]; then
    "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/main.py"
elif [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
    "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/main.py"
else
    python3 "$SCRIPT_DIR/main.py"
fi
