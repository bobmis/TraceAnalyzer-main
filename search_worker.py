"""Standalone worker process for heavy trace searches."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from lazy_parser import LazyLogParser
from main import SearchThread


def _configure_stdio():
    """Ensure subprocess progress text is emitted as UTF-8 on Windows."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def _emit(message: Dict[str, Any]):
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TraceAnalyzer search worker")
    parser.add_argument("--file", required=True, help="Trace file path")
    parser.add_argument("--mode", required=True, help="Search mode")
    parser.add_argument("--query", required=True, help="Search query")
    parser.add_argument("--start-index", type=int, default=0, help="Start index for find-first searches")
    return parser


def _run_search(file_path: str, mode: str, query: str, start_index: int) -> Dict[str, Any]:
    parser = LazyLogParser(file_path)
    try:
        parser.build_index(
            progress_callback=lambda current, total: _emit(
                {
                    "type": "progress",
                    "current": int(current),
                    "total": int(total),
                    "text": "正在准备搜索索引...",
                }
            )
        )
        worker = SearchThread(parser, mode, query, start_index)
        worker._emit_progress = lambda current, total, text: _emit(
            {
                "type": "progress",
                "current": int(current),
                "total": int(total),
                "text": str(text),
            }
        )

        if mode == SearchThread.MODE_FIND_FIRST:
            return worker._find_first_match()
        if mode == SearchThread.MODE_ADDRESS_ALL:
            return worker._collect_address_matches()
        if mode == SearchThread.MODE_OFFSET_ALL:
            return worker._collect_offset_matches()
        if mode == SearchThread.MODE_MNEMONIC_ALL:
            return worker._collect_mnemonic_matches()
        if mode == SearchThread.MODE_DATA_ALL:
            return worker._collect_data_matches()
        if mode == SearchThread.MODE_STRING_ALL:
            return worker._collect_string_matches()
        raise ValueError(f"Unknown search mode: {mode}")
    finally:
        parser.close()


def main() -> int:
    args = _build_parser().parse_args()
    file_path = str(Path(args.file))
    try:
        result = _run_search(file_path, args.mode, args.query, int(args.start_index))
    except Exception as exc:  # pragma: no cover - subprocess surface
        _emit({"type": "error", "error": str(exc)})
        return 1

    _emit({"type": "result", "mode": args.mode, "result": result})
    return 0


if __name__ == "__main__":
    _configure_stdio()
    raise SystemExit(main())
