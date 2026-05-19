"""Command-line entry point for the string analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

from .extract import extract_strings
from .report import analyze_file, write_report_json


def build_arg_parser() -> argparse.ArgumentParser:
    """Configure and return the CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="string-analyzer",
        description="Extract and categorize interesting strings from an executable file.",
    )
    p.add_argument("input_path", type=Path, help="Path to input EXE/DLL/etc.")
    p.add_argument("--out", type=Path, required=True, help="Where to write JSON report.")
    p.add_argument("--min-len", type=int, default=4, help="Minimum string length.")
    p.add_argument("--max-len", type=int, default=2048, help="Maximum string length.")
    p.add_argument("--no-ascii", action="store_true", help="Disable ASCII extraction.")
    p.add_argument("--no-utf16", action="store_true", help="Disable UTF-16LE extraction.")
    p.add_argument(
        "--limit-per-category",
        type=int,
        default=500,
        help="Max strings stored per category in JSON (still counts full set).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """Run analysis on the CLI arguments and write the JSON report."""
    args = build_arg_parser().parse_args(argv)

    settings = {
        "min_len": int(args.min_len),
        "max_len": int(args.max_len),
        "extract_ascii": not bool(args.no_ascii),
        "extract_utf16le": not bool(args.no_utf16),
        "limit_per_category": int(args.limit_per_category),
    }

    _ = extract_strings  # Keep import used even if analyze_file evolves.
    report = analyze_file(
        input_path=args.input_path,
        min_len=settings["min_len"],
        max_len=settings["max_len"],
        extract_ascii=settings["extract_ascii"],
        extract_utf16le=settings["extract_utf16le"],
        limit_per_category=settings["limit_per_category"],
    )
    write_report_json(args.out, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
