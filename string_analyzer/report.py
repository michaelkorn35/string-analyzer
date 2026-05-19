"""Build and write JSON analysis reports for input files."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .detect import categorize_strings
from .extract import extract_strings


@dataclass(frozen=True)
class AnalyzeSettings:
    """Extraction and reporting options used for a single analysis run."""

    min_len: int
    max_len: int
    extract_ascii: bool
    extract_utf16le: bool
    limit_per_category: int


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _file_sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return sha256(data).hexdigest()


def _cap_list(values: list[str], limit: int) -> list[str]:
    """Return at most *limit* items from *values* (empty when *limit* <= 0)."""
    if limit <= 0:
        # A zero or negative limit means omit matches from the report body.
        return []
    if len(values) <= limit:
        # The full list already fits within the configured cap.
        return values
    return values[:limit]


def analyze_file(
    *,
    input_path: Path,
    min_len: int = 4,
    max_len: int = 2048,
    extract_ascii: bool = True,
    extract_utf16le: bool = True,
    limit_per_category: int = 500,
) -> dict[str, Any]:
    """Read *input_path*, extract strings, categorize them, and return a report dict."""
    data = input_path.read_bytes()

    settings = AnalyzeSettings(
        min_len=min_len,
        max_len=max_len,
        extract_ascii=extract_ascii,
        extract_utf16le=extract_utf16le,
        limit_per_category=limit_per_category,
    )

    strings = extract_strings(
        data,
        min_len=settings.min_len,
        max_len=settings.max_len,
        extract_ascii=settings.extract_ascii,
        extract_utf16le=settings.extract_utf16le,
    )

    cats = categorize_strings(strings)

    categories: dict[str, Any] = {}
    # Build a stable report section for every known indicator category.
    for name in [
        "urls",
        "domains",
        "ipv4",
        "paths",
        "filenames",
        "errors_and_keywords",
        "base64_like",
        "hex_like",
        "high_entropy",
    ]:
        matches = cats.get(name, [])
        # Emit total count plus a capped sample list for each fixed category.
        categories[name] = {
            "count": len(matches),
            "matches": _cap_list(matches, settings.limit_per_category),
        }

    report: dict[str, Any] = {
        "input_path": str(input_path),
        "file_size": len(data),
        "sha256": _file_sha256(data),
        "generated_at": _utc_now_iso(),
        "settings": {
            "min_len": settings.min_len,
            "max_len": settings.max_len,
            "extract_ascii": settings.extract_ascii,
            "extract_utf16le": settings.extract_utf16le,
            "limit_per_category": settings.limit_per_category,
        },
        "counts": {
            "extracted_unique": len(strings),
        },
        "categories": categories,
    }
    return report


def write_report_json(out_path: Path, report: dict[str, Any]) -> None:
    """Write *report* as indented UTF-8 JSON to *out_path*, creating parents if needed."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
