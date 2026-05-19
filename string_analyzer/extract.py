"""Extract printable ASCII and UTF-16LE strings from raw bytes."""

from __future__ import annotations

from collections.abc import Iterable


def _is_printable_ascii_byte(b: int) -> bool:
    """Return True if *b* is tab or a printable ASCII byte."""
    return b == 0x09 or 0x20 <= b <= 0x7E


def _dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    """Return unique strings from *items*, keeping first occurrence order."""
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        # Skip strings already emitted so only the first copy is kept.
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def extract_ascii_strings(data: bytes, *, min_len: int, max_len: int) -> list[str]:
    """Scan *data* for contiguous printable ASCII runs of at least *min_len*."""
    buf = bytearray()
    out: list[str] = []

    def flush() -> None:
        nonlocal buf
        # Only emit a string when the buffered run meets the minimum length.
        if len(buf) >= min_len:
            s = bytes(buf[:max_len]).decode("ascii", errors="ignore").strip("\x00 \t\r\n")
            # Ignore runs that decode to whitespace only.
            if s:
                out.append(s)
        buf = bytearray()

    for b in data:
        # Extend the current run on printable bytes; flush when a run breaks.
        if _is_printable_ascii_byte(b):
            # Grow the current run until it hits the maximum allowed length.
            if len(buf) < max_len:
                buf.append(b)
            else:
                # Keep scanning until the run ends, then flush the capped string.
                continue
        else:
            # A non-printable byte ends the current run.
            flush()
    # Emit any trailing run that reaches the end of the file.
    flush()
    return out


def extract_utf16le_strings(data: bytes, *, min_len: int, max_len: int) -> list[str]:
    """Scan *data* for UTF-16LE runs of printable ASCII characters."""
    out: list[str] = []
    buf = bytearray()
    i = 0
    n = len(data)

    def flush() -> None:
        nonlocal buf
        # Character count is half the byte count for UTF-16LE pairs.
        if len(buf) // 2 >= min_len:
            s = bytes(buf[: max_len * 2]).decode("utf-16le", errors="ignore").strip(
                "\x00 \t\r\n"
            )
            if s:
                out.append(s)
        buf = bytearray()

    # Walk the buffer two bytes at a time looking for char + 0x00 pairs.
    while i + 1 < n:
        ch = data[i]
        nul = data[i + 1]
        # A UTF-16LE ASCII character is a printable byte followed by 0x00.
        if nul == 0x00 and _is_printable_ascii_byte(ch):
            if len(buf) < max_len * 2:
                # Append the UTF-16LE code unit to the active run.
                buf.append(ch)
                buf.append(nul)
            i += 2
            continue
        # Misaligned or non-ASCII pair ends the current UTF-16LE run.
        flush()
        i += 1
    flush()
    return out


def extract_strings(
    data: bytes,
    *,
    min_len: int = 4,
    max_len: int = 2048,
    extract_ascii: bool = True,
    extract_utf16le: bool = True,
) -> list[str]:
    """Extract and deduplicate strings from *data* using the enabled encodings."""
    strings: list[str] = []
    if extract_ascii:
        # Collect null-terminated-style ASCII runs from the binary.
        strings.extend(extract_ascii_strings(data, min_len=min_len, max_len=max_len))
    if extract_utf16le:
        # Collect wide-character runs used by Windows binaries.
        strings.extend(extract_utf16le_strings(data, min_len=min_len, max_len=max_len))
    return _dedupe_preserve_order(strings)
