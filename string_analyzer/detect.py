"""Categorize extracted strings into security-relevant indicator types."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable

from . import patterns
from . import validators


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of *s*."""
    # An empty string has no character distribution to measure.
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    # Tally how often each character appears in the input.
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    # Sum -p*log2(p) over each distinct character frequency.
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _iter_unique(seq: Iterable[str]) -> Iterable[str]:
    """Yield unique items from *seq* in first-seen order."""
    seen: set[str] = set()
    for s in seq:
        # Skip duplicates while preserving the first occurrence order.
        if s in seen:
            continue
        seen.add(s)
        yield s


def categorize_strings(
    strings: list[str],
    *,
    entropy_min_len: int = 32,
    entropy_threshold: float = 4.75,
) -> dict[str, list[str]]:
    """Classify *strings* into named categories (urls, paths, keywords, etc.)."""
    cats: dict[str, list[str]] = defaultdict(list)

    # Classify each unique extracted string once.
    for s in _iter_unique(strings):
        s_stripped = s.strip()
        # Ignore whitespace-only entries.
        if not s_stripped:
            continue

        # Collect HTTP(S) URL substrings from the line.
        for m in patterns.URL_RE.finditer(s_stripped):
            cats["urls"].append(m.group(0))

        # Keep domain-shaped tokens only when they pass hostname heuristics.
        for m in patterns.DOMAIN_RE.finditer(s_stripped):
            d = m.group(0)
            if validators.is_plausible_domain(d):
                cats["domains"].append(d)

        # Keep dotted quads only when they look like real IPv4 addresses.
        for m in patterns.IPV4_CANDIDATE_RE.finditer(s_stripped):
            ip = m.group(0)
            if validators.is_plausible_ipv4(ip):
                cats["ipv4"].append(ip)

        # Record Windows drive-letter and UNC path matches.
        for m in patterns.WIN_DRIVE_PATH_RE.finditer(s_stripped):
            cats["paths"].append(m.group(0))
        for m in patterns.UNC_PATH_RE.finditer(s_stripped):
            cats["paths"].append(m.group(0))

        # Accept filename tokens with an allowlisted extension.
        for m in patterns.FILENAME_RE.finditer(s_stripped):
            fn = m.group(0)
            ext = fn.rsplit(".", 1)[-1].lower()
            if ext not in patterns.FILENAME_EXT_ALLOWLIST:
                continue
            # Skip Windows API forwarder stubs; they add noise without IOC value.
            if fn.lower().startswith("api-ms-win-"):
                continue
            cats["filenames"].append(fn)

        # Flag strings that mention errors or suspicious APIs.
        if validators.matches_error_keyword(s_stripped):
            cats["errors_and_keywords"].append(s_stripped)

        # Keep Base64-shaped tokens that decode plausibly.
        for m in patterns.BASE64_RE.finditer(s_stripped):
            token = m.group(0)
            if validators.is_plausible_base64(token):
                cats["base64_like"].append(token)

        # Keep long hex runs that look like hashes or keys.
        for m in patterns.HEX_RE.finditer(s_stripped):
            token = m.group(0)
            if validators.is_plausible_hex(token):
                cats["hex_like"].append(token)

        # Score full-string entropy only on sufficiently long inputs.
        if len(s_stripped) >= entropy_min_len:
            ent = shannon_entropy(s_stripped)
            if ent >= entropy_threshold and validators.is_plausible_high_entropy(
                s_stripped, ent
            ):
                cats["high_entropy"].append(s_stripped)

    out: dict[str, list[str]] = {}
    # Deduplicate matches within each category before returning.
    for k, vals in cats.items():
        out[k] = list(_iter_unique(vals))
    return out
