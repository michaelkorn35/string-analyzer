"""Post-match validators to filter false positives from regex detectors."""

from __future__ import annotations

import base64
import binascii
import re

from . import patterns

# Common DNS TLDs; hostnames outside this set are treated as unlikely domains.
KNOWN_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "uk",
        "de",
        "fr",
        "au",
        "ca",
        "us",
        "cn",
        "jp",
        "ru",
        "br",
        "in",
        "it",
        "nl",
        "es",
        "eu",
        "pl",
        "se",
        "no",
        "fi",
        "dk",
        "be",
        "at",
        "ch",
        "info",
        "biz",
        "name",
        "pro",
        "xyz",
        "app",
        "dev",
        "me",
        "tv",
        "cc",
        "ws",
        "online",
        "site",
        "tech",
        "store",
        "cloud",
        "live",
    }
)

# File-type suffixes that are not internet TLDs but match domain-shaped tokens.
NON_DOMAIN_SUFFIXES = patterns.FILENAME_EXT_ALLOWLIST | {
    "cpp",
    "c",
    "h",
    "hpp",
    "pdb",
    "drv",
    "lib",
    "obj",
    "idl",
    "rc",
    "tlb",
    "mui",
    "autosave",
    "common",
    "launcher",
    "uri",
    "clipboard",
    "rl",
}

_PASCAL_CASE_IDENTIFIER_RE = re.compile(r"^[A-Z][a-z]+(?:[A-Z][a-z0-9]*)+$")
_WINRT_NAMESPACE_RE = re.compile(r"^(?:Windows|Microsoft|System)\.[A-Z]", re.IGNORECASE)


def is_plausible_domain(domain: str) -> bool:
    """Return True when *domain* looks like a real hostname, not a file or type name."""
    # Real DNS hostnames are lowercase; mixed case suggests a type or constant name.
    if domain != domain.lower():
        return False
    labels = domain.split(".")
    # A hostname needs at least a label and a TLD (e.g. example.com).
    if len(labels) < 2:
        return False
    # Single-character labels are too short for plausible DNS names.
    if any(len(label) < 2 for label in labels):
        return False
    tld = labels[-1]
    # Reject tokens whose final label is not a known public suffix.
    if tld not in KNOWN_TLDS:
        return False
    # Reject file extensions and other non-TLD suffixes that look like domains.
    if tld in NON_DOMAIN_SUFFIXES:
        return False
    # Numeric labels (e.g. 192.168.1.1) are not domain names.
    if any(label.isdigit() for label in labels):
        return False
    return True


def looks_like_version_quad(ip: str) -> bool:
    """Return True when *ip* is probably an assembly/OS version, not a host address."""
    parts = [int(p) for p in ip.split(".")]
    a, b, c, d = parts
    # 0.0.0.0 is a common placeholder, not a routable host.
    if a == 0 and b == 0 and c == 0 and d == 0:
        return True
    # Patterns like 4.0.0.0 or 10.0.0.0 match .NET/Windows version strings.
    if c == 0 and d == 0 and a <= 10 and b <= 20:
        return True
    return False


def is_plausible_ipv4(ip: str) -> bool:
    """Return True for dotted-quad values that look like network addresses."""
    parts = ip.split(".")
    # IPv4 requires exactly four octets.
    if len(parts) != 4:
        return False
    # Each octet must be a decimal value in 0–255.
    for p in parts:
        if not p.isdigit() or len(p) > 3:
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    # Filter out assembly and OS version quads that match the IPv4 pattern.
    if looks_like_version_quad(ip):
        return False
    a = int(parts[0])
    # 0.x and 255.x are reserved or broadcast ranges, rarely useful as IOCs.
    if a == 0 or a == 255:
        return False
    return True


def is_plausible_base64(token: str) -> bool:
    """Return True when *token* is likely Base64 data, not a long identifier."""
    # Base64 payloads are padded to a multiple of four characters.
    if len(token) < 24 or len(token) % 4 != 0:
        return False
    # Long PascalCase tokens are usually identifiers, not encoded blobs.
    if _PASCAL_CASE_IDENTIFIER_RE.match(token):
        return False
    # Reject URL or manifest path fragments that use the Base64 alphabet.
    if re.search(r"^[a-z]{2,}/", token) or re.search(r"/[A-Z][a-z]", token):
        return False
    # Standard Base64 uses padding or URL-safe characters; try strict decode.
    if "/" in token or "+" in token or token.endswith("="):
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            return False
        return len(decoded) >= 8
    # Unpadded tokens need digits to distinguish them from long words.
    if not any(c.isdigit() for c in token):
        return False
    upper = sum(c.isupper() for c in token)
    lower = sum(c.islower() for c in token)
    # Real Base64 mixes case; all-upper or all-lower strings are unlikely.
    if upper == 0 or lower == 0:
        return False
    return False


def is_plausible_hex(token: str) -> bool:
    """Return True for long hex blobs (hashes/keys), not short manifest tokens."""
    # Hash-like hex is long and has an even number of nibbles.
    if len(token) < 32 or len(token) % 2 != 0:
        return False
    # Every character must be a hexadecimal digit.
    if not all(c in "0123456789abcdefABCDEF" for c in token):
        return False
    return True


def _keyword_is_identifier_suffix(text: str, keyword: str) -> bool:
    """Return True when *keyword* is embedded in a CamelCase identifier tail."""
    # Walk each word-boundary match of the keyword in the source text.
    for match in re.finditer(rf"(?i)\b{re.escape(keyword)}\b", text):
        # A lowercase letter immediately before the match means CamelCase glue.
        if match.start() > 0 and text[match.start() - 1].islower():
            return True
    return False


def _is_api_ms_dll_name(text: str) -> bool:
    return text.lower().startswith("api-ms-win-")


def matches_error_keyword(text: str) -> bool:
    """Return True when *text* contains a high-signal or natural-language error indicator."""
    lowered = text.lower()
    # High-signal API and tooling names always count as indicators.
    for kw in patterns.HIGH_SIGNAL_KEYWORDS:
        if re.search(rf"(?i)\b{re.escape(kw)}\b", text):
            return True
    # Multi-word error phrases are matched as plain substrings.
    for phrase in patterns.ERROR_PHRASES:
        if phrase in lowered:
            return True
    # API forwarder DLL names are noise, not error messages.
    if _is_api_ms_dll_name(text):
        return False
    # Soft keywords apply only in message-like context (see checks below).
    for kw in patterns.SOFT_ERROR_KEYWORDS:
        if not re.search(rf"(?i)\b{re.escape(kw)}\b", text):
            continue
        # Skip when the keyword is part of a larger identifier (e.g. OnError).
        if _keyword_is_identifier_suffix(text, kw):
            continue
        # A lone keyword with no surrounding context is too generic.
        if text.strip().lower() == kw:
            continue
        # Accept short strings or ones with spaces (typical log/message text).
        if " " in text or len(text) < 48:
            return True
    return False


def is_plausible_high_entropy(text: str, entropy: float) -> bool:
    """Return True when *text* looks like encoded/random data, not structured text."""
    # Below threshold or length, entropy is not meaningful for blob detection.
    if entropy < 4.75 or len(text) < 32:
        return False
    # Markup and XML fragments are structured text, not random payloads.
    if text.lstrip().startswith("<") or "<?xml" in text.lower():
        return False
    # URLs have high entropy but are categorized separately.
    if "://" in text:
        return False
    # WinRT-style namespaces are identifiers, not encoded secrets.
    if _WINRT_NAMESPACE_RE.match(text):
        return False
    # Multiple path separators suggest a file path, not a blob.
    if text.count("\\") >= 2 or text.count("/") >= 3:
        return False
    # Spaced text with mostly letters is natural language, not random data.
    if " " in text:
        alpha_ratio = sum(c.isalpha() for c in text) / len(text)
        if alpha_ratio > 0.65:
            return False
    # Borderline entropy needs enough non-alphanumeric characters to qualify.
    if entropy < 5.0:
        non_alnum = sum(not c.isalnum() for c in text)
        if non_alnum / len(text) < 0.10:
            return False
    return True
