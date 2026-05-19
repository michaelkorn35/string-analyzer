"""Regular expressions and allowlists for string categorization."""

from __future__ import annotations

import re

# Patterns are deliberately conservative to reduce false positives.

URL_RE = re.compile(
    r"(?i)\b(?:https?|hxxps?)://[a-z0-9\-._~%]+(?:\:[0-9]{1,5})?(?:/[^\s\"\'<>]*)?"
)

# FQDN-ish: labels separated by dots, last label 2-24 chars.
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b"
)

IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

WIN_DRIVE_PATH_RE = re.compile(
    r"(?i)\b[a-z]:\\(?:[^<>:\"/\\|?*\r\n]+\\)*[^<>:\"/\\|?*\r\n]*"
)
UNC_PATH_RE = re.compile(
    r"(?i)\\\\[a-z0-9._-]+\\[a-z0-9 $._-]+(?:\\[^<>:\"/\\|?*\r\n]+)*"
)

# Generic file token that looks like "name.ext" (validated against allowlist below).
FILENAME_RE = re.compile(r"(?i)\b[a-z0-9][a-z0-9._-]{0,200}\.[a-z0-9]{1,8}\b")

SUSPICIOUS_EXTENSIONS = {
    "exe",
    "dll",
    "sys",
    "scr",
    "ps1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "jse",
    "jar",
    "docm",
    "xlsm",
    "pptm",
    "lnk",
    "hta",
    "msi",
    "iso",
}

# Allowlist for filename detection; includes suspicious and common doc/script types.
FILENAME_EXT_ALLOWLIST = SUSPICIOUS_EXTENSIONS | {
    "txt",
    "log",
    "dat",
    "cfg",
    "ini",
    "json",
    "xml",
    "yml",
    "yaml",
    "pem",
    "crt",
    "cer",
    "key",
    "pfx",
    "zip",
    "rar",
    "7z",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "csv",
    "tmp",
}

# Always treated as indicators when present (substring match is intentional).
HIGH_SIGNAL_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "bitsadmin",
    "certutil",
    "mshta",
    "schtasks",
    "wininet",
    "winsock",
    "ws2_32",
    "urlmon",
    "internetopen",
    "internetconnect",
    "httpopenrequest",
    "urldownloadtofile",
    "createremotethread",
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "openprocess",
    "getprocaddress",
    "loadlibrary",
]

# Multi-word phrases that indicate errors or denials in log/message strings.
ERROR_PHRASES = [
    "access denied",
    "not found",
    "timed out",
]

# Generic error words; matched only in message-like strings (see validators).
SOFT_ERROR_KEYWORDS = [
    "error",
    "failed",
    "failure",
    "exception",
    "invalid",
    "denied",
    "refused",
    "timeout",
    "unauthorized",
]

# Base64-ish tokens: require decent length and avoid whitespace.
BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{32,})\b")
