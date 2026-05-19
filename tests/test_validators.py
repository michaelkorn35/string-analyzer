"""Unit tests for detection validators."""

from __future__ import annotations

import unittest

from string_analyzer.validators import (
    is_plausible_base64,
    is_plausible_domain,
    is_plausible_hex,
    is_plausible_high_entropy,
    is_plausible_ipv4,
    looks_like_version_quad,
    matches_error_keyword,
)
from string_analyzer.detect import shannon_entropy


class DomainTests(unittest.TestCase):
    def test_rejects_source_files(self) -> None:
        self.assertFalse(is_plausible_domain("banner.cpp"))
        self.assertFalse(is_plausible_domain("notepad.pdb"))

    def test_rejects_winrt_namespaces(self) -> None:
        self.assertFalse(is_plausible_domain("Microsoft.Windows.Shell.notepad"))
        self.assertFalse(is_plausible_domain("Windows.System.Launcher"))

    def test_accepts_real_hosts(self) -> None:
        self.assertTrue(is_plausible_domain("go.microsoft.com"))
        self.assertTrue(is_plausible_domain("schemas.microsoft.com"))


class Ipv4Tests(unittest.TestCase):
    def test_rejects_version_quads(self) -> None:
        self.assertTrue(looks_like_version_quad("5.1.0.0"))
        self.assertTrue(looks_like_version_quad("6.0.0.0"))
        self.assertFalse(is_plausible_ipv4("5.1.0.0"))

    def test_accepts_real_addresses(self) -> None:
        self.assertTrue(is_plausible_ipv4("192.168.1.1"))


class Base64Tests(unittest.TestCase):
    def test_rejects_api_names(self) -> None:
        self.assertFalse(is_plausible_base64("RtlDisownModuleHeapAllocation"))
        self.assertFalse(is_plausible_base64("RaiseFailFastException"))

    def test_rejects_path_fragments(self) -> None:
        self.assertFalse(is_plausible_base64("com/SMI/2016/WindowsSettings"))

    def test_accepts_encoded_payload(self) -> None:
        self.assertTrue(is_plausible_base64("SGVsbG8gV29ybGQhIEJhc2U2NCE="))


class HexTests(unittest.TestCase):
    def test_rejects_short_manifest_tokens(self) -> None:
        self.assertFalse(is_plausible_hex("6595b64144ccf1df"))

    def test_accepts_long_hashes(self) -> None:
        self.assertTrue(
            is_plausible_hex("6595b64144ccf1df6595b64144ccf1df6595b64144ccf1df")
        )


class KeywordTests(unittest.TestCase):
    def test_rejects_api_suffix_matches(self) -> None:
        self.assertFalse(matches_error_keyword("GetLastError"))
        self.assertFalse(matches_error_keyword("RaiseFailFastException"))

    def test_rejects_api_ms_dll_names(self) -> None:
        self.assertFalse(
            matches_error_keyword("api-ms-win-core-winrt-error-l1-1-0.dll")
        )

    def test_rejects_bare_generic_words(self) -> None:
        self.assertFalse(matches_error_keyword("Exception"))

    def test_accepts_error_messages(self) -> None:
        self.assertTrue(matches_error_keyword("Unknown exception"))


class HighEntropyTests(unittest.TestCase):
    def test_rejects_structured_text(self) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        ent = shannon_entropy(xml)
        self.assertFalse(is_plausible_high_entropy(xml, ent))

    def test_rejects_api_names(self) -> None:
        api = "WaitForThreadpoolTimerCallbacks"
        ent = shannon_entropy(api)
        self.assertFalse(is_plausible_high_entropy(api, ent))


if __name__ == "__main__":
    unittest.main()
