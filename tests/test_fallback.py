"""
tests/test_fallback.py
Fallback resilience tests.
Verifies that when LLM fails, times out, or has no API keys, the system:
1. Never crashes
2. Falls back to deterministic rules-only mode
3. Displays a clear fallback warning
4. Accurately flags obvious scams based on rules
"""

import pytest
from unittest.mock import patch
from core.fusion import analyze_message
from core.schemas import Verdict


def test_rules_only_fallback_on_llm_failure():
    """Verify system falls back gracefully when LLM returns None."""
    scam_msg = "Mubarak ho! Apka BISP me 50,000 rupay ka wazifa aya hai. Fauri rabta karein 0300-1122334"

    # Simulate LLM failure / offline
    with patch("core.fusion.analyze_with_llm", return_value=(None, None)):
        result = analyze_message(scam_msg)

        assert result is not None
        assert result.mode == "rules_only"
        assert result.verdict == Verdict.LIKELY_SCAM
        assert any("rules-only fallback" in w.lower() or "offline" in w.lower() for w in result.warnings)
        assert len(result.red_flags) > 0
        assert result.rule_score > 0


def test_rules_only_fallback_on_safe_message():
    """Verify safe message classification in rules-only fallback mode."""
    safe_msg = "Hello bhai, are we meeting for dinner tonight at 8 PM?"

    with patch("core.fusion.analyze_with_llm", return_value=(None, None)):
        result = analyze_message(safe_msg)

        assert result is not None
        assert result.mode == "rules_only"
        assert result.verdict == Verdict.LIKELY_SAFE
        assert len(result.red_flags) == 0


def test_rules_only_fallback_on_legitimate_otp():
    """Verify that legitimate OTP alert is safe even in rules-only fallback mode."""
    otp_msg = "Your OTP is 998811 for login. Never share this code with anyone including bank staff."

    with patch("core.fusion.analyze_with_llm", return_value=(None, None)):
        result = analyze_message(otp_msg)

        assert result is not None
        assert result.mode == "rules_only"
        assert result.verdict == Verdict.LIKELY_SAFE
