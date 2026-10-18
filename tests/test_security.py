"""
tests/test_security.py
Security, sanitization, grounding, and boundary condition tests:
- XSS prevention (html.escape before adding <mark> tags)
- Exact substring quote validation (dropping hallucinated quotes)
- Input length limits (2000 character cap)
- Boundary handling for empty inputs and 5000+ char inputs
- Rate limiter verification
"""

import pytest
from core.highlight import highlight_message
from core.schemas import RedFlag, Verdict
from core.fusion import analyze_message
from core.preprocess import normalize_text, MAX_INPUT_LENGTH
from core.rate_limit import RateLimiter


def test_html_xss_escaping_in_highlighting():
    """Ensure raw HTML tags are strictly escaped and never rendered directly."""
    malicious_input = '<script>alert("xss")</script> <img src=x onerror=alert(1)> Fauri rabta karein'
    flags = [
        RedFlag(
            phrase="Fauri rabta",
            explanation="Urgency indicator",
            evidence_quote="Fauri rabta",
            category="urgency",
            severity="medium"
        )
    ]
    highlighted = highlight_message(malicious_input, flags)

    # Must contain HTML escaped entities, NOT raw unescaped script tags
    assert "<script>" not in highlighted
    assert "&lt;script&gt;" in highlighted
    assert '<img src=x' not in highlighted
    assert '&lt;img src=x' in highlighted
    assert '<mark class="scam-mark">' in highlighted


def test_exact_substring_evidence_quote_grounding():
    """Ensure evidence_quote must strictly exist in the original text; hallucinations dropped."""
    text = "Your account is temporarily suspended. Please visit your branch."
    # Fabricated quote not in text
    fake_flag = RedFlag(
        phrase="fabricated quote",
        explanation="Fake explanation",
        evidence_quote="Send your 4 digit pin to 03001234567",
        category="credential_theft",
        severity="high"
    )
    highlighted = highlight_message(text, [fake_flag])
    # The fake quote should not appear in mark tags
    assert '<mark class="scam-mark">Send your 4 digit pin' not in highlighted
    assert highlighted == "Your account is temporarily suspended. Please visit your branch."


def test_input_truncation_2000_chars():
    """Verify input longer than 2000 chars is cleanly truncated without crashing."""
    oversized_input = "Warning! " * 500  # 4500 characters
    normalized = normalize_text(oversized_input)
    assert len(normalized) <= MAX_INPUT_LENGTH


def test_empty_input_handling():
    """Verify empty input does not cause an exception."""
    result = analyze_message("")
    assert result.verdict == Verdict.LIKELY_SAFE
    assert len(result.red_flags) == 0
    assert "No text submitted" in result.warnings[0]


def test_large_5000_char_input():
    """Verify 5000 character input passes through pipeline safely."""
    huge_text = ("Urgent: Account block ho jayega! " * 150)[:5000]
    result = analyze_message(huge_text)
    assert result is not None
    assert result.verdict in (Verdict.LIKELY_SCAM, Verdict.SUSPICIOUS)


def test_rate_limiter():
    """Verify session rate limiter permits up to max_requests and blocks afterwards."""
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    session_id = "test_user_session_1"

    assert limiter.is_allowed(session_id) is True
    assert limiter.is_allowed(session_id) is True
    assert limiter.is_allowed(session_id) is True
    # 4th request must be rejected
    assert limiter.is_allowed(session_id) is False
    assert limiter.get_remaining(session_id) == 0
