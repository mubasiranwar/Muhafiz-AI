"""
tests/test_rules.py
Unit tests for deterministic rule engine covering:
- English, Urdu script, and Roman Urdu fuzzy spelling variants
- Suspicious URLs and shorteners
- Legitimate bank alerts with safety warnings
"""

import pytest
from core.rules import run_rules
from core.preprocess import detect_script, extract_entities


def test_roman_urdu_fuzzy_variations():
    """Test various spelling variants of inam/inaam and jeeta/jita."""
    msg1 = "Mubarak ho aap ne jeeta hai 50,000 inaam! Call 0300-1234567"
    score1, flags1, _ = run_rules(msg1)
    assert score1 >= 2.0
    assert any("jeeta" in f.evidence_quote.lower() or "inaam" in f.evidence_quote.lower() for f in flags1)

    msg2 = "Congratulations! Ap jita hai 25000 inam qurandazi me. Rabta karein."
    score2, flags2, _ = run_rules(msg2)
    assert score2 >= 2.0
    assert any("inam" in f.evidence_quote.lower() or "jita" in f.evidence_quote.lower() for f in flags2)


def test_urgency_and_threat_variations():
    """Test urgency and account blockage threats across Roman Urdu."""
    msg = "Apka JazzCash khata band ho jayega 24 ghante me. Fauri rabta karein."
    score, flags, _ = run_rules(msg)
    assert score >= 2.0
    assert any("khata band" in f.evidence_quote.lower() or "fauri rabta" in f.evidence_quote.lower() for f in flags)


def test_credential_harvesting_rules():
    """Test requests for OTP and PIN."""
    msg = "Apna OTP code fori bhejein verification ke liye."
    score, flags, _ = run_rules(msg)
    assert score >= 3.0
    assert any("otp" in f.evidence_quote.lower() for f in flags)


def test_urdu_script_rules():
    """Test Urdu script bank threat and credential theft."""
    msg = "آپ کا اکاؤنٹ بند کر دیا گیا ہے، فوری او ٹی پی بھیجیں۔"
    score, flags, _ = run_rules(msg)
    assert score >= 3.0
    assert len(flags) >= 1


def test_suspicious_url_rules():
    """Test detection of URL shorteners and suspicious TLDs."""
    msg = "Claim your package here: https://bit.ly/track-pakpost or http://update-bank.xyz"
    score, flags, _ = run_rules(msg)
    assert score >= 2.0
    quotes = [f.evidence_quote for f in flags]
    assert any("bit.ly" in q for q in quotes)


def test_legitimate_bank_otp_alert():
    """Test that legitimate OTP alerts with 'never share' warnings do not get scored as scams."""
    msg = "Your OTP is 492812. NEVER share this OTP with anyone, including bank staff. Valid 5 mins."
    score, flags, is_legit = run_rules(msg)
    assert is_legit is True
    assert score == 0.0
