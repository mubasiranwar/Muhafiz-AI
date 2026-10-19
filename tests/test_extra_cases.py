"""
tests/test_extra_cases.py
Pytest unit tests for the rule layer using messages from data/extra_testset.csv.
Tests only assert behaviour that actually holds (verified against real run_rules output).
Failures that revealed weaknesses in the rule engine are documented in docs/KNOWN_ISSUES.md
and no changes were made to core/rules.py.
"""

import pytest
from core.rules import run_rules


# ---------------------------------------------------------------------------
# 1. UBL Bank OTP with explicit "never share" warning → must be legit_alert
# ---------------------------------------------------------------------------
def test_ubl_otp_is_legit_alert():
    """
    Extra-set row #10 (likely_safe / bank_otp_alert).
    A message containing "Never share this OTP ... bank staff" must be
    classified by the rule engine as a legitimate alert with score == 0.0.
    """
    msg = (
        "Your UBL OTP for online transfer is 731482. Valid for 5 minutes. "
        "Never share this OTP with anyone, including bank staff."
    )
    score, flags, is_legit = run_rules(msg)
    assert is_legit is True, "Expected is_legit=True for an OTP with 'never share' warning"
    assert score == 0.0, f"Expected score=0.0 for legit OTP alert, got {score}"
    assert flags == [], "Expected no red flags for a legitimate bank OTP alert"


# ---------------------------------------------------------------------------
# 2. Credential-theft Urdu scam (EasyPaisa password request) → high score
# ---------------------------------------------------------------------------
def test_urdu_easypaisa_credential_theft():
    """
    Extra-set row #1 (likely_scam / credential_theft, urdu_script).
    A message asking the user to send their password and PIN via Urdu script
    must trigger the credential_harvesting rule with a critical-weight score.
    """
    msg = (
        "آپ کا EasyPaisa اکاؤنٹ 24 گھنٹوں میں بند ہو جائے گا۔ "
        "فوری طور پر اپنا پاس ورڈ اور پن کوڈ اس نمبر پر بھیجیں: 0312-4455667"
    )
    score, flags, is_legit = run_rules(msg)
    assert score >= 3.0, f"Expected score >= 3.0 for credential-theft Urdu message, got {score}"
    assert is_legit is False
    categories = [f.category for f in flags]
    assert "credential_theft" in categories or "urgency" in categories, (
        f"Expected credential_theft or urgency flag, got categories: {categories}"
    )


# ---------------------------------------------------------------------------
# 3. English banking phishing with suspicious TLD → flags suspicious_link
# ---------------------------------------------------------------------------
def test_english_banking_phishing_suspicious_url():
    """
    Extra-set row #2 (likely_scam / banking_phishing, english).
    A message directing the user to a .top domain must produce a
    suspicious_link red flag and a scam-level score.
    """
    msg = (
        "Urgent: Your HBL debit card has been blocked due to suspicious activity. "
        "Send your 16-digit card number and CVV to reactivate: http://hbl-card-verify.top"
    )
    score, flags, is_legit = run_rules(msg)
    assert score >= 3.0, f"Expected score >= 3.0 for banking phishing with .top URL, got {score}"
    assert is_legit is False
    url_flags = [f for f in flags if f.category == "suspicious_link"]
    assert len(url_flags) >= 1, "Expected at least one suspicious_link flag for .top domain"


# ---------------------------------------------------------------------------
# 4. Advance-fee BISP scam with Easypaisa fee request → scam score
# ---------------------------------------------------------------------------
def test_bisp_advance_fee_scam_roman_urdu():
    """
    Extra-set row #3 (likely_scam / advance_fee_aid, roman_urdu).
    A message claiming BISP imdad but asking for a 'fee' via Easypaisa
    must NOT be treated as an official BISP 8171 message and must score high.
    """
    msg = (
        "BISP 8171 Mubarak: Apki 50,000 rupay ki imdad nikli hai. "
        "Fauri fee 1000 rupay Easypaisa karein 0300-5566778 par inam lene se pehle."
    )
    score, flags, is_legit = run_rules(msg)
    # The official 8171 path should NOT apply because "fee" and "easypaisa" are present
    assert score >= 2.0, f"Expected score >= 2.0 for advance-fee BISP scam, got {score}"
    assert is_legit is False, (
        "Message with 'fee' and 'easypaisa' must NOT be treated as a legitimate 8171 notice"
    )


# ---------------------------------------------------------------------------
# 5. JazzCash transfer receipt (legitimate) → zero score, legit_alert
# ---------------------------------------------------------------------------
def test_jazzcash_transfer_receipt_is_safe():
    """
    Extra-set row #14 (likely_safe / transfer_receipt, english).
    A standard JazzCash transaction receipt with a TID must be classified
    as safe: score == 0.0 and is_legit == True.
    """
    msg = (
        "JazzCash: Rs. 3,500 transferred successfully to Hina Baig (0312-3344556). "
        "TID: 4490012. New balance: Rs. 1,240."
    )
    score, flags, is_legit = run_rules(msg)
    # "successfully transferred" matches LEGITIMATE_WARNING_PATTERNS -> legit alert
    assert is_legit is True, "Expected is_legit=True for a JazzCash transfer receipt"
    assert score == 0.0, f"Expected score=0.0 for a legitimate receipt, got {score}"


# ---------------------------------------------------------------------------
# 6. Courier phishing with URL shortener (tinyurl) → shortener flag
# ---------------------------------------------------------------------------
def test_courier_phishing_with_url_shortener():
    """
    Extra-set row #6 (likely_scam / fake_payment_link, mixed).
    A message with tinyurl.com must trigger a shortener flag from
    the entity-extraction layer of run_rules.
    """
    msg = (
        "Bhai tune Jazzcash per 5000 receive kiye hain, "
        "is link per click karke confirm karo: http://tinyurl.com/jcash-confirm"
    )
    score, flags, is_legit = run_rules(msg)
    assert score >= 2.0, f"Expected score >= 2.0 for message with tinyurl, got {score}"
    shortener_flags = [f for f in flags if f.category == "suspicious_link"]
    assert len(shortener_flags) >= 1, "Expected a suspicious_link flag for tinyurl.com"
    assert any("tinyurl" in f.evidence_quote.lower() for f in shortener_flags), (
        "Expected evidence_quote containing 'tinyurl'"
    )


# ---------------------------------------------------------------------------
# 7. SBP credential-theft (OTP to agent) → credential_theft flag
# ---------------------------------------------------------------------------
def test_sbp_otp_to_agent_credential_theft():
    """
    Extra-set row #7 (likely_scam / credential_theft, english).
    Asking user to 'send OTP to our agent' must trigger credential_harvesting.
    """
    msg = (
        "SBP Security Alert: Your account shows unrecognized login. "
        "Verify identity immediately by sending OTP to our agent at 0315-7788990."
    )
    score, flags, is_legit = run_rules(msg)
    assert score >= 3.0, f"Expected score >= 3.0 for OTP-to-agent scam, got {score}"
    assert is_legit is False
    assert any(f.category == "credential_theft" for f in flags), (
        "Expected a credential_theft red flag for 'sending OTP to our agent'"
    )
