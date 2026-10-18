"""
core/fusion.py
Hybrid fusion engine and fallback orchestrator.
Combines deterministic rule engine evidence with LLM reasoning.
Handles edge cases, disagreements, and graceful fallback.
"""

from typing import Optional, List, Dict, Any
from core.schemas import AnalysisResult, Verdict, RedFlag
from core.preprocess import normalize_text, detect_script, extract_entities
from core.rules import run_rules
from core.llm import analyze_with_llm
from core.highlight import highlight_message


# --- Configurable Threshold Constants ---
RULE_SCAM_THRESHOLD = 3.0       # Score >= 3.0 indicates strong scam indicators
RULE_SUSPICIOUS_THRESHOLD = 1.5 # Score >= 1.5 indicates suspicious signals


def _generate_rule_explanations(script_type: str, verdict: Verdict) -> Dict[str, str]:
    """Generates simple fallback explanations when LLM is offline."""
    if verdict == Verdict.LIKELY_SCAM:
        return {
            "en": "This message exhibits critical red flags such as urgent threats, fake prizes, or suspicious links. Do not reply or send money.",
            "ur": "اس پیغام میں انعامی دھوکہ، جعلی لنکس یا اکاؤنٹس بند کرنے کی دھمکی پائی گئی ہے۔ اس پر ہرگز عمل نہ کریں اور پیسے نہ بھیجیں۔"
        }
    elif verdict == Verdict.SUSPICIOUS:
        return {
            "en": "This message contains unusual requests or unverified sender patterns. Proceed with caution and verify independently.",
            "ur": "اس میسج میں غیر تصدیق شدہ معلومات یا مشتبہ لنکس ہیں۔ احتیاط برتیں اور خود براہِ راست تصدیق کریں۔"
        }
    else:
        return {
            "en": "No common scam patterns or fraudulent triggers were detected in this message. Always stay alert.",
            "ur": "اس پیغام میں کوئی عام فراڈ یا دھوکہ دہی کے آثار نہیں ملے۔ تاہم ہمیشہ احتیاط برتیں۔"
        }


def _generate_rule_next_steps(verdict: Verdict) -> List[str]:
    """Default safety next steps for Pakistani users."""
    if verdict == Verdict.LIKELY_SCAM:
        return [
            "Never share your OTP, ATM PIN, or CNIC with anyone.",
            "Do not click unverified links or install external APK files.",
            "For bank inquiries, call the official number on the back of your ATM card.",
            "Report scam numbers directly to your telecom operator (PTA shortcode 9900)."
        ]
    elif verdict == Verdict.SUSPICIOUS:
        return [
            "Verify the sender's identity through official channels.",
            "Do not transfer funds or share private information until confirmed.",
            "Avoid opening attached links on unknown numbers."
        ]
    else:
        return [
            "Always verify sudden requests for money even from known contacts.",
            "Remember that banks never ask for your password or secret PIN."
        ]


def analyze_message(raw_text: str) -> AnalysisResult:
    """
    Main pipeline entry point:
    1. Preprocessing (normalization, script detection, entities)
    2. Deterministic Rule evaluation
    3. LLM evaluation (with retry, timeout & untrusted data wrapping)
    4. Fusion & Disagreement resolution
    5. Graceful fallback if LLM is down
    6. Safe HTML highlighting
    """
    text = normalize_text(raw_text)
    script_type = detect_script(text)
    warnings: List[str] = []

    # Short circuit empty text
    if not text:
        return AnalysisResult(
            verdict=Verdict.LIKELY_SAFE,
            confidence=1.0,
            summary="Empty message provided.",
            red_flags=[],
            highlighted_text="",
            next_steps=[],
            simple_explanation_en="Please enter a message to analyze.",
            simple_explanation_ur="تجزیہ کے لیے برائے مہربانی کوئی میسج درج کریں۔",
            mode="rules_only",
            script_type="english",
            rule_score=0.0,
            llm_verdict=None,
            disagreement=False,
            warnings=["No text submitted."]
        )

    # 1. Deterministic Rule Layer
    rule_score, rule_flags, is_legit_alert = run_rules(text)

    # 2. LLM Layer Call
    llm_resp, provider_name = analyze_with_llm(text)

    # 3. Decision Fusion & Fallback
    if llm_resp is not None:
        # Hybrid Mode Active
        mode = f"hybrid ({provider_name})"
        llm_v = llm_resp.verdict
        final_verdict = llm_v
        disagreement = False

        # Check for Strong Disagreement
        # Case A: Rules found severe scam indicators (score >= 3.0), but LLM declared safe
        if rule_score >= RULE_SCAM_THRESHOLD and llm_v == Verdict.LIKELY_SAFE and not is_legit_alert:
            final_verdict = Verdict.SUSPICIOUS
            disagreement = True
            warnings.append("AI and rules disagree: Strong rule patterns detected despite AI safe rating.")

        # Case B: Rules found zero risk and legit alert, but LLM flagged as scam
        elif is_legit_alert and rule_score == 0.0 and llm_v == Verdict.LIKELY_SCAM:
            final_verdict = Verdict.LIKELY_SAFE
            disagreement = True
            warnings.append("AI and rules disagree: Legitimate security alert syntax verified.")

        # If the verdict is likely safe, suppress benign institution red flags
        if final_verdict == Verdict.LIKELY_SAFE:
            combined_flags = []
        else:
            # Combine red flags: prioritize LLM flags, supplement with rule flags whose quote is not already covered
            combined_flags: List[RedFlag] = list(llm_resp.red_flags)
            for rf in rule_flags:
                rf_q = rf.evidence_quote.strip().lower()
                # Skip if this quote is already contained in or contains any existing flag quote
                already_covered = any(
                    rf_q in cf.evidence_quote.lower() or cf.evidence_quote.lower() in rf_q
                    for cf in combined_flags
                )
                if not already_covered:
                    combined_flags.append(rf)

        # Ensure highlighted message uses validated quotes
        highlighted = highlight_message(text, combined_flags)

        return AnalysisResult(
            verdict=final_verdict,
            confidence=llm_resp.confidence if not disagreement else 0.70,
            summary=llm_resp.summary,
            red_flags=combined_flags,
            highlighted_text=highlighted,
            next_steps=llm_resp.next_steps or _generate_rule_next_steps(final_verdict),
            simple_explanation_en=llm_resp.simple_explanation_en,
            simple_explanation_ur=llm_resp.simple_explanation_ur,
            mode=mode,
            script_type=script_type,
            rule_score=rule_score,
            llm_verdict=llm_v.value,
            disagreement=disagreement,
            warnings=warnings
        )

    else:
        # Fallback: Rules-Only Mode
        mode = "rules_only"
        warnings.append("AI service offline or rate-limited. Running in deterministic Rules-Only fallback mode.")

        if is_legit_alert and rule_score == 0.0:
            final_verdict = Verdict.LIKELY_SAFE
            confidence = 0.90
            summary = "Verified legitimate transactional message / security warning."
        elif rule_score >= RULE_SCAM_THRESHOLD:
            final_verdict = Verdict.LIKELY_SCAM
            confidence = 0.85
            summary = "Multiple critical scam indicators identified by rule engine."
        elif rule_score >= RULE_SUSPICIOUS_THRESHOLD:
            final_verdict = Verdict.SUSPICIOUS
            confidence = 0.70
            summary = "Suspicious keywords or links detected by rule engine."
        else:
            final_verdict = Verdict.LIKELY_SAFE
            confidence = 0.75
            summary = "No obvious scam indicators detected by deterministic rules."

        display_flags = [] if final_verdict == Verdict.LIKELY_SAFE else rule_flags
        highlighted = highlight_message(text, display_flags)
        simple_expl = _generate_rule_explanations(script_type, final_verdict)

        return AnalysisResult(
            verdict=final_verdict,
            confidence=confidence,
            summary=summary,
            red_flags=display_flags,
            highlighted_text=highlighted,
            next_steps=_generate_rule_next_steps(final_verdict),
            simple_explanation_en=simple_expl["en"],
            simple_explanation_ur=simple_expl["ur"],
            mode=mode,
            script_type=script_type,
            rule_score=rule_score,
            llm_verdict=None,
            disagreement=False,
            warnings=warnings
        )
