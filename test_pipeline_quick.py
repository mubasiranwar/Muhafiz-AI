"""
Quick script to test Phase 1 pipeline on 3 sample messages with UTF-8 console output.
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")

from core.fusion import analyze_message

samples = [
    (
        "Roman Urdu BISP Prize Scam",
        "Mubarak ho! Apka BISP me 25,000 rupay ka wazifa aya hai. Fauri rabta karein 0301-7654321 par."
    ),
    (
        "Urdu Script Bank Block Scam",
        "آپ کا حبیب بینک اکاؤنٹ غیر قانونی سرگرمی کی وجہ سے بلاک کر دیا گیا ہے۔ فوری بحالی کے لیے شناختی کارڈ اور اے ٹی ایم پن درج کریں۔"
    ),
    (
        "Legitimate Bank OTP Alert",
        "Your OTP for HBL Online Banking login is 839210. Valid for 5 mins. NEVER share this OTP with anyone, including HBL staff."
    )
]

print("=" * 60)
print("PHASE 1 CORE PIPELINE DEMO EXECUTION")
print("=" * 60)

for name, text in samples:
    print(f"\n--- Testing: {name} ---")
    print(f"Input: {text}")
    res = analyze_message(text)
    print(f"Verdict: {res.verdict.value.upper()}")
    print(f"Confidence: {res.confidence}")
    print(f"Mode: {res.mode}")
    print(f"Script: {res.script_type}")
    print(f"Rule Score: {res.rule_score}")
    print(f"Red Flags ({len(res.red_flags)}):")
    for f in res.red_flags:
        print(f"  - [{f.category}] \"{f.evidence_quote}\": {f.explanation}")
    print(f"Simple Expl (EN): {res.simple_explanation_en}")
    print(f"Simple Expl (UR): {res.simple_explanation_ur}")
    print(f"Highlighted HTML: {res.highlighted_text}")
