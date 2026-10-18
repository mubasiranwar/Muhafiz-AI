"""
core/rules.py
Deterministic rule engine for scam detection with support for:
- English
- Urdu script
- Roman Urdu (with phonological / fuzzy spelling variations)
- Legitimate message detection (e.g. legitimate bank OTP alerts with warnings)

Each rule returns:
- category
- severity
- points (weight)
- matched phrase (exact substring found in text for highlighting)
- explanation
"""

import re
from typing import List, Dict, Any, Tuple
from core.schemas import RedFlag
from core.preprocess import extract_entities


# Scoring weights
WEIGHT_CRITICAL = 3.0
WEIGHT_HIGH = 2.0
WEIGHT_MEDIUM = 1.0
WEIGHT_LOW = 0.5


# Rule definitions with regex patterns, category, weight, and explanation
RULES = [
    # --- 1. Prize & Aid Scams (BISP, Inam, Lottery) ---
    {
        "id": "prize_aid_claim",
        "category": "prize_scam",
        "weight": WEIGHT_HIGH,
        "explanation": "Unsolicited claims of winning money, lottery, or government aid (BISP/Benazir) are classic Pakistani fraud pretexts.",
        "patterns": [
            r"\b(?:bisp|benazir\s*(?:income|support)?|ehsaas)\s*(?:scheme|fund|program|aid|wazifa|office)?\b",
            r"\b(?:inaam|inam|enaam|prize|lottery|qurandazi)\s*(?:nikla|mubarak|jeeta|jita|jeet)\b",
            r"\b(?:jeeta|jita|jeet)\s*(?:hai|chuke)?\s*[\w\s]{0,25}(?:inaam|inam|enaam|prize|lottery|rupay|lakh)\b",
            r"\b(?:qurandazi|lottery|inaam|inam)\s*(?:me|mein)?\s*[\w\s]{0,15}(?:jeeta|jita|nikla|mubarak)\b",
            r"\b(?:mubarak\s*ho)\s*[\w\s]{0,25}(?:inaam|inam|jeeta|jita|rupay|lakh)\b",
            r"(?:بینظیر|بی\s*آئی\s*ایس\s*پی|احساس\s*پروگرام|انعام|قرعہ\s*اندازی|لاٹری|مبارک\s*ہو)",
            r"\b(?:you\s+have\s+won|congratulations\s+you\s+won|claimed\s+your\s+cash\s+prize)\b",
            r"\b(?:ramzan|ramadan)\s*(?:package|relief|ration|free\s*ration)\b"
        ]
    },

    # --- 2. Threats, Urgency & Account Deactivation ---
    {
        "id": "urgency_threat",
        "category": "urgency",
        "weight": WEIGHT_HIGH,
        "explanation": "Artificial urgency or threats of account suspension pressure the victim to act without thinking.",
        "patterns": [
            r"\b(?:account|khata|sim|atm|card)\s*(?:block|band|suspend|deactivat\w*)\s*(?:ho\s*jayega|ho\s*gya|hoga|kardiya)\b",
            r"\b(?:fauri|fori|fawri|urgent|immediately|emergency|ab\s*hi|abhi)\s*(?:rabta|karein|call|bhejein|update)\b",
            r"\b(?:24\s*ghante|24\s*hours|within\s*24\s*hours|aaj\s*hi|last\s*warning|akhri\s*ittehad)\b",
            r"(?:اکاؤنٹ\s*بند|بلاک\s*ہو\s*جائے\s*گا|فوری\s*رابطہ|آخری\s*وارننگ|معطل)",
            r"\b(?:act\s+now|urgent\s+action\s+required|immediate\s+verification\s+needed|account\s+suspended)\b"
        ]
    },

    # --- 3. Credential & Financial Theft (OTP, PIN, Password, CNIC) ---
    {
        "id": "credential_harvesting",
        "category": "credential_theft",
        "weight": WEIGHT_CRITICAL,
        "explanation": "Legitimate institutions NEVER ask you to reply with your OTP, PIN, password, or card CVV.",
        "patterns": [
            r"\b(?:send|bhejein|bhejo|bhejain|bhejiye|share\s*karein|batayein)\s*[\w\s]{0,20}(?:otp|pin|password|cnic|cvv|code)\b",
            r"\b(?:otp|pin|password|cnic|card\s*number|cvv|code)\s*[\w\s]{0,20}(?:send|bhejein|bhejo|bhejain|bhejiye|share|batayein)\b",
            r"\b(?:apna|apni|apka|aapka)?\s*(?:otp|pin|shanakhti\s*card|password)\s*[\w\s]{0,20}(?:darj|bhejein|bhejo|batayein)\b",
            r"(?:او\s*ٹی\s*پی\s*بھیجیں|پن\s*کوڈ\s*بتائیں|شناختی\s*کارڈ\s*نمبر\s*شیئر|پاس\s*ورڈ)",
            r"\b(?:verify\s+your\s+identity\s+by\s+sending|reply\s+with\s+your\s+otp|enter\s+pin)\b"
        ]
    },

    # --- 4. Impersonation of Financial Services / Government ---
    {
        "id": "impersonation",
        "category": "impersonation",
        "weight": WEIGHT_MEDIUM,
        "explanation": "Scammers pose as trusted Pakistani institutions like JazzCash, Easypaisa, State Bank, or FIA.",
        "patterns": [
            r"\b(?:jazzcash|easypaisa|nayapay|sadapay|upaisa)\s*(?:helpline|head\s*office|officer|manager)?\b",
            r"\b(?:state\s*bank|sbp|hbl|ubl|mcb|meezan|allied\s*bank|bank\s*alfalah)\s*(?:verification|department|security)?\b",
            r"\b(?:fia|fbr|pakistan\s*post|tcs|leopards)\s*(?:customs|delivery|parcel|hold|tax)\b",
            r"(?:جاز\s*کیش|ایزی\s*پیسہ|اسٹیٹ\s*بینک|میزان\s*بینک|حبیب\s*بینک|ڈاکخانہ)",
            r"\b(?:bisp\s*head\s*office|ehsaas\s*director)\b"
        ]
    },

    # --- 5. Suspicious Contact Requests (WhatsApp / Unofficial Numbers) ---
    {
        "id": "informal_contact",
        "category": "suspicious_channel",
        "weight": WEIGHT_MEDIUM,
        "explanation": "Directing users to personal WhatsApp numbers or unknown mobile numbers instead of official UAN or shortcodes.",
        "patterns": [
            r"\b(?:whatsapp\s*par|whatsapp\s*karein|contact\s*on\s*whatsapp|rabta\s*karein\s*is\s*number\s*par)\b",
            r"(?:واٹس\s*ایپ\s*پر\s*رابطہ|اس\s*نمبر\s*پر\s*کال\s*کریں)"
        ]
    }
]

# Legitimate Banking Warning & Transaction Receipt Patterns
LEGITIMATE_WARNING_PATTERNS = [
    r"\b(?:do\s*not\s*share|never\s*share|kisi\s*(?:se|ko)?\s*share\s*na\s*karein|kisi\s*ko\s*mat\s*batayein)\b",
    r"\b(?:bank\s*(?:staff|officer)?\s*will\s*never\s*ask|bank\s*kabhi\s*(?:bhi\s*)?nahi\s*mangta)\b",
    r"\b(?:confidential|if\s*you\s*did\s*not\s*request|agar\s*aap\s*ne\s*request\s*nahi\s*ki)\b",
    r"(?:کسی\s*کو\s*مت\s*بتائیں|بینک\s*کبھی\s*نہیں\s*مانگتا|کسی\s*سے\s*شیئر\s*نہ\s*کریں)",
    # Legitimate Transaction Confirmations / Receipts
    r"\b(?:successfully\s*(?:transferred|received|paid)|transaction\s*id|tid\s*:\s*\d+|new\s*balance\s*is)\b",
    r"(?:کامیابی\s*سے\s*منتقل|ٹرانزیکشن\s*آئی\s*ڈی|بل\s*جمع\s*ہو\s*چکا\s*ہے|ادا\s*ہو\s*گیا|بقایا\s*بیلنس)",
    r"\b(?:out\s*for\s*delivery|order\s*#?\s*\d+\s*has\s*been\s*dispatched|delivery\s*time)\b"
]


def run_rules(text: str) -> Tuple[float, List[RedFlag], bool]:
    """
    Evaluate deterministic rules against input text.
    Returns:
    - total_score: float (accumulated scam points)
    - red_flags: List of detected RedFlag objects with exact substring quotes
    - is_legit_alert: bool (True if text is a verified legitimate security warning/OTP alert/receipt)
    """
    if not text:
        return 0.0, [], False

    red_flags: List[RedFlag] = []
    total_score = 0.0

    # Check for Official BISP 8171 notification without personal mobile number or fees
    is_official_8171 = bool(
        re.search(r"\b8171\b", text) and
        re.search(r"\b(?:sah\s*mahi|kist|konnect|bisp\.gov\.pk)\b", text, re.IGNORECASE) and
        not re.search(r"\b(?:03[0-4][0-9]|fee|easypaisa|jazzcash)\b", text, re.IGNORECASE)
    )

    # 1. Run regex-based rule checks
    for rule in RULES:
        # If it's official BISP 8171, don't flag as prize scam
        if is_official_8171 and rule["id"] in ("prize_aid_claim", "impersonation"):
            continue

        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_quote = match.group(0)
                # Verify exact substring presence
                if matched_quote in text:
                    severity = "high" if rule["weight"] >= WEIGHT_HIGH else "medium"
                    flag = RedFlag(
                        phrase=matched_quote,
                        explanation=rule["explanation"],
                        evidence_quote=matched_quote,
                        category=rule["category"],
                        severity=severity
                    )
                    # Avoid duplicate flags for the same quote
                    if not any(f.evidence_quote == matched_quote for f in red_flags):
                        red_flags.append(flag)
                        total_score += rule["weight"]
                break  # match once per rule to avoid double counting

    # 2. Entity-based rules (URLs, shorteners, suspicious TLDs)
    entities = extract_entities(text)
    
    # Suspicious shorteners (e.g. bit.ly, tinyurl)
    for shortener in entities.get("shorteners", []):
        flag = RedFlag(
            phrase=shortener,
            explanation="URL shorteners conceal the real website destination and are frequently used to bypass spam filters.",
            evidence_quote=shortener,
            category="suspicious_link",
            severity="high"
        )
        if not any(f.evidence_quote == shortener for f in red_flags):
            red_flags.append(flag)
            total_score += WEIGHT_HIGH

    # Suspicious TLDs or IP addresses in URLs
    for sus_url in entities.get("suspicious_urls", []):
        if not any(f.evidence_quote == sus_url for f in red_flags):
            flag = RedFlag(
                phrase=sus_url,
                explanation="Unconventional domain extension or non-standard URL structure typically indicative of phishing portals.",
                evidence_quote=sus_url,
                category="suspicious_link",
                severity="high"
            )
            red_flags.append(flag)
            total_score += WEIGHT_HIGH

    # 3. Check for Legitimate Bank Warning / Receipt indicators
    has_legit_warning = is_official_8171
    if not has_legit_warning:
        for legit_pattern in LEGITIMATE_WARNING_PATTERNS:
            if re.search(legit_pattern, text, re.IGNORECASE):
                has_legit_warning = True
                break

    # If it is a legitimate transaction / OTP alert / official 8171 notification:
    if has_legit_warning:
        has_scam_link = any(f.category == "suspicious_link" for f in red_flags)
        has_harvesting = any(f.category == "credential_theft" for f in red_flags)
        # If no scam links and no credential theft requests, clear score
        if not has_scam_link and not has_harvesting:
            total_score = 0.0
            red_flags = []

    return round(total_score, 2), red_flags, has_legit_warning
