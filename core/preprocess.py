"""
core/preprocess.py
Text normalization, script detection, and entity extraction.
IMPORTANT: URLs are extracted as raw strings and analyzed via string properties only.
NO URLs ARE EVER FETCHED OR OPENED.
"""

import re
import unicodedata
from typing import Dict, List, Any


# Common Roman Urdu indicator words / function words
ROMAN_URDU_MARKERS = {
    "aap", "apka", "aapka", "apki", "aapki", "apke", "aapke",
    "karein", "karo", "karen", "karna", "hoga", "hogi", "hoge", "haye", "hai", "hain", "hon",
    "bisp", "benazir", "inaam", "inam", "lottery", "qurandazi", "qurandazi",
    "rabta", "bhejein", "bhejo", "bhejain", "shukriya", "meharbani",
    "hum", "mera", "meri", "mere", "tum", "tumhara", "tumhari",
    "yeh", "woh", "kis", "kisi", "mat", "nahi", "nahin", "na",
    "paisay", "paisa", "rupay", "hazar", "lakh", "crore",
    "muft", "tohfa", "mubarak", "milay", "milega", "milegi",
    "shanakhti", "card", "wazifa", "imdad", "khata", "band"
}

# Suspicious TLDs frequently abused in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".loan", ".vip", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".buzz", ".fit", ".rest", ".monster", ".bar", ".cfd"
}

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy", "shorturl.at", "ow.ly", "goo.gl"
}


MAX_INPUT_LENGTH = 2000


def normalize_text(text: str) -> str:
    """
    Standardize spaces and unicode while preserving case and exact characters.
    Enforces maximum input length of 2000 characters.
    """
    if not text:
        return ""
    # Enforce 2000 character security limit
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
    # Normalize unicode to standard NFKC
    normalized = unicodedata.normalize("NFKC", text)
    # Replace multiple spaces/tabs with single space, keeping newline structure clean
    normalized = re.sub(r"[ \t]+", " ", normalized)
    return normalized.strip()


def detect_script(text: str) -> str:
    """
    Detect script and language style:
    - 'urdu_script': Contains significant Arabic/Urdu Unicode characters.
    - 'roman_urdu': Latin script with Urdu vocabulary/grammar markers.
    - 'english': Latin script predominantly in English.
    - 'mixed': Contains significant mix of scripts (e.g. Urdu script + Latin words).
    """
    if not text:
        return "english"

    # Count Urdu/Arabic characters: U+0600 to U+06FF and extended Arabic blocks
    urdu_chars = len(re.findall(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]", text))
    latin_chars = len(re.findall(r"[A-Za-z]", text))
    total_alpha = urdu_chars + latin_chars

    if total_alpha == 0:
        return "english"

    urdu_ratio = urdu_chars / total_alpha
    latin_ratio = latin_chars / total_alpha

    # Mixed script (both Urdu script and Latin text present in significant proportion)
    if urdu_ratio > 0.15 and latin_ratio > 0.15:
        return "mixed"

    if urdu_ratio >= 0.5:
        return "urdu_script"

    # For Latin script, test for Roman Urdu markers
    words = [w.lower().strip(".,!?:;\"'()[]{}") for w in text.split()]
    matched_markers = sum(1 for w in words if w in ROMAN_URDU_MARKERS)

    if len(words) > 0 and (matched_markers / len(words) >= 0.10 or matched_markers >= 2):
        return "roman_urdu"

    return "english"


def extract_entities(text: str) -> Dict[str, Any]:
    """
    Extract URLs, phone numbers, and amounts from text.
    URLs are strictly analyzed as strings and NEVER fetched or accessed.
    """
    if not text:
        return {
            "urls": [],
            "suspicious_urls": [],
            "shorteners": [],
            "phone_numbers": [],
            "amounts": []
        }

    # URL extraction pattern (matches http/https links, www. links, or naked domains with common TLDs)
    url_pattern = r"(?:https?:\/\/|www\.)[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:com|org|net|pk|xyz|top|work|click|loan|vip|info|biz|me|online|site)[^\s<>\"']*"
    raw_urls = re.findall(url_pattern, text, re.IGNORECASE)
    
    cleaned_urls = []
    suspicious_urls = []
    shorteners = []

    for u in raw_urls:
        u_clean = u.rstrip(".,!?:;)]}\"'")
        if u_clean and u_clean not in cleaned_urls:
            cleaned_urls.append(u_clean)
            u_lower = u_clean.lower()
            
            # Check shorteners
            if any(shortener in u_lower for shortener in URL_SHORTENERS):
                shorteners.append(u_clean)
            
            # Check suspicious TLDs or lookalike patterns
            has_suspicious_tld = any(u_lower.endswith(tld) or (tld + "/") in u_lower for tld in SUSPICIOUS_TLDS)
            is_ip_address = bool(re.search(r"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower))
            
            if has_suspicious_tld or is_ip_address or ("bit.ly" in u_lower) or ("tinyurl" in u_lower):
                suspicious_urls.append(u_clean)

    # Pakistani Phone Numbers / Shortcodes:
    # 1) Mobile numbers: 03xx-xxxxxxx, 03xxxxxxxxx, +923xxxxxxxxx, 923xxxxxxxxx
    # 2) Government/Bank shortcodes: 8171, 9999, etc.
    phone_pattern = r"(?:\+92|92|0)?3[0-4][0-9][-\s]?[0-9]{7}\b|\b(?:8171|8070|8500|9900)\b"
    phones = list(set(re.findall(phone_pattern, text)))

    # Amounts: PKR, Rs, lacs, crore, hazar
    amount_pattern = r"(?:(?:Rs\.?|PKR)\s*[\d,]+(?:\.\d+)?|\b[\d,]+\s*(?:lakh|lac|crore|hazar|rupees|rupay)\b)"
    amounts = list(set(re.findall(amount_pattern, text, re.IGNORECASE)))

    return {
        "urls": cleaned_urls,
        "suspicious_urls": suspicious_urls,
        "shorteners": shorteners,
        "phone_numbers": phones,
        "amounts": amounts
    }
