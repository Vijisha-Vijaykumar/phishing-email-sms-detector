"""
PhishGuard AI — Deterministic Rule Engine
Implements Sections 15, 18, 23, 24, 25, 47, 48.
No LLM at runtime. All rules are pattern-based and deterministic.
"""

import re
from typing import Dict, List, Optional, Tuple

# -----------------------------------------------------------------------
# Compiled patterns (compiled once at module load)
# -----------------------------------------------------------------------
URGENCY_PATTERNS = re.compile(
    r'\b(immediately|urgent|urgently|right now|now|today|tonight|within 24 hours?|'
    r'last (?:warning|chance|reminder)|act (?:now|quickly|fast)|'
    r'asap|no time|final (?:notice|warning)|deadline|expires? (?:today|tonight|soon)|'
    r'don\'?t delay|respond immediately|before (?:today|tonight|midnight))\b',
    re.IGNORECASE
)

THREAT_PATTERNS = {
    "Account suspension": re.compile(
        r'\b(account (?:will be |is |has been )?(?:blocked|suspended|locked|deactivated|closed|frozen)|'
        r'blocked|suspend(?:ed)?|restrict(?:ed)?|freeze|frozen|deactivat(?:ed)?)\b',
        re.IGNORECASE
    ),
    "Service disconnection": re.compile(
        r'\b(power (?:cut|disconnect(?:ed)?|off)|(?:electricity|service|connection|internet|line|power) (?:will be |is |has been )?(?:disconnect(?:ed)?|cut|suspended)|(?:service|power|line|electricity) disconnection)\b',
        re.IGNORECASE
    ),
    "Financial loss": re.compile(
        r'\b(unauthorized (?:transaction|payment|charge)|fraud(?:ulent)?|money (?:deducted|lost|stolen)|'
        r'penalty|fine|charges?|overdue|outstanding)\b',
        re.IGNORECASE
    ),
    "SIM deactivation": re.compile(
        r'\b(sim (?:card )?(?:will be )?(?:deactivat(?:ed)?|blocked|suspend(?:ed)?)|trai (?:verification|notice))\b',
        re.IGNORECASE
    ),
    "Legal action": re.compile(
        r'\b(legal (?:action|notice|proceedings?)|court (?:summons?|order|notice)|'
        r'fir|lawsuit|prosecut(?:ion|ed)|section 138|arrest)\b',
        re.IGNORECASE
    ),
    "Parcel/Delivery hold": re.compile(
        r'\b(parcel|package|shipment|delivery|courier) (?:is |has been |will be )?'
        r'(?:held?|hold|stuck|delayed|returned|on hold|cannot be delivered)\b',
        re.IGNORECASE
    )
}

AUTHORITY_PATTERNS = re.compile(
    r'\b(bank|sbi|hdfc|icici|kotak|axis|rbi|irdai|sebi|government|govt|income tax|'
    r'tax department|trai|police|court|judiciary|epfo|uidai|aadhaar|'
    r'microsoft|apple|google|amazon|flipkart|paytm|phonepe|gpay|netflix|airtel|jio|bsnl|'
    r'dhbvn|india post|courier|delivery|amazon|dhl|fedex|bluedart|'
    r'support team|helpdesk|it department|payroll|hr)\b',
    re.IGNORECASE
)

CREDENTIAL_REQUEST_PATTERNS = re.compile(
    r'\b(otp|one[- ]time (?:password|passcode|pin)|pin|password|passcode|'
    r'cvv|card (?:number|details?)|account (?:number|details?)|netbanking|net banking|'
    r'login|credentials?|aadhaar|pan (?:card|number)|bank details?|'
    r'debit card|credit card|atm (?:pin|card)|ifsc)\b',
    re.IGNORECASE
)

PAYMENT_REQUEST_PATTERNS = re.compile(
    r'\b(pay|payment|amount due|dues?|balance|transfer|upi|neft|rtgs|imps|'
    r'cashback|refund (?:claim|to your)|redeem|credit to your account|'
    r'customs? (?:fee|duty|charge)|clearance fee|subscription fee)\b',
    re.IGNORECASE
)

FEAR_PATTERNS = re.compile(
    r'\b(suspend|block|deactivat|terminat|penalt|fine|arrest|fraud warn|'
    r'account clos|account lock|debit|loss|stolen|unauthorized|illegal)\w*\b',
    re.IGNORECASE
)

REWARD_PATTERNS = re.compile(
    r'\b(prize|win|won|cashback|reward|bonus|free|offer|claim|gift|lucky|refund (?:of|amount)|'
    r'congratulations?|selected|eligible|special offer)\b',
    re.IGNORECASE
)

OTP_SHARE_PATTERNS = re.compile(
    r'\b(share (?:the |your |this )?otp|send (?:the |your |this )?otp|give (?:the |your |this )?otp|'
    r'tell (?:the |your |this )?otp|provide (?:the |your |this )?otp|enter (?:the |your |this )?otp|'
    r'forward (?:the |your |this )?otp)\b',
    re.IGNORECASE
)

DO_NOT_SHARE_PATTERNS = re.compile(
    r'\b(do not share|never share|don\'?t share|do not give|never give|'
    r'we (?:will )?never ask|bank never asks?)\b',
    re.IGNORECASE
)

PHONE_PATTERNS = re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b')
URL_PATTERNS = re.compile(r'https?://[^\s]+|www\.[^\s]+')

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.io", "rebrand.ly", "tiny.cc", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".site", ".online", ".club", ".info", ".biz", ".link", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq"}

IP_URL_PATTERN = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}')


def analyze_text(text: str, sender: str = "", subject: str = "") -> Dict:
    """
    Core deterministic analysis of a message.
    Returns a dictionary of detected cues — never hallucinated.
    """
    full_text = f"{subject} {text}".strip()
    
    # URL extraction
    urls = URL_PATTERNS.findall(full_text)
    phones = PHONE_PATTERNS.findall(full_text)
    
    # Urgency detection
    urgency_matches = URGENCY_PATTERNS.findall(full_text)
    has_urgency = len(urgency_matches) > 0
    urgency_level = "High" if len(urgency_matches) >= 2 else ("Medium" if has_urgency else "Low")
    
    # Threat detection
    detected_threat = "None"
    for threat_name, pattern in THREAT_PATTERNS.items():
        if pattern.search(full_text):
            detected_threat = threat_name
            break
    
    # Authority / Impersonation hints
    authority_mentions = AUTHORITY_PATTERNS.findall(full_text)
    has_authority = len(authority_mentions) > 0
    
    # Credential request detection
    credential_matches = CREDENTIAL_REQUEST_PATTERNS.findall(full_text)
    has_credential_request = len(credential_matches) > 0
    
    # OTP share vs. do-not-share check
    has_do_not_share = bool(DO_NOT_SHARE_PATTERNS.search(full_text))
    raw_otp_share = bool(OTP_SHARE_PATTERNS.search(full_text))
    has_otp_share_instruction = raw_otp_share and not has_do_not_share
    
    # Payment request detection
    payment_matches = PAYMENT_REQUEST_PATTERNS.findall(full_text)
    has_payment_request = len(payment_matches) > 0
    
    # Determine credential_payment field
    if has_credential_request and has_payment_request:
        cred_pay = "Both"
    elif has_credential_request:
        cred_pay = "Credential"
    elif has_payment_request:
        cred_pay = "Payment"
    else:
        cred_pay = "None"
    
    # Requested action heuristics
    action = "None"
    if has_otp_share_instruction:
        action = "Share credential"
    elif has_credential_request and not has_do_not_share:
        action = "Verify identity"
    elif has_payment_request:
        action = "Pay"
    elif urls:
        action = "Click link"
    elif phones:
        action = "Call number"
    
    # Fear cues
    has_fear = bool(FEAR_PATTERNS.search(full_text))
    
    # Reward / lure cues
    has_reward = bool(REWARD_PATTERNS.search(full_text))
    
    # Pressure
    has_pressure = has_urgency and (has_threat := detected_threat != "None")
    
    return {
        "urgency_level": urgency_level,
        "urgency_keywords": urgency_matches[:3],
        "detected_threat": detected_threat,
        "has_authority_language": has_authority,
        "authority_mentions": list(set(authority_mentions))[:5],
        "has_credential_request": has_credential_request,
        "has_payment_request": has_payment_request,
        "credential_payment_indicator": cred_pay,
        "has_otp_share_instruction": has_otp_share_instruction,
        "has_do_not_share_instruction": has_do_not_share,
        "has_fear_language": has_fear,
        "has_reward_lure": has_reward,
        "has_pressure_tactics": has_urgency and detected_threat != "None",
        "detected_action": action,
        "extracted_urls": urls,
        "extracted_phones": phones
    }


def analyze_url(url: str) -> Dict:
    """
    Deterministic URL heuristic analysis.
    Returns flags for suspicious URL characteristics.
    """
    flags = []
    is_suspicious = False
    
    # IP-based URL
    if IP_URL_PATTERN.match(url):
        flags.append("IP-based URL (non-domain address)")
        is_suspicious = True
    
    # Extract domain
    domain_match = re.search(r'https?://([^/\s?#]+)', url)
    domain = domain_match.group(1).lower() if domain_match else url.lower()
    
    # Shortened URL
    for shortener in SHORTENER_DOMAINS:
        if domain == shortener or domain.endswith(f".{shortener}"):
            flags.append(f"Shortened URL ({shortener})")
            is_suspicious = True
            break
    
    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Suspicious TLD ({tld})")
            is_suspicious = True
            break
    
    # Typosquatting / look-alike patterns
    lookalike_map = {
        "paypa1": "paypal", "micros0ft": "microsoft", "g00gle": "google",
        "amaz0n": "amazon", "app1e": "apple", "faceb00k": "facebook"
    }
    for fake, real in lookalike_map.items():
        if fake in domain:
            flags.append(f"Possible typosquatting ('{fake}' resembles '{real}')")
            is_suspicious = True
    
    # Suspicious subdomain depth
    parts = domain.split(".")
    if len(parts) > 4:
        flags.append("Excessive subdomain depth")
        is_suspicious = True
    
    # Long random-looking strings
    path_part = url[url.find(domain) + len(domain):]
    if re.search(r'[a-zA-Z0-9]{20,}', path_part):
        flags.append("Long random-looking path string")
        is_suspicious = True
    
    return {
        "url": url,
        "is_suspicious": is_suspicious,
        "flags": flags
    }


def build_evidence_list(cues: Dict, url_checks: List[Dict]) -> List[str]:
    """
    Build a list of human-readable evidence strings.
    Only includes evidence that was ACTUALLY detected.
    Never hallucinated.
    """
    evidence = []
    
    if cues.get("urgency_level") in ("High", "Medium"):
        evidence.append(f"Urgent language detected (urgency: {cues['urgency_level']})")
    
    threat = cues.get("detected_threat", "None")
    if threat != "None":
        evidence.append(f"Threat detected: {threat}")
    
    if cues.get("has_credential_request") and not cues.get("has_do_not_share_instruction"):
        evidence.append("Credential or sensitive information request detected")
    
    if cues.get("has_otp_share_instruction"):
        evidence.append("OTP sharing instruction detected — HIGH-RISK indicator")
    
    if cues.get("has_payment_request"):
        evidence.append("Payment request detected")
    
    if cues.get("has_fear_language"):
        evidence.append("Fear-inducing language detected")
    
    if cues.get("has_pressure_tactics"):
        evidence.append("Pressure tactics: urgency combined with threat")
    
    if cues.get("has_reward_lure"):
        evidence.append("Reward / lure language detected")
    
    for url_check in url_checks:
        if url_check.get("is_suspicious"):
            for flag in url_check.get("flags", []):
                evidence.append(f"Suspicious URL: {flag}")
    
    return evidence


def build_safety_advice(risk_label: str, cues: Dict, url_checks: List[Dict]) -> str:
    """Build contextually accurate safety advice. Never claims certainty."""
    if risk_label == "Genuine":
        return (
            "This message appears consistent with a legitimate notification. "
            "Verify the organization through an independent official channel before taking any sensitive action."
        )
    
    advice_parts = []
    
    if cues.get("has_otp_share_instruction") or cues.get("has_credential_request"):
        advice_parts.append("Never share an OTP, PIN, password, or card details with anyone — including anyone claiming to be from your bank or a support team.")
    
    for url_check in url_checks:
        if url_check.get("is_suspicious"):
            advice_parts.append("Avoid opening the link in this message. Visit the organization's official website or app directly by typing it yourself.")
            break
    
    if cues.get("has_payment_request"):
        advice_parts.append("Verify any payment request through an independently confirmed official channel — not the number or link provided in this message.")
    
    if cues.get("extracted_phones"):
        advice_parts.append("Do not call the number provided in this message. Use the official contact number from the organization's verified website.")
    
    if not advice_parts:
        advice_parts.append("Exercise caution. Verify this message through the organization's official contact before taking any action.")
    
    return " | ".join(advice_parts)


def analyze_sender(sender: Optional[str], text: str = "") -> Dict:
    """
    Deterministic sender analysis (Section 47).
    Sender identity alone is NEVER proof of legitimacy.
    """
    sender = (sender or "").strip()
    indicators = []
    is_suspicious = False
    format_type = "unknown"
    mismatch_detected = False
    
    if not sender:
        return {
            "sender": "",
            "provided": False,
            "format_type": "missing",
            "is_suspicious": False,
            "mismatch_detected": False,
            "indicators": ["Sender information was not provided."],
            "note": "Sender analysis is optional. Missing sender does not imply phishing on its own.",
            "disclaimer": "Sender identity alone is never proof of legitimacy."
        }
    
    # 1. Detect format type
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', sender):
        format_type = "email"
        domain = sender.split("@")[-1].lower()
        
        # Free webmail used for institutional alerts
        free_webmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com"]
        if domain in free_webmails:
            indicators.append(f"Message sent from public free webmail provider ({domain})")
            is_suspicious = True
            
        # Check suspicious TLDs or look-alikes
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append(f"Sender email uses suspicious TLD ({tld})")
                is_suspicious = True
                
        lookalike_map = {
            "paypa1": "paypal", "micros0ft": "microsoft", "g00gle": "google",
            "amaz0n": "amazon", "app1e": "apple", "hdfc-": "hdfcbank", "sbi-": "onlinesbi"
        }
        for fake, real in lookalike_map.items():
            if fake in domain:
                indicators.append(f"Sender domain '{fake}' resembles official domain '{real}'")
                is_suspicious = True

    elif re.match(r'^(?:\+91|0)?[6-9]\d{9}$', sender) or re.match(r'^\+?\d{10,14}$', sender):
        format_type = "phone_number"
        if re.search(r'\b(bank|hdfc|sbi|icici|axis|kotak|otp|kyc)\b', text, re.IGNORECASE):
            indicators.append("Institutional notification received from personal mobile number rather than registered entity header")
            is_suspicious = True
            
    elif re.match(r'^[A-Z]{2}-[A-Z0-9]{6}$', sender, re.IGNORECASE) or re.match(r'^[A-Z0-9]{3,9}$', sender):
        format_type = "sms_header"
        indicators.append("Standard alphanumeric SMS sender header format detected.")
    else:
        format_type = "unusual"
        indicators.append(f"Unusual or malformed sender format: '{sender}'")
        is_suspicious = True
        
    # Check mismatch with claimed organization in text
    known_orgs = {
        "hdfc": ["hdfcbank.com", "hdfc"],
        "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi"],
        "icici": ["icicibank.com", "icici"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com", "amazon.in"],
        "microsoft": ["microsoft.com"],
        "netflix": ["netflix.com"],
        "apple": ["apple.com"]
    }
    
    sender_lower = sender.lower()
    text_lower = text.lower()
    for org, legit_domains in known_orgs.items():
        if org in text_lower:
            matches_org = any(d in sender_lower for d in legit_domains)
            if not matches_org and format_type in ("email", "phone_number"):
                indicators.append(f"Potential mismatch: Message claims affiliation with '{org.upper()}', but sender '{sender}' does not reflect official domain.")
                mismatch_detected = True
                is_suspicious = True

    return {
        "sender": sender,
        "provided": True,
        "format_type": format_type,
        "is_suspicious": is_suspicious,
        "mismatch_detected": mismatch_detected,
        "indicators": indicators,
        "disclaimer": "Sender identity alone is never proof of legitimacy. Spoofing is common in phishing attacks."
    }
