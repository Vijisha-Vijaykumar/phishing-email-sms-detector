"""
PhishGuard AI — Named Entity Recognition (NER) & Entity Extraction
Deterministic, regex-based entity extraction for phishing analysis.
No external NLP API. No LLM calls.

Extracts:
  - Organizations / brands (impersonation targets)
  - Banks / financial services
  - URLs
  - Phone numbers
  - Monetary amounts
  - Dates / deadlines
  - Account / card references (structural, not raw values)
"""

import re
from typing import Dict, List

# ── Compiled patterns ────────────────────────────────────────────────────────────
_URL_RE    = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
_PHONE_RE  = re.compile(r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b')
_AMOUNT_RE = re.compile(
    r'(?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?|\b[\d,]+(?:\.\d{1,2})?\s*(?:rupees?|Rs\.?|INR)\b',
    re.IGNORECASE
)
_DATE_RE = re.compile(
    r'\b(?:\d{1,2}(?:st|nd|rd|th)?\s+'
    r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|'
    r'Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)|'
    r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|'
    r'(?:today|tonight|tomorrow|immediately|within \d+ hours?))\b',
    re.IGNORECASE
)

# Banks and financial institutions
_BANK_ORG_RE = re.compile(
    r'\b(sbi|state bank|hdfc|icici|kotak|axis bank|pnb|punjab national|'
    r'canara|union bank|bob|bank of baroda|yes bank|indusind|rbl|idfc|'
    r'paytm|phonepe|gpay|google pay|amazon pay|razorpay|upi|bhim|'
    r'paypal|mastercard|visa|rupay)\b',
    re.IGNORECASE
)

# Government / regulatory bodies
_GOVT_RE = re.compile(
    r'\b(rbi|reserve bank|sebi|irdai|trai|aadhaar|uidai|epfo|income tax|'
    r'it department|gst|customs|police|court|government|ministry|'
    r'cid|cbi|enforcement directorate)\b',
    re.IGNORECASE
)

# Technology / e-commerce brands
_TECH_ORG_RE = re.compile(
    r'\b(amazon|flipkart|meesho|snapdeal|myntra|swiggy|zomato|'
    r'microsoft|apple|google|facebook|instagram|whatsapp|netflix|'
    r'airtel|jio|bsnl|vi|vodafone|idea|'
    r'dhl|fedex|bluedart|dtdc|ekart|india post|speedpost)\b',
    re.IGNORECASE
)

# Account / card structural patterns (structure only, not raw values)
_ACCOUNT_STRUCT_RE = re.compile(
    r'\b(?:account|a/c|ac)\s*(?:no\.?|number)?\b',
    re.IGNORECASE
)
_CARD_STRUCT_RE = re.compile(
    r'\b(?:debit|credit|atm)\s+card\b|\bcard\s+(?:ending|no\.?|number)\b',
    re.IGNORECASE
)

# OTP / PIN references (structural)
_OTP_STRUCT_RE = re.compile(
    r'\b(?:otp|one[\s-]time\s+(?:password|passcode|pin)|pin|mpin)\b',
    re.IGNORECASE
)


def extract_entities(text: str, subject: str = "") -> Dict:
    """
    Extract named entities from message text.
    Returns structured entity data.
    Never exposes raw PII values for account/card numbers.
    """
    combined = f"{subject} {text}".strip()

    urls    = _URL_RE.findall(combined)
    phones  = _PHONE_RE.findall(combined)
    amounts = _AMOUNT_RE.findall(combined)
    dates   = _DATE_RE.findall(combined)

    banks       = list({m.lower() for m in _BANK_ORG_RE.findall(combined)})
    govt_bodies = list({m.lower() for m in _GOVT_RE.findall(combined)})
    tech_orgs   = list({m.lower() for m in _TECH_ORG_RE.findall(combined)})

    has_account_ref = bool(_ACCOUNT_STRUCT_RE.search(combined))
    has_card_ref    = bool(_CARD_STRUCT_RE.search(combined))
    has_otp_ref     = bool(_OTP_STRUCT_RE.search(combined))

    all_orgs = list(set(banks + govt_bodies + tech_orgs))

    return {
        "organizations":      all_orgs[:10],
        "banks_financial":    banks[:8],
        "government_bodies":  govt_bodies[:5],
        "tech_orgs":          tech_orgs[:5],
        "urls":               urls,
        "phone_numbers":      phones,
        "monetary_amounts":   amounts,
        "dates_deadlines":    dates,
        "has_account_ref":    has_account_ref,
        "has_card_ref":       has_card_ref,
        "has_otp_ref":        has_otp_ref,
        "entity_count":       len(all_orgs) + len(urls) + len(phones) + len(amounts)
    }
