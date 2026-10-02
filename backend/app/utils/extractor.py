"""
PhishGuard AI — Message Extraction Utilities
Extracts: URLs, phone numbers, amounts, dates, requested actions.
All deterministic — never hallucinates extracted fields.
"""

import re
from typing import Dict, List, Optional

URL_RE = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
PHONE_RE = re.compile(r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b')
AMOUNT_RE = re.compile(r'(?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:rupees?|Rs\.?|INR)\b', re.IGNORECASE)
DATE_RE = re.compile(
    r'\b(?:\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|'
    r'Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)|'
    r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|'
    r'(?:today|tonight|tomorrow)|'
    r'\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)\b',
    re.IGNORECASE
)

OTP_SHARE_RE = re.compile(
    r'\b(share (?:the )?otp|send (?:the )?otp|give (?:the )?otp|provide (?:the )?otp)\b',
    re.IGNORECASE
)
VERIFY_RE = re.compile(r'\b(verify|verification|confirm|authenticate|update (?:your|the))\b', re.IGNORECASE)
PAY_RE = re.compile(r'\b(pay|payment|transfer|pay (?:now|immediately|online))\b', re.IGNORECASE)
CLICK_RE = re.compile(r'\b(click|open (?:the )?link|visit|go to|access|log(?:in|[ -]in)?)\b', re.IGNORECASE)
CALL_RE = re.compile(r'\b(call|contact (?:us )?at|reach us|dial|ring)\b', re.IGNORECASE)
APPROVE_RE = re.compile(r'\b(approve|authorization|authorize|sanctioned)\b', re.IGNORECASE)
REPLY_RE = re.compile(r'\b(reply|respond|text back|msg back|whatsapp)\b', re.IGNORECASE)


def extract_message(text: str, subject: str = "", sender: str = "") -> Dict:
    """
    Extracts structured fields from a message.
    Returns 'Not detected' for fields that genuinely cannot be extracted.
    Never fabricates values.
    """
    combined = f"{subject} {text}".strip()
    
    urls = URL_RE.findall(combined)
    phones = PHONE_RE.findall(combined)
    amounts = AMOUNT_RE.findall(combined)
    dates = DATE_RE.findall(combined)
    
    # Determine primary requested action
    action = "None"
    if OTP_SHARE_RE.search(combined):
        action = "Share credential"
    elif VERIFY_RE.search(combined):
        action = "Verify identity"
    elif PAY_RE.search(combined):
        action = "Pay"
    elif CLICK_RE.search(combined) and urls:
        action = "Click link"
    elif CALL_RE.search(combined) and phones:
        action = "Call number"
    elif APPROVE_RE.search(combined):
        action = "Approve transaction"
    elif REPLY_RE.search(combined):
        action = "Reply/contact"
    
    return {
        "sender": sender if sender else "Not detected",
        "subject": subject if subject else "Not detected",
        "urls": urls if urls else [],
        "phones": phones if phones else [],
        "amounts": amounts if amounts else [],
        "dates": dates if dates else [],
        "requested_action": action
    }
