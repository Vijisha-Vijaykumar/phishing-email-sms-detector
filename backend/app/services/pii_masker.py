"""
PhishGuard AI — PII Tokenization & Masking Service
Masks sensitive values before any storage/logging while preserving
enough structure for phishing analysis.

Masked values are NOT exposed in API responses.
"""

import re
from typing import Tuple

# ── PII patterns ────────────────────────────────────────────────────────────────
_PHONE_RE = re.compile(r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b')
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_ACCOUNT_RE = re.compile(
    r'\b(?:account(?:\s+no\.?|\s+number)?\s*:?\s*[A-Z0-9]{6,20}|'
    r'a/c\s*(?:no\.?)?\s*:?\s*[A-Z0-9]{6,20}|'
    r'\b\d{9,18}\b)',               # long digit strings (account/card/txn)
    re.IGNORECASE
)
_CARD_RE = re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b')   # 16-digit card numbers
_TXN_RE = re.compile(
    r'\b(?:txn|transaction|ref|utr|rrn)[\s#:]*[A-Z0-9]{8,20}\b',
    re.IGNORECASE
)
_OTP_RE = re.compile(r'\b\d{4,8}\b')   # potential OTP/PIN digits


def sanitize_and_mask(text: str) -> Tuple[str, dict]:
    """
    Returns (masked_text, pii_summary).

    masked_text: safe-for-processing version where PII tokens are replaced
                 with structural placeholders (e.g. [PHONE], [EMAIL]).
    pii_summary: counts of each PII type detected — not raw values.
    """
    text = text.strip()

    phones  = _PHONE_RE.findall(text)
    emails  = _EMAIL_RE.findall(text)
    cards   = _CARD_RE.findall(text)
    txns    = _TXN_RE.findall(text)

    masked = text
    masked = _CARD_RE.sub('[CARD]', masked)      # cards before accounts
    masked = _PHONE_RE.sub('[PHONE]', masked)
    masked = _EMAIL_RE.sub('[EMAIL]', masked)
    masked = _TXN_RE.sub('[TXN_REF]', masked)
    # Do NOT mask OTPs — they are content-bearing for phishing detection.

    pii_summary = {
        "phone_numbers_detected":     len(phones),
        "email_addresses_detected":   len(emails),
        "card_numbers_detected":      len(cards),
        "transaction_refs_detected":  len(txns),
    }

    return masked, pii_summary
