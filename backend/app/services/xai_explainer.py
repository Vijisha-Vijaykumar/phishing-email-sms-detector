"""
PhishGuard AI — XAI / Guardrail Core
Deterministic, template-based explanation engine.

Rules:
  - Only reports evidence that was ACTUALLY detected.
  - Never generates text with an LLM.
  - Maps detected cues → predefined explanation templates.
  - Provides risk-level-appropriate safety action gate.
"""

from typing import Dict, List


# ── Explanation templates ────────────────────────────────────────────────────────

_URGENCY_TEMPLATES = {
    "High":   "This message creates strong time pressure, a classic phishing technique to prevent careful thinking.",
    "Medium": "This message uses moderately urgent language to prompt quick action.",
}

_THREAT_TEMPLATES = {
    "Account suspension":    "It threatens account suspension or blocking to provoke anxiety and immediate compliance.",
    "Service disconnection": "It threatens service disconnection unless immediate action is taken.",
    "Financial loss":        "It warns of financial penalties or unauthorized charges.",
    "SIM deactivation":      "It threatens SIM deactivation, a common telecom-phishing tactic.",
    "Legal action":          "It invokes legal threats (court notices, FIRs, arrest) to intimidate the recipient.",
    "Parcel/Delivery hold":  "It uses a parcel or delivery hold to create urgency around payment or personal information.",
}

_CRED_TEMPLATES = {
    "otp_share":     "It actively requests that you share an OTP — a definitive phishing indicator (legitimate services never ask for your OTP).",
    "credential":    "It requests sensitive information such as account credentials, Aadhaar, PAN, or card details.",
    "payment":       "It contains a payment request that should be independently verified.",
}

_URL_TEMPLATES = {
    "ip_url":        "It contains a link pointing to a raw IP address instead of a domain name, which legitimate services do not do.",
    "shortened":     "It uses a shortened URL that conceals the true destination.",
    "lookalike":     "The link uses a domain that closely resembles a legitimate brand name (typosquatting).",
    "suspicious_tld":"The link's domain extension is commonly associated with low-cost abuse domains.",
    "http_only":     "The link uses unencrypted HTTP rather than HTTPS.",
    "banking_path":  "The link path contains banking or security keywords on an untrusted domain.",
    "subdomain_brand":"A known brand name appears as a subdomain of an unrelated domain.",
    "generic_suspicious": "The link has structural characteristics associated with phishing URLs.",
}

_SENDER_TEMPLATES = {
    "free_webmail":  "The message arrives from a free webmail provider (e.g. Gmail) instead of an official organizational domain.",
    "mismatch":      "The sender identifier does not match the organization the message claims to represent.",
    "suspicious":    "The sender address has characteristics associated with suspicious or spoofed senders.",
}


def build_explanation(
    risk: str,
    cues: Dict,
    url_checks: List[Dict],
    sender_check: Dict,
    entities: Dict,
    fingerprint: Dict,
) -> str:
    """
    Build a factual, template-based explanation of the risk assessment.
    Only includes statements for findings that were actually detected.
    """
    parts: List[str] = []

    # ── Risk level preamble ───────────────────────────────────────────────────────
    if risk == "High-risk":
        parts.append(
            "This message shows multiple strong indicators of a phishing attempt."
        )
    elif risk == "Suspicious":
        parts.append(
            "This message contains some characteristics that may indicate a phishing or social engineering attempt."
        )
    else:
        parts.append(
            "This message does not show strong phishing indicators based on the available analysis."
        )
        return " ".join(parts)

    detail_parts: List[str] = []

    # ── Urgency ───────────────────────────────────────────────────────────────────
    urgency = cues.get("urgency_level", "Low")
    if urgency in _URGENCY_TEMPLATES:
        detail_parts.append(_URGENCY_TEMPLATES[urgency])

    # ── Threat ────────────────────────────────────────────────────────────────────
    threat = cues.get("detected_threat", "None")
    if threat in _THREAT_TEMPLATES:
        detail_parts.append(_THREAT_TEMPLATES[threat])

    # ── Credential / OTP / Payment ────────────────────────────────────────────────
    if cues.get("has_otp_share_instruction"):
        detail_parts.append(_CRED_TEMPLATES["otp_share"])
    elif cues.get("has_credential_request") and not cues.get("has_do_not_share_instruction"):
        detail_parts.append(_CRED_TEMPLATES["credential"])

    if cues.get("has_payment_request"):
        detail_parts.append(_CRED_TEMPLATES["payment"])

    # ── URL analysis ───────────────────────────────────────────────────────────────
    for uc in url_checks:
        if not uc.get("is_suspicious"):
            continue
        flags = uc.get("flags", [])
        added = False
        for flag in flags:
            fl = flag.lower()
            if "ip-based" in fl:
                detail_parts.append(_URL_TEMPLATES["ip_url"]); added = True; break
            if "shortened" in fl or "redirect" in fl:
                detail_parts.append(_URL_TEMPLATES["shortened"]); added = True; break
            if "typosquatting" in fl or "resembles" in fl:
                detail_parts.append(_URL_TEMPLATES["lookalike"]); added = True; break
            if "suspicious tld" in fl:
                detail_parts.append(_URL_TEMPLATES["suspicious_tld"]); added = True; break
            if "non-https" in fl or "unencrypted" in fl:
                detail_parts.append(_URL_TEMPLATES["http_only"]); added = True; break
            if "banking" in fl or "security keywords" in fl:
                detail_parts.append(_URL_TEMPLATES["banking_path"]); added = True; break
            if "subdomain" in fl and "brand" in fl:
                detail_parts.append(_URL_TEMPLATES["subdomain_brand"]); added = True; break
        if not added and uc.get("is_suspicious"):
            detail_parts.append(_URL_TEMPLATES["generic_suspicious"])
        break  # One URL explanation is enough to avoid over-repetition

    # ── Sender ────────────────────────────────────────────────────────────────────
    if sender_check.get("provided") and sender_check.get("is_suspicious"):
        indicators = sender_check.get("indicators", [])
        for ind in indicators:
            il = ind.lower()
            if "free webmail" in il or "gmail" in il or "yahoo" in il:
                detail_parts.append(_SENDER_TEMPLATES["free_webmail"]); break
            if "mismatch" in il:
                detail_parts.append(_SENDER_TEMPLATES["mismatch"]); break
        else:
            detail_parts.append(_SENDER_TEMPLATES["suspicious"])

    # ── Compose final explanation ──────────────────────────────────────────────────
    if detail_parts:
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in detail_parts:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        parts.append(" ".join(unique))

    return " ".join(parts)


def build_safety_advice_structured(
    risk: str,
    cues: Dict,
    url_checks: List[Dict],
) -> List[str]:
    """
    Returns a list of contextual safety action items.
    Risk-level-appropriate. Never generic beyond necessary.
    """
    advice: List[str] = []

    if risk == "High-risk":
        advice.append("Do not click any links in this message.")
        if cues.get("has_otp_share_instruction") or cues.get("has_credential_request"):
            advice.append(
                "Do not share your OTP, PIN, password, Aadhaar, PAN, or card details with anyone — "
                "including someone claiming to be from your bank or a support team."
            )
        if cues.get("has_payment_request"):
            advice.append(
                "Do not make any payment based on this message. "
                "Verify payment requests independently through the organization's official app or verified website."
            )
        if cues.get("extracted_phones"):
            advice.append(
                "Do not call the phone number provided in this message. "
                "Use the official contact number from the organization's verified website."
            )
        advice.append(
            "Verify directly through the organization's official app or website — "
            "not through any link, number, or address contained in this message."
        )

    elif risk == "Suspicious":
        advice.append("Exercise caution before taking any action based on this message.")
        advice.append(
            "Verify the sender's identity through an independently confirmed official channel "
            "(official website, app, or published helpline number)."
        )
        if any(uc.get("is_suspicious") for uc in url_checks):
            advice.append(
                "Avoid clicking links in this message. Open the official website or app manually instead."
            )
        if cues.get("extracted_phones"):
            advice.append(
                "Avoid using contact details contained in the message for verification. "
                "Use the official contact number from the organization's verified website."
            )

    else:  # Genuine
        advice.append(
            "This message appears consistent with a legitimate notification. "
            "As general practice, always verify the organization through an independent official channel "
            "before sharing any sensitive information or making payments."
        )

    return advice
