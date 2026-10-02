"""
PhishGuard AI — Rule Engine & URL Analysis Tests
Implements Section 54:
- URL: shortened URL, IP URL, normal URL, look-alike domain
- Risk: genuine OTP, urgent genuine message, KYC phishing, payment phishing, credential phishing
- Sender: missing sender, normal sender, suspicious lookalike/free webmail sender
"""

import pytest
import sys
from pathlib import Path

# Add project root and backend to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.rules.rule_engine import (
    analyze_text,
    analyze_url,
    analyze_sender,
    build_evidence_list,
    build_safety_advice
)


class TestURLAnalysis:
    def test_shortened_url(self):
        result = analyze_url("http://bit.ly/kyc-update-now")
        assert result["is_suspicious"] is True
        assert any("Shortened URL" in f for f in result["flags"])

    def test_tinyurl(self):
        result = analyze_url("https://tinyurl.com/urgent-bank-verify")
        assert result["is_suspicious"] is True
        assert any("Shortened URL" in f for f in result["flags"])

    def test_ip_based_url(self):
        result = analyze_url("http://192.168.1.100/login/index.php")
        assert result["is_suspicious"] is True
        assert any("IP-based URL" in f for f in result["flags"])

    def test_lookalike_domain(self):
        result = analyze_url("http://paypa1-security-verification.com/login")
        assert result["is_suspicious"] is True
        assert any("typosquatting" in f.lower() for f in result["flags"])

    def test_normal_legitimate_url(self):
        result = analyze_url("https://www.chase.com/personal/banking")
        assert result["is_suspicious"] is False
        assert len(result["flags"]) == 0

    def test_suspicious_tld(self):
        result = analyze_url("http://sbi-reward-points.top/claim")
        assert result["is_suspicious"] is True
        assert any("Suspicious TLD" in f for f in result["flags"])


class TestSocialEngineeringCues:
    def test_genuine_otp_hard_negative(self):
        """Legitimate OTP should NOT be flagged as credential phishing threat."""
        text = "492019 is your secret OTP for Rs 1,450 at Swiggy. Do not share this OTP with anyone. Bank never asks for OTP."
        cues = analyze_text(text)
        assert cues["has_do_not_share_instruction"] is True
        assert cues["has_otp_share_instruction"] is False

    def test_urgent_genuine_notice_hard_negative(self):
        """Urgent electricity bill notice with official channel advice."""
        text = "Reminder: Rs 840 is due on electricity a/c 48102. Line will be disconnected if unpaid by 10 Oct. Pay through official DHBVN app."
        cues = analyze_text(text)
        assert cues["detected_threat"] == "Service disconnection"
        assert cues["has_credential_request"] is False

    def test_kyc_phishing_cues(self):
        text = "Your HDFC account will be suspended today. Verify KYC immediately: http://hdfc-kyc-verify.net"
        cues = analyze_text(text)
        assert cues["detected_threat"] == "Account suspension"
        assert cues["urgency_level"] == "High"
        assert cues["has_pressure_tactics"] is True

    def test_otp_phishing_near_miss(self):
        """Adversarial pair: Share OTP with executive vs Do not share."""
        phish_text = "Share the OTP 49102 with our banking executive to complete verification."
        phish_cues = analyze_text(phish_text)
        assert phish_cues["has_otp_share_instruction"] is True

        genuine_text = "Do not share this OTP with anyone. We will never ask for your OTP."
        gen_cues = analyze_text(genuine_text)
        assert gen_cues["has_do_not_share_instruction"] is True
        assert gen_cues["has_otp_share_instruction"] is False


class TestSenderAnalysis:
    def test_missing_sender(self):
        res = analyze_sender("")
        assert res["provided"] is False
        assert res["is_suspicious"] is False

    def test_free_webmail_for_bank(self):
        res = analyze_sender("hdfc-security-desk@gmail.com", text="Your HDFC account is blocked.")
        assert res["provided"] is True
        assert res["is_suspicious"] is True
        assert any("free webmail" in ind.lower() for ind in res["indicators"])

    def test_legitimate_sms_header(self):
        res = analyze_sender("VM-HDFCBK", text="Your salary has been credited.")
        assert res["provided"] is True
        assert res["format_type"] == "sms_header"

    def test_personal_phone_for_bank_alert(self):
        res = analyze_sender("+919876543210", text="Dear customer, your SBI account is locked. Update KYC.")
        assert res["provided"] is True
        assert res["is_suspicious"] is True
        assert any("personal mobile" in ind.lower() for ind in res["indicators"])


class TestSafetyAdvice:
    def test_high_risk_advice_contains_otp_warning(self):
        cues = {"has_otp_share_instruction": True, "has_credential_request": True, "extracted_urls": [], "extracted_phones": []}
        advice = build_safety_advice("High-risk", cues, [])
        assert "Never share an OTP" in advice

    def test_genuine_advice_neutral(self):
        cues = {}
        advice = build_safety_advice("Genuine", cues, [])
        assert "consistent with a legitimate notification" in advice
