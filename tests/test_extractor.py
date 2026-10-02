"""
PhishGuard AI — Extraction Unit Tests
Implements Section 54:
- Extraction: URL, amount, phone, date, requested action
- Empty / missing values return 'Not detected' or empty lists, never hallucinated
"""

import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.utils.extractor import extract_message


class TestExtractor:
    def test_extract_url(self):
        text = "Check your bill at https://pay.dhbvn.org.in/bill/84920 before deadline."
        res = extract_message(text)
        assert "https://pay.dhbvn.org.in/bill/84920" in res["urls"]

    def test_extract_phone(self):
        text = "Call customer support at 9876543210 immediately to unblock your card."
        res = extract_message(text)
        assert any("9876543210" in p for p in res["phones"])
        assert res["requested_action"] == "Call number"

    def test_extract_amount(self):
        text = "Your pending electricity bill of Rs 1,450.50 is overdue."
        res = extract_message(text)
        assert len(res["amounts"]) > 0
        assert any("1,450" in a for a in res["amounts"])

    def test_extract_date(self):
        text = "Line will be disconnected on 15th October if payment is not received today."
        res = extract_message(text)
        assert len(res["dates"]) > 0

    def test_action_share_credential(self):
        text = "Please share the OTP sent to your phone to confirm the transaction."
        res = extract_message(text)
        assert res["requested_action"] == "Share credential"

    def test_action_verify_identity(self):
        text = "Your KYC is expired. Please verify your identity now."
        res = extract_message(text)
        assert res["requested_action"] == "Verify identity"

    def test_missing_fields_default_to_not_detected(self):
        text = "Hello, how are you doing?"
        res = extract_message(text)
        assert res["sender"] == "Not detected"
        assert res["subject"] == "Not detected"
        assert res["urls"] == []
        assert res["phones"] == []
        assert res["amounts"] == []
        assert res["requested_action"] == "None"
