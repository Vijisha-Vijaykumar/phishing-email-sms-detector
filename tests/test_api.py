"""
PhishGuard AI — FastAPI Endpoints & Integration Tests
Tests: API validation, prediction pipeline, auxiliary endpoints.
"""

import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.main import app

client = TestClient(app)


class TestHealthAndInfo:
    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "PhishGuard" in data["service"]

    def test_model_info_endpoint(self):
        resp = client.get("/model-info")
        assert resp.status_code == 200
        data = resp.json()
        assert "models" in data
        assert isinstance(data["models"], list)

    def test_root_endpoint(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "PhishGuard AI" in resp.json()["project"]


class TestPredictEndpoint:
    def test_predict_sms_phishing(self):
        payload = {
            "channel": "SMS",
            "text": "Your HDFC account will be suspended today. Verify KYC immediately: http://hdfc-kyc-verify.net",
            "sender": "HDFCBK"
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk"] in ("High-risk", "Suspicious", "Genuine")
        assert "confidence" in data
        assert data["channel"] == "SMS"
        # Fingerprint
        assert "fingerprint" in data
        assert "threat" in data["fingerprint"]
        assert "urgency" in data["fingerprint"]
        assert "requested_action" in data["fingerprint"]
        assert "credential_payment_request" in data["fingerprint"]
        # Cues
        assert "cues" in data
        assert "urgency" in data["cues"]
        assert "threat" in data["cues"]
        # URL analysis (new field name)
        assert "url_analysis" in data
        assert len(data["url_analysis"]) > 0
        # Evidence and explanation
        assert "evidence" in data
        assert "explanation" in data
        assert isinstance(data["explanation"], str)
        # Safety advice is now a list
        assert "safety_advice" in data
        assert isinstance(data["safety_advice"], list)
        # Other fields
        assert "repeat_check" in data
        assert "disclaimer" in data
        assert "latency_ms" in data
        # Entities
        assert "entities" in data
        assert "urls" in data["entities"]
        assert "pii_detected" in data["entities"]

    def test_predict_email_phishing(self):
        payload = {
            "channel": "Email",
            "subject": "Urgent: Verify Your Chase Bank Account",
            "text": "Subject: Urgent: Verify Your Chase Bank Account\n\nYour account has been locked. Verify identity at http://192.168.1.10/login to prevent suspension.",
            "sender": "security@chase-verify.net"
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["channel"] == "Email"
        assert "sender_check" in data
        assert data["sender_check"]["provided"] is True

    def test_predict_genuine_otp(self):
        payload = {
            "channel": "SMS",
            "text": "492019 is your secret OTP for Rs 500 at Amazon. Do not share this OTP with anyone. Bank never calls for OTP.",
            "sender": "AMAZON"
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "safety_advice" in data
        assert isinstance(data["safety_advice"], list)

    def test_predict_invalid_channel(self):
        payload = {
            "channel": "WhatsApp",
            "text": "Hello there"
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 422  # Pydantic validator raises 422

    def test_predict_empty_text(self):
        payload = {
            "channel": "SMS",
            "text": "   "
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 422  # Pydantic validator raises 422

    def test_predict_text_too_long(self):
        payload = {
            "channel": "SMS",
            "text": "A" * 17_000
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 422

    def test_predict_pii_detected(self):
        """PII summary should count phones and card numbers."""
        payload = {
            "channel": "SMS",
            "text": "Call 9876543210 and share card 4111 1111 1111 1111 to claim prize.",
            "sender": "OFFER"
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        pii = data["entities"]["pii_detected"]
        assert pii["phone_numbers_detected"] >= 1
        assert pii["card_numbers_detected"] >= 1

    def test_predict_url_analysis_flags(self):
        """Suspicious URL should produce flags in url_analysis."""
        payload = {
            "channel": "SMS",
            "text": "Click http://bit.ly/bank-login-xyz to verify."
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["url_analysis"]) > 0
        assert data["url_analysis"][0]["is_suspicious"] is True
        assert len(data["url_analysis"][0]["flags"]) > 0

    def test_predict_entity_extraction(self):
        """NER should detect HDFC and monetary amount."""
        payload = {
            "channel": "SMS",
            "text": "Your HDFC account is suspended. Pay Rs 2,500 to restore service."
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        ents = data["entities"]
        assert any("hdfc" in b for b in ents.get("banks_financial", []))
        assert len(ents.get("monetary_amounts", [])) > 0

    def test_cues_contains_new_fields(self):
        """Cues dict should include detected_action and otp_share."""
        payload = {
            "channel": "SMS",
            "text": "Share the OTP immediately to verify your SBI account."
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "otp_share" in data["cues"]
        assert "detected_action" in data["cues"]

    def test_latency_ms_present(self):
        payload = {
            "channel": "SMS",
            "text": "Test message for latency check."
        }
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "latency_ms" in data
        assert isinstance(data["latency_ms"], (int, float))


class TestAuxiliaryEndpoints:
    def test_fingerprint_endpoint(self):
        payload = {
            "channel": "SMS",
            "text": "Airtel SIM will be deactivated today. Submit Aadhaar immediately."
        }
        resp = client.post("/fingerprint", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "threat" in data
        assert "urgency" in data
        assert "requested_action" in data
        assert "credential_payment_request" in data

    def test_extract_endpoint(self):
        payload = {
            "channel": "SMS",
            "text": "Pay electricity bill of Rs 1,450 before 15 Oct at https://billpay.in or call 9876543210"
        }
        resp = client.post("/extract", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["urls"]) > 0
        assert len(data["phones"]) > 0
        assert len(data["amounts"]) > 0
        # New: entity data
        assert "entities" in data
        assert "urls" in data["entities"]

    def test_url_check_endpoint(self):
        resp = client.post("/url-check", json={"url": "http://bit.ly/bank-login-xyz"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_suspicious"] is True
        # New extended fields
        assert "trust_notes" in data
        assert "https" in data
        assert data["https"] is False

    def test_url_check_trusted_domain(self):
        resp = client.post("/url-check", json={"url": "https://hdfcbank.com/netbanking"})
        assert resp.status_code == 200
        data = resp.json()
        assert "trust_notes" in data
        assert any("trusted" in note.lower() for note in data["trust_notes"])

    def test_url_check_ip_based(self):
        resp = client.post("/url-check", json={"url": "http://192.168.1.10/login"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_suspicious"] is True
        assert any("IP" in f for f in data["flags"])

    def test_sender_check_endpoint(self):
        resp = client.post("/sender-check", json={"sender": "support@paypa1-help.biz", "text": "PayPal login"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["provided"] is True
        assert data["is_suspicious"] is True

    def test_repeat_check_increments(self):
        text = "Unique test message for repeat check verification: 981726490"
        resp1 = client.post("/repeat-check", json={"channel": "SMS", "text": text})
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["count"] >= 1

        resp2 = client.post("/repeat-check", json={"channel": "SMS", "text": text})
        data2 = resp2.json()
        assert data2["count"] == data1["count"] + 1

    def test_research_metrics_endpoint(self):
        resp = client.get("/research/metrics")
        assert resp.status_code == 200


class TestPIIMasker:
    """Unit tests for PII masking service."""

    def test_phone_masked(self):
        from backend.app.services.pii_masker import sanitize_and_mask
        masked, summary = sanitize_and_mask("Call 9876543210 immediately.")
        assert "9876543210" not in masked
        assert "[PHONE]" in masked
        assert summary["phone_numbers_detected"] == 1

    def test_email_masked(self):
        from backend.app.services.pii_masker import sanitize_and_mask
        masked, summary = sanitize_and_mask("Contact us at attacker@evil.com for help.")
        assert "attacker@evil.com" not in masked
        assert "[EMAIL]" in masked
        assert summary["email_addresses_detected"] == 1

    def test_card_masked(self):
        from backend.app.services.pii_masker import sanitize_and_mask
        masked, summary = sanitize_and_mask("Your card 4111 1111 1111 1111 has been charged.")
        assert "4111" not in masked
        assert "[CARD]" in masked
        assert summary["card_numbers_detected"] == 1

    def test_clean_text_unaffected(self):
        from backend.app.services.pii_masker import sanitize_and_mask
        text = "Your account will be suspended. Click the link now."
        masked, summary = sanitize_and_mask(text)
        # Core phishing words must not be masked
        assert "suspended" in masked
        assert "Click" in masked
        assert all(v == 0 for v in summary.values())


class TestNERExtractor:
    """Unit tests for NER extractor."""

    def test_bank_entity_detected(self):
        from backend.app.services.ner_extractor import extract_entities
        ents = extract_entities("Your HDFC account is blocked. Pay Rs 2,500.")
        assert any("hdfc" in b for b in ents["banks_financial"])
        assert len(ents["monetary_amounts"]) > 0

    def test_govt_entity_detected(self):
        from backend.app.services.ner_extractor import extract_entities
        ents = extract_entities("TRAI notice: Submit Aadhaar details.")
        assert any("trai" in g or "aadhaar" in g for g in ents["government_bodies"])

    def test_url_extracted(self):
        from backend.app.services.ner_extractor import extract_entities
        ents = extract_entities("Click https://evil-bank.xyz/login to verify.")
        assert len(ents["urls"]) > 0

    def test_otp_ref_detected(self):
        from backend.app.services.ner_extractor import extract_entities
        ents = extract_entities("Enter your OTP to continue.")
        assert ents["has_otp_ref"] is True


class TestURLAnalyzer:
    """Unit tests for extended URL analyzer."""

    def test_ip_url_flagged(self):
        from backend.app.services.url_analyzer import analyze_url_extended
        result = analyze_url_extended("http://192.168.1.10/login")
        assert result["is_suspicious"] is True
        assert any("IP" in f for f in result["flags"])

    def test_shortened_url_flagged(self):
        from backend.app.services.url_analyzer import analyze_url_extended
        result = analyze_url_extended("http://bit.ly/abc123")
        assert result["is_suspicious"] is True

    def test_typosquatting_flagged(self):
        from backend.app.services.url_analyzer import analyze_url_extended
        result = analyze_url_extended("https://paypa1.com/login")
        assert result["is_suspicious"] is True

    def test_trusted_domain_noted(self):
        from backend.app.services.url_analyzer import analyze_url_extended
        result = analyze_url_extended("https://hdfcbank.com/netbanking")
        assert any("trusted" in note.lower() for note in result.get("trust_notes", []))

    def test_https_flag(self):
        from backend.app.services.url_analyzer import analyze_url_extended
        r1 = analyze_url_extended("https://example.com")
        r2 = analyze_url_extended("http://example.com")
        assert r1["https"] is True
        assert r2["https"] is False
