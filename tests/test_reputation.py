"""
Unit and integration tests for PhishGuard AI OSINT & Web Reputation Analyzer.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.main import app
from backend.app.services.reputation_analyzer import (
    check_brand_impersonation,
    match_public_scam_advisories,
    query_live_web_signals,
    analyze_web_reputation,
    OFFICIAL_BRAND_REGISTRY
)

client = TestClient(app)


class TestReputationAnalyzer:
    def test_official_brand_registry_loaded(self):
        assert "hdfc" in OFFICIAL_BRAND_REGISTRY
        assert "paypal" in OFFICIAL_BRAND_REGISTRY
        assert "chase" in OFFICIAL_BRAND_REGISTRY
        assert "sbi" in OFFICIAL_BRAND_REGISTRY

    def test_impersonation_detection_mismatch(self):
        res = check_brand_impersonation("hdfc-netbanking-kyc.com")
        assert res is not None
        assert res["is_impersonation"] is True
        assert res["brand_name"] == "HDFC Bank"
        assert "hdfcbank.com" in res["canonical_domain"]

    def test_impersonation_detection_canonical_is_clean(self):
        res = check_brand_impersonation("www.hdfcbank.com")
        assert res is None

        res_paypal = check_brand_impersonation("paypal.com")
        assert res_paypal is None

    def test_match_public_scam_advisories(self):
        alerts = match_public_scam_advisories("sbi-kyc-pan-update.net")
        assert len(alerts) > 0
        assert any("Banking KYC Phishing Campaign" in a for a in alerts)

        alerts_chase = match_public_scam_advisories("chase-identity-resolution.net")
        assert len(alerts_chase) > 0
        assert any("Chase Online Security Alert" in a for a in alerts_chase)

    def test_analyze_web_reputation_high_risk_scam(self):
        res = analyze_web_reputation(
            extracted_urls=["http://paypa1-resolution-case.biz/login"],
            sender="security@chase-verify.net"
        )
        assert res["is_known_scam"] is True
        assert "Flagged Deceptive" in res["reputation_status"]
        assert len(res["impersonation_alerts"]) > 0
        assert len(res["scam_bulletins"]) > 0
        assert len(res["sources_queried"]) >= 3

    def test_analyze_web_reputation_verified_entity(self):
        res = analyze_web_reputation(
            extracted_urls=["https://www.hdfcbank.com"],
            sender="HDFCBK"
        )
        assert res["is_known_scam"] is False
        assert res["is_verified_entity"] is True
        assert res["reputation_status"] == "Verified Official Organization"
        assert res["reputation_score"] <= 20

    def test_web_intel_api_endpoint(self):
        resp = client.post(
            "/web-intel",
            json={
                "url": "http://hdfc-update-kyc.xyz/auth",
                "sender": "HDFCBK"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "reputation_status" in data
        assert "sources_queried" in data
        assert "summary" in data
        assert data["is_known_scam"] is True
