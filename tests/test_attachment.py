"""
Unit and integration tests for PhishGuard AI Attachment and URL Security Analysis.
"""

import io
import zipfile
import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.main import app
from backend.app.services.attachment_analyzer import (
    detect_real_file_type, calculate_entropy, analyze_attachment_file, QUARANTINE_DIR
)

client = TestClient(app)


class TestAttachmentAnalyzer:
    def test_detect_real_file_type_pdf(self):
        header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        assert detect_real_file_type(header) == "pdf"

    def test_detect_real_file_type_pe(self):
        header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
        assert detect_real_file_type(header) == "pe"

    def test_detect_real_file_type_zip(self):
        header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        assert detect_real_file_type(header) == "zip_based"

    def test_detect_real_file_type_office_legacy(self):
        header = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00"
        assert detect_real_file_type(header) == "office_legacy"

    def test_entropy_calculation(self):
        zeros = b"\x00" * 1000
        assert calculate_entropy(zeros) == 0.0

        import os
        random_bytes = os.urandom(2048)
        ent = calculate_entropy(random_bytes)
        assert ent > 7.0

    def test_pdf_javascript_and_openaction(self, tmp_path):
        malicious_pdf = tmp_path / "threat.pdf"
        malicious_pdf.write_bytes(
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('pwned');) >> >>\nendobj\n"
        )
        res = analyze_attachment_file(malicious_pdf, "threat.pdf")
        assert res["risk"] == "High-risk"
        assert res["findings"]["has_javascript"] is True
        assert res["findings"]["has_open_action"] is True
        assert any("JavaScript" in ev for ev in res["evidence"])

    def test_zip_with_executable_payload(self, tmp_path):
        zip_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("statement.pdf.exe", b"MZ\x90\x00" + b"\x00" * 100)
        res = analyze_attachment_file(zip_path, "archive.zip")
        assert res["risk"] == "High-risk"
        assert "statement.pdf.exe" in res["findings"]["dangerous_files"]
        assert res["findings"]["has_double_extensions"] is True

    def test_clean_text_attachment(self, tmp_path):
        txt_path = tmp_path / "notes.txt"
        txt_path.write_bytes(b"Meeting agenda: discuss sprint deliverables.")
        res = analyze_attachment_file(txt_path, "notes.txt")
        assert res["risk"] == "Genuine"
        assert res["is_suspicious"] is False


class TestAttachmentRoutes:
    def test_analyze_attachment_endpoint(self):
        file_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        response = client.post(
            "/analyze-attachment",
            files={"file": ("report.pdf", io.BytesIO(file_bytes), "application/pdf")}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["file_name"] == "report.pdf"
        assert data["real_file_type"] == "pdf"
        assert "risk" in data
        assert "explanation" in data
        assert "safety_advice" in data
        assert "latency_ms" in data

    def test_analyze_url_endpoint_high_risk(self):
        response = client.post(
            "/analyze-url",
            json={"url": "http://192.168.1.1/login/verify-hdfc-kyc"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk"] == "High-risk"
        assert data["is_suspicious"] is True
        assert len(data["evidence"]) > 0

    def test_analyze_url_endpoint_clean(self):
        response = client.post(
            "/analyze-url",
            json={"url": "https://www.hdfcbank.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk"] == "Genuine"
        assert data["is_suspicious"] is False
