"""
PhishGuard AI — Attachment and URL Security Analysis Routes

Provides endpoints for static file analysis and standalone URL analysis.
Uploads are quarantined in a secure temporary directory and deleted immediately upon completion.
"""

import shutil
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel, Field

from app.services.attachment_analyzer import analyze_attachment_file, QUARANTINE_DIR
from app.services.url_analyzer import analyze_url_extended
from app.services.reputation_analyzer import analyze_web_reputation

router = APIRouter(prefix="", tags=["Security Analysis"])

_MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25MB


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to inspect")


@router.post("/analyze-attachment")
async def analyze_attachment(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Securely inspects an uploaded attachment using static analysis.
    The file is quarantined, analyzed without execution, and immediately purged.
    """
    t_start = time.perf_counter()
    filename = file.filename or "unknown_file"

    temp_path = None
    try:
        # Create unique temporary quarantine file
        with tempfile.NamedTemporaryFile(dir=QUARANTINE_DIR, delete=False) as tmp:
            temp_path = Path(tmp.name)
            bytes_written = 0
            while chunk := await file.read(65536):
                bytes_written += len(chunk)
                if bytes_written > _MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds maximum allowed upload size of 25MB."
                    )
                tmp.write(chunk)

        # Run isolated static analysis
        result = analyze_attachment_file(temp_path, filename)
        result["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 2)

        # Ensure compatibility with UI telemetry cards
        findings = result.get("findings", {})
        risk = result.get("risk", "Genuine")
        verdict = "MALICIOUS" if risk == "High-risk" else "SUSPICIOUS" if risk == "Suspicious" else "CLEAN"

        result["filename"] = result.get("file_name", filename)
        result["verdict"] = verdict
        result["risk_level"] = risk
        result["detected_type"] = result.get("real_file_type", "Unknown")
        result["file_type"] = result.get("real_file_type", "Unknown")
        result["threat_indicators"] = result.get("evidence", [])
        result["summary"] = result.get("explanation", "")

        result["has_macros"] = findings.get("has_macros", False)
        result["suspicious_macros"] = findings.get("suspicious_macros", False)
        result["has_scripts"] = findings.get("has_scripts", False)
        result["has_javascript"] = findings.get("has_javascript", False)
        result["is_encrypted"] = findings.get("is_encrypted", False)
        result["is_packed"] = findings.get("is_packed", False)
        result["entropy"] = findings.get("entropy")
        result["page_count"] = findings.get("page_count")
        result["extracted_urls"] = findings.get("extracted_urls", [])
        result["archive_contents"] = findings.get("archive_contents", [])

        return result

    finally:
        # Guarantee immediate deletion of quarantined file
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@router.post("/analyze-url")
def analyze_standalone_url(req: URLAnalysisRequest) -> Dict[str, Any]:
    """
    Performs multi-layered heuristic and structure analysis on a standalone URL.
    """
    t_start = time.perf_counter()
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    url_res = analyze_url_extended(url)
    is_suspicious = url_res.get("is_suspicious", False)
    flags = list(url_res.get("flags", []))

    # Multi-source OSINT & Web Reputation check
    web_intel = analyze_web_reputation(extracted_urls=[url])
    if web_intel.get("is_known_scam") or web_intel.get("impersonation_alerts"):
        is_suspicious = True
        for imp in web_intel.get("impersonation_alerts", []):
            if imp not in flags:
                flags.append(imp)
        for sc in web_intel.get("scam_bulletins", []):
            if sc not in flags:
                flags.append(sc)

    if (
        len(flags) >= 2 
        or any("IP-based" in f or "lookalike" in f.lower() or "typosquatting" in f.lower() or "punycode" in f.lower() for f in flags)
        or web_intel.get("is_known_scam")
    ):
        risk = "High-risk"
        explanation = f"URL exhibits high-risk indicators ({'; '.join(flags[:3])}). Target domain is likely deceptive."
        safety_advice = [
            "Do not navigate to this URL or enter credentials.",
            "If this link arrived in an unexpected message, treat it as a suspected credential harvester.",
        ]
    elif is_suspicious:
        risk = "Suspicious"
        explanation = f"URL exhibits anomalous characteristics ({'; '.join(flags[:3])}). Proceed with extreme caution."
        safety_advice = [
            "Verify the destination domain before submitting information.",
            "Check for official domain spelling manually in your browser address bar.",
        ]
    else:
        risk = "Genuine"
        explanation = "No heuristic deception patterns, look-alikes, or deceptive encoding were detected in this URL."
        safety_advice = [
            "Maintain standard browsing caution.",
            "Ensure the browser shows a valid SSL/TLS certificate when visiting.",
        ]

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "url": url,
        "risk": risk,
        "is_suspicious": is_suspicious,
        "https": url_res.get("https", True),
        "flags": flags,
        "evidence": flags,
        "trust_notes": url_res.get("trust_notes", []),
        "url_analysis": [url_res],
        "explanation": explanation,
        "safety_advice": safety_advice,
        "latency_ms": latency_ms,
        "disclaimer": "This is a heuristic URL assessment, not a guarantee of site safety.",
        "web_intel": web_intel,
    }
