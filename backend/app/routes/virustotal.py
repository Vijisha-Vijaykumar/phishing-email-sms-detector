"""
PhishGuard AI — VirusTotal Dedicated Routes

Provides direct endpoints to scan URLs and inspect file hashes via the VirusTotal v3 REST API.
"""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.virustotal_service import (
    check_url,
    check_file_hash,
    is_configured,
    VT_API_KEY
)

router = APIRouter(prefix="", tags=["VirusTotal Intelligence"])


class VTURLRequest(BaseModel):
    url: str = Field(..., description="The URL to check against VirusTotal")


@router.get("/virustotal/status")
@router.get("/api/virustotal/status")
def virustotal_status() -> Dict[str, Any]:
    """Returns the integration status of the VirusTotal service."""
    configured = is_configured()
    return {
        "configured": configured,
        "engine": "VirusTotal v3 REST API",
        "api_key_configured": configured,
        "rate_limiting": "In-memory TTL cache active"
    }


@router.post("/virustotal/check-url")
@router.post("/api/virustotal/check-url")
def virustotal_check_url(req: VTURLRequest) -> Dict[str, Any]:
    """Inspects a URL using VirusTotal's global threat intelligence dataset."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return check_url(url)


@router.get("/virustotal/check-hash/{sha256}")
@router.get("/api/virustotal/check-hash/{sha256}")
def virustotal_check_hash(sha256: str) -> Dict[str, Any]:
    """Inspects a SHA-256 file hash using VirusTotal's antivirus scan repository."""
    sha = sha256.strip().lower()
    if len(sha) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA-256 hash length (must be 64 hexadecimal characters).")
    return check_file_hash(sha)
