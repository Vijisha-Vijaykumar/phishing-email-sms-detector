"""
PhishGuard AI — VirusTotal Threat Intelligence Integration Service

Integrates VirusTotal v3 REST API for:
  - Real-time URL threat scanning and reputation queries
  - File hash (SHA-256) threat intelligence and malware engine detection

Features:
  - In-memory caching with TTL (reduces API quota usage)
  - Resilient timeout handling and non-blocking fallback
  - Zero external dependencies beyond requests (built-in)
"""

import os
import time
import base64
import logging
from typing import Dict, Any, Optional, List
import requests

logger = logging.getLogger("phishguard.virustotal")

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 6.0  # seconds

# In-memory cache: key -> (timestamp, data)
_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL = 600  # 10 minutes


def is_configured() -> bool:
    """Returns True if a VirusTotal API key is present."""
    return bool(VT_API_KEY and len(VT_API_KEY) >= 32)


def _get_headers() -> Dict[str, str]:
    return {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
        "User-Agent": "PhishGuard-AI-ThreatScanner/1.0"
    }


def _get_from_cache(key: str) -> Optional[Dict[str, Any]]:
    if key in _CACHE:
        ts, data = _CACHE[key]
        if time.time() - ts < _CACHE_TTL:
            return data
        del _CACHE[key]
    return None


def _set_cache(key: str, data: Dict[str, Any]) -> None:
    _CACHE[key] = (time.time(), data)


def url_to_vt_id(url: str) -> str:
    """Encodes a URL into VirusTotal's base64 URL identifier without padding."""
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("ascii").strip("=")


def check_url(url: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 URL threat intelligence for a given URL.
    Returns engine detection counts, reputation score, and safety status.
    """
    if not url or not url.strip():
        return {"configured": is_configured(), "status": "empty_url"}

    clean_url = url.strip()
    cache_key = f"url:{clean_url}"
    cached = _get_from_cache(cache_key)
    if cached:
        return cached

    if not is_configured():
        return {
            "configured": False,
            "status": "not_configured",
            "message": "VirusTotal API key not configured."
        }

    url_id = url_to_vt_id(clean_url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        resp = requests.get(endpoint, headers=_get_headers(), timeout=VT_TIMEOUT)

        if resp.status_code == 200:
            payload = resp.json().get("data", {})
            attributes = payload.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            # Extract engines that flagged it
            flagged_engines: List[Dict[str, str]] = []
            for engine_name, engine_data in results.items():
                cat = engine_data.get("category")
                if cat in ("malicious", "suspicious"):
                    flagged_engines.append({
                        "engine": engine_name,
                        "category": cat,
                        "result": engine_data.get("result", "malicious")
                    })

            verdict = "MALICIOUS" if malicious >= 2 else "SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN"

            data = {
                "configured": True,
                "status": "scanned",
                "verdict": verdict,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total,
                "reputation": attributes.get("reputation", 0),
                "tags": attributes.get("tags", []),
                "categories": attributes.get("categories", {}),
                "flagged_engines": flagged_engines[:8],
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                "last_analysis_date": attributes.get("last_analysis_date")
            }
            _set_cache(cache_key, data)
            return data

        elif resp.status_code == 404:
            # URL not yet analyzed in VirusTotal database
            data = {
                "configured": True,
                "status": "not_found",
                "verdict": "UNKNOWN",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                "message": "URL not found in VirusTotal database."
            }
            _set_cache(cache_key, data)
            return data

        elif resp.status_code == 429:
            logger.warning("VirusTotal rate limit exceeded (429).")
            return {
                "configured": True,
                "status": "rate_limited",
                "verdict": "UNKNOWN",
                "message": "VirusTotal request rate limit reached. Fallback to local heuristic engine."
            }

        else:
            return {
                "configured": True,
                "status": "error",
                "http_status": resp.status_code,
                "message": f"VirusTotal responded with HTTP {resp.status_code}."
            }

    except requests.exceptions.Timeout:
        logger.warning("VirusTotal URL query timed out.")
        return {
            "configured": True,
            "status": "timeout",
            "message": "VirusTotal connection timed out; local heuristic engine active."
        }
    except Exception as e:
        logger.error(f"VirusTotal error during URL check: {e}")
        return {
            "configured": True,
            "status": "error",
            "message": str(e)
        }


def check_file_hash(sha256: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 for a file SHA-256 hash.
    Checks multi-engine antivirus detection stats and threat classification.
    """
    if not sha256 or len(sha256.strip()) != 64:
        return {"configured": is_configured(), "status": "invalid_hash"}

    clean_hash = sha256.strip().lower()
    cache_key = f"hash:{clean_hash}"
    cached = _get_from_cache(cache_key)
    if cached:
        return cached

    if not is_configured():
        return {
            "configured": False,
            "status": "not_configured",
            "message": "VirusTotal API key not configured."
        }

    endpoint = f"{VT_BASE_URL}/files/{clean_hash}"

    try:
        resp = requests.get(endpoint, headers=_get_headers(), timeout=VT_TIMEOUT)

        if resp.status_code == 200:
            payload = resp.json().get("data", {})
            attributes = payload.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            flagged_engines: List[Dict[str, str]] = []
            for engine_name, engine_data in results.items():
                cat = engine_data.get("category")
                if cat in ("malicious", "suspicious"):
                    flagged_engines.append({
                        "engine": engine_name,
                        "category": cat,
                        "result": engine_data.get("result", "malicious")
                    })

            pop_class = attributes.get("popular_threat_classification", {})
            suggested_label = pop_class.get("suggested_threat_label")

            verdict = "MALICIOUS" if malicious >= 2 else "SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN"

            data = {
                "configured": True,
                "status": "scanned",
                "sha256": clean_hash,
                "verdict": verdict,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total,
                "threat_label": suggested_label,
                "names": attributes.get("names", [])[:5],
                "flagged_engines": flagged_engines[:8],
                "permalink": f"https://www.virustotal.com/gui/file/{clean_hash}"
            }
            _set_cache(cache_key, data)
            return data

        elif resp.status_code == 404:
            data = {
                "configured": True,
                "status": "not_found",
                "sha256": clean_hash,
                "verdict": "UNKNOWN",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "permalink": f"https://www.virustotal.com/gui/file/{clean_hash}",
                "message": "File hash not found in VirusTotal database (unseen sample)."
            }
            _set_cache(cache_key, data)
            return data

        elif resp.status_code == 429:
            return {
                "configured": True,
                "status": "rate_limited",
                "message": "VirusTotal request rate limit reached. Fallback to static quarantine analysis."
            }

        else:
            return {
                "configured": True,
                "status": "error",
                "http_status": resp.status_code,
                "message": f"VirusTotal responded with HTTP {resp.status_code}."
            }

    except requests.exceptions.Timeout:
        return {
            "configured": True,
            "status": "timeout",
            "message": "VirusTotal hash check timed out; local quarantine analysis active."
        }
    except Exception as e:
        return {
            "configured": True,
            "status": "error",
            "message": str(e)
        }
