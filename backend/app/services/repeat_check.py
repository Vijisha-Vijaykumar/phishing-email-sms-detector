"""
PhishGuard AI — Repeat Check Service
Tracks how many times similar messages have been analyzed locally.
Uses in-memory store (prototype). Data never leaves the app.
"""

import hashlib
import re
from collections import defaultdict
from typing import Dict

_history: Dict[str, int] = defaultdict(int)


def _normalize_key(text: str) -> str:
    """Loose normalization for near-duplicate session tracking."""
    t = text.lower().strip()
    t = re.sub(r'https?://\S+', '__URL__', t)
    t = re.sub(r'\b[6-9]\d{9}\b', '__PHONE__', t)
    t = re.sub(r'\s+', ' ', t)
    return hashlib.sha256(t.encode('utf-8')).hexdigest()


def check_and_increment(text: str) -> Dict:
    key = _normalize_key(text)
    _history[key] += 1
    count = _history[key]
    return {
        "count": count,
        "check_count": count,
        "message": f"You've checked this message {count} time{'s' if count != 1 else ''} in PhishGuard AI." if count > 1 else None
    }
