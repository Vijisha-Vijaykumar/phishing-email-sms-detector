"""
PhishGuard AI — /samples endpoint
Returns labelled samples from the curated research datasets so the UI
can offer one-click 'load from dataset' examples.
"""

import random
import csv
from pathlib import Path
from fastapi import APIRouter, Query
from typing import Optional

router = APIRouter()

# ── Dataset root ──────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_RAW  = _ROOT / "data" / "raw"

# ── CSV loaders ───────────────────────────────────────────────────────────────

def _load_sms() -> list:
    path = _RAW / "mishra_soni" / "mishra_soni_curated.csv"
    samples = []
    if not path.exists():
        return samples
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row.get("label", "ham")
            samples.append({
                "id":       row.get("sms_id", ""),
                "channel":  "SMS",
                "sender":   "",
                "subject":  "",
                "text":     row.get("text", ""),
                "label":    "phishing" if label == "smishing" else "genuine",
                "source":   "Mishra & Soni (2022)",
                "threat":   row.get("threat", ""),
                "urgency":  row.get("urgency", ""),
            })
    return samples


def _load_email() -> list:
    path = _RAW / "email_phishing" / "phishing_email_curated.csv"
    samples = []
    if not path.exists():
        return samples
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            lbl_raw = row.get("label", "0")
            label   = "phishing" if str(lbl_raw) == "1" else "genuine"
            samples.append({
                "id":       row.get("email_id", ""),
                "channel":  "Email",
                "sender":   row.get("sender", ""),
                "subject":  row.get("subject", ""),
                "text":     row.get("body", ""),
                "label":    label,
                "source":   row.get("source_corpus", "spamassassin/nazario"),
                "threat":   row.get("threat", ""),
                "urgency":  row.get("urgency", ""),
            })
    return samples


def _load_enron() -> list:
    path = _RAW / "enron" / "enron_sample_curated.csv"
    samples = []
    if not path.exists():
        return samples
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            samples.append({
                "id":       row.get("enron_id", ""),
                "channel":  "Email",
                "sender":   row.get("sender", ""),
                "subject":  row.get("subject", ""),
                "text":     row.get("body", ""),
                "label":    "genuine",
                "source":   "Enron Ham Corpus",
                "threat":   "",
                "urgency":  "Low",
            })
    return samples


def _all_samples() -> list:
    return _load_sms() + _load_email() + _load_enron()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/samples", tags=["Dataset"])
def get_samples(
    n: int = Query(default=10, ge=1, le=50, description="Number of samples to return"),
    channel: Optional[str] = Query(default=None, description="Filter by 'SMS' or 'Email'"),
    label: Optional[str]   = Query(default=None, description="Filter by 'phishing' or 'genuine'"),
    seed: Optional[int]    = Query(default=None, description="Random seed for reproducibility"),
):
    """
    Return random labelled samples from the curated research datasets.
    Used by the frontend to populate the 'Load from Dataset' panel.
    """
    channel_str = channel if isinstance(channel, str) else None
    label_str = label if isinstance(label, str) else None
    num_samples = n if isinstance(n, int) else 10
    seed_val = seed if isinstance(seed, int) else None

    pool = _all_samples()

    if channel_str:
        pool = [s for s in pool if s["channel"].lower() == channel_str.lower()]
    if label_str:
        pool = [s for s in pool if s["label"].lower() == label_str.lower()]

    if not pool:
        return {"samples": [], "total_available": 0, "filters": {"channel": channel_str, "label": label_str}}

    rng = random.Random(seed_val)
    chosen = rng.sample(pool, min(num_samples, len(pool)))

    return {
        "samples": chosen,
        "total_available": len(pool),
        "filters": {"channel": channel_str, "label": label_str},
    }


@router.get("/samples/stats", tags=["Dataset"])
def get_sample_stats():
    """Return counts of available samples per channel and label."""
    pool = _all_samples()
    stats: dict = {}
    for s in pool:
        key = f"{s['channel']}:{s['label']}"
        stats[key] = stats.get(key, 0) + 1
    return {
        "total": len(pool),
        "breakdown": stats,
        "sources": list({s["source"] for s in pool}),
    }
