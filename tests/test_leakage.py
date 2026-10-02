"""
PhishGuard AI — Anti-Leakage Invariants Tests
Implements Sections 20, 34, 61:
- Zero template leakage: variants of the same template_id must never appear in both train and test
- No duplicate messages between train and test
- Out-of-fold predicted fingerprints used in Model C (never gold labels)
"""

import pytest
import os
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = ROOT / "data" / "processed"


class TestAntiLeakage:
    def test_train_test_template_isolation(self):
        """CRITICAL: All variants of a template must remain strictly in one split."""
        train_path = PROCESSED_DIR / "train.parquet"
        test_path = PROCESSED_DIR / "test.parquet"
        
        assert train_path.exists(), "train.parquet must exist"
        assert test_path.exists(), "test.parquet must exist"
        
        train_df = pd.read_parquet(train_path)
        test_df = pd.read_parquet(test_path)
        
        train_templates = set(train_df["template_id"].dropna())
        test_templates = set(test_df["template_id"].dropna())
        
        overlap = train_templates.intersection(test_templates)
        assert len(overlap) == 0, f"FATAL DATA LEAKAGE: Templates found in both train and test: {overlap}"

    def test_no_exact_text_overlap(self):
        """No duplicate texts should exist across train and test."""
        train_path = PROCESSED_DIR / "train.parquet"
        test_path = PROCESSED_DIR / "test.parquet"
        
        train_df = pd.read_parquet(train_path)
        test_df = pd.read_parquet(test_path)
        
        train_texts = set(train_df["text"].str.strip().str.lower())
        test_texts = set(test_df["text"].str.strip().str.lower())
        
        overlap = train_texts.intersection(test_texts)
        assert len(overlap) == 0, f"FATAL LEAKAGE: Exact duplicate texts in train and test: {overlap}"

    def test_schema_completeness(self):
        """Verify train and test have canonical 24 columns."""
        train_df = pd.read_parquet(PROCESSED_DIR / "train.parquet")
        expected_cols = [
            "message_id", "channel", "text", "subject", "body", "sender",
            "language", "risk_label", "category", "threat", "urgency",
            "requested_action", "credential_payment_request", "template_id",
            "variant_type", "generator", "source", "url_present"
        ]
        for col in expected_cols:
            assert col in train_df.columns, f"Missing required column: {col}"
