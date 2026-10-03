"""
PhishGuard AI — FastAPI Application Entry Point
"""

import sys
import os
from pathlib import Path

# Ensure project root is on path so services can import siblings
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.predict import router
from app.routes.samples import router as samples_router
from app.routes.attachment import router as attachment_router
from app.routes.virustotal import router as virustotal_router

app = FastAPI(
    title="PhishGuard AI",
    description=(
        "Explainable and Robust Phishing Detection for Email and SMS. "
        "No external LLM used at runtime. All predictions from trained ML pipeline."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Allow local React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "https://phishing-email-sms-detector-1.onrender.com", "https://phishing-email-sms-detector.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(samples_router)
app.include_router(attachment_router)
app.include_router(attachment_router, prefix="/api/attachment")
app.include_router(virustotal_router)


@app.get("/", tags=["Root"])
def root():
    return {
        "project": "PhishGuard AI",
        "tagline": "Detect before you click.",
        "docs": "/docs",
        "health": "/health",
        "predict": "/predict"
    }
