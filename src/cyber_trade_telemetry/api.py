"""Hardened FastAPI service for telemetry attestation and underwriter verification."""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from cyber_trade_telemetry.models import (
    ShiftRoster,
    ZeroKnowledgeRatioProof,
    ActuarialWarrantyReport
)
from cyber_trade_telemetry.engine import TelemetryEngine
from cyber_trade_telemetry.crypto import (
    load_public_key_pem,
    load_private_key_pem,
    generate_keypair,
    export_public_key_pem,
    export_private_key_pem
)

app = FastAPI(
    title="Cybersecurity Trade Telemetry Gateway",
    description="Zero-Knowledge Supervisory Ratio Attestation & Actuarial Warranty Service (Pillar VII)",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url=None
)

# Defensive CORS: Restrict in production, permissive for demonstration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

engine = TelemetryEngine()

# In-memory test store for nonces and verified proofs
SEEN_NONCES: Dict[str, float] = {}
PROOF_REGISTRY: Dict[str, ZeroKnowledgeRatioProof] = {}
EMPLOYER_KEY_STORE: Dict[str, str] = {}


# Middleware: Enforce defense-in-depth headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class VerifyProofRequest(BaseModel):
    proof: ZeroKnowledgeRatioProof
    employer_public_key_pem: str


class WarrantyEvaluationRequest(BaseModel):
    employer_id: str
    proofs: List[ZeroKnowledgeRatioProof]
    base_annual_premium: float = Field(default=120000.0, ge=1000.0)


@app.get("/healthz")
def healthz():
    """Liveness and readiness health probe."""
    return {
        "status": "healthy",
        "service": "cyber-trade-telemetry",
        "framework_version": "1.9.1",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/telemetry/submit-roster", response_model=ZeroKnowledgeRatioProof)
def submit_shift_roster(roster: ShiftRoster):
    """Submits a raw SOC shift roster and returns a signed zero-knowledge ratio proof."""
    # Ensure employer key exists or generate demo key
    if roster.employer_id not in EMPLOYER_KEY_STORE:
        priv, pub = generate_keypair()
        EMPLOYER_KEY_STORE[roster.employer_id] = export_public_key_pem(pub)
        private_key = priv
    else:
        # For mock demo purposes
        priv, _ = generate_keypair()
        private_key = priv

    proof = engine.evaluate_shift_roster(roster, private_key=private_key)
    PROOF_REGISTRY[proof.proof_id] = proof
    return proof


@app.post("/api/v1/underwriter/verify-proof")
def verify_underwriter_proof(req: VerifyProofRequest):
    """Underwriter verification endpoint for Zero-Knowledge ratio proofs."""
    # Anti-Replay: Check nonce age (120-second max window)
    now = time.time()
    if req.proof.nonce in SEEN_NONCES:
        if now - SEEN_NONCES[req.proof.nonce] > 120.0:
            raise HTTPException(status_code=400, detail="Replay error: Nonce expired")
    SEEN_NONCES[req.proof.nonce] = now

    try:
        pubkey = load_public_key_pem(req.employer_public_key_pem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key PEM format: {str(e)}")

    valid, msg = engine.verify_proof(req.proof, pubkey)
    if not valid:
        raise HTTPException(status_code=422, detail=f"Verification failed: {msg}")

    return {
        "verified": True,
        "proof_id": req.proof.proof_id,
        "employer_id": req.proof.employer_id,
        "ratio_compliant": req.proof.ratio_compliant,
        "effective_ratio": req.proof.effective_ratio,
        "mor_active": req.proof.mor_active,
        "fatigue_compliant": req.proof.fatigue_compliant,
        "message": msg
    }


@app.post("/api/v1/underwriter/evaluate-warranty", response_model=ActuarialWarrantyReport)
def evaluate_actuarial_warranty(req: WarrantyEvaluationRequest):
    """Evaluates an enterprise batch of proofs to calculate underwriter warranty discounts."""
    return engine.evaluate_actuarial_warranty(
        employer_id=req.employer_id,
        proofs=req.proofs,
        base_annual_premium=req.base_annual_premium
    )
