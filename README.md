# Cybersecurity Trade Telemetry Gateway (Pillar VII Engine)

The **Insurance Telemetry Gateway & Actuarial Warranty Engine** (`cyber-trade-telemetry`) is the reference privacy-preserving telemetry service for **The Cybersecurity Trade Project**.

It is designed as an **edge-deployed, on-premises / private cloud utility** for enterprise Security Operations Centers (SOCs), Managed Security Service Providers (MSSPs), and Participating Employer Council (PEC) members. It generates cryptographically verifiable, zero-knowledge proofs of labor standard compliance for cyber liability insurance carriers (Cyber Underwriting & Actuarial Advisory Consortium - CUAAC) without allowing raw operational logs or employee PII to leave the enterprise network boundary.

---

## 1. Core Architecture & Edge Deployment Model

* **On-Premises / Private Cloud Edge Execution:**
  * Deployed inside the enterprise network boundary as a local CLI (`ctl-telemetry`) or private microservice sidecar.
  * Connects directly to internal SIEM/SOAR clusters (Splunk, Microsoft Sentinel, Elastic).
  * Raw operational logs, internal IP addresses, hostnames, client identifiers, and employee PII **never cross the corporate firewall**.
* **Zero-Knowledge Supervisory Ratio Scoring (Pillar III & VII):**
  * Verifies the mandatory 2:1 on-shift Journeyman-to-Apprentice operational supervision ratio.
  * Strips sensitive attributes locally and replaces practitioner IDs with salted one-way hashes (`sha256(practitioner_id)`).
  * Emits an Ed25519-signed mathematical attestation (`ZeroKnowledgeRatioProof`) that is safe for public or underwriter egress.
* **Master of Record (MoR) Verification Feed (Pillar IV & V):**
  * Validates active, licensed Master Practitioner of Record oversight and digital stamping authority on the active shift.
  * MoR standing is correlated with the authoritative National Cybersecurity Trade Board (NCTB) Clearinghouse trust root.
* **Actuarial Warranty & Discount Calculation:**
  * Evaluates consecutive compliant operational cycles and fatigue limit compliance (12-hour max shift, 10-hour rest period).
  * Calculates preferred premium discount schedules (25% to 35% warranty credits under Pillar VII).
* **SIEM / SOAR Ingestion Adapters:**
  * Pre-built local sanitization connectors for Splunk, Microsoft Sentinel, and Elastic SIEM audit logs.
* **Defense-in-Depth Security:**
  * Constant-time cryptographic verification (`hmac.compare_digest`).
  * Ed25519 digital signatures and continuous SHA-256 Merkle proof traversal.
  * Strict timestamp freshness windows (+/- 120 seconds) and nonce tracking to prevent replay attacks.

---

## 2. Directory Structure

```
telemetry/
├── public/                       # Interactive Underwriter Audit Portal (GitHub Pages)
│   ├── data/
│   │   └── sample_shifts.json    # Pre-configured SOC shift rosters for demonstration
│   ├── index.html                # Telemetry dashboard & underwriter inspector
│   ├── styles.css                # Shared ecosystem design token styles
│   └── app.js                    # WebCrypto client-side zero-knowledge proof engine
├── src/
│   └── cyber_trade_telemetry/
│       ├── __init__.py           # Package version metadata
│       ├── models.py             # Pydantic v2 telemetry, shift, and warranty schemas
│       ├── crypto.py             # Ed25519 signing, verification, and SHA-256 Merkle proofs
│       ├── engine.py             # Ratio math, fatigue checks, and warranty scoring
│       ├── api.py                # Hardened FastAPI service with auth and rate-limiting
│       ├── cli.py                # Command-line utility (`ctl-telemetry`)
│       └── connectors/
│           ├── __init__.py
│           ├── base.py           # Abstract SIEM/SOAR ingestion adapter
│           ├── splunk.py         # Splunk SOC audit exporter adapter
│           └── sentinel.py       # Microsoft Sentinel shift log adapter
├── tests/
│   ├── test_crypto.py            # Cryptographic signing and proof validation tests
│   ├── test_engine.py            # Ratio calculation, fatigue, and warranty scoring tests
│   ├── test_api.py               # API security, replay prevention, and auth tests
│   └── test_connectors.py        # SIEM adapter parsing and sanitization tests
├── pyproject.toml                # uv package manifest
└── README.md
```

---

## 3. Command-Line Interface (`ctl-telemetry`)

### Generate a Signed Telemetry Proof from a Shift Roster
```bash
ctl-telemetry generate --input shift_roster.json --key private_key.pem --output proof_attestation.json
```

### Verify an Attestation Proof (Underwriter Mode)
```bash
ctl-telemetry verify --proof proof_attestation.json --pubkey employer_pubkey.pem
```

### Calculate Actuarial Warranty Credits
```bash
ctl-telemetry evaluate-warranty --proof proof_attestation.json --base-premium 120000
```

---

## 4. Running the Hardened API Service

```bash
uv run uvicorn cyber_trade_telemetry.api:app --host 0.0.0.0 --port 8000
```

---

## 5. Local Execution & Testing

```bash
uv run pytest tests/ -v
```
