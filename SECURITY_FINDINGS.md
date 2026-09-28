# Secure Document Provenance Platform - Security Audit & Findings Report

**Audit Date**: September 2026  
**Phase**: Phase 15 End-to-End Security Validation & Hardening  
**Scope**: Full Codebase Audit across Backend (FastAPI / SQLAlchemy), Frontend (React / Tailwind), Cryptographic Subsystems (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65, AES-256-GCM, Argon2id), Database Models & Migrations, Ledger Adapters, and Deployment Infrastructure.

---

## 1. Executive Summary

A comprehensive, zero-compromise static and dynamic security audit was conducted on the **Secure Document Provenance Platform**. All development bypasses, permissive defaults, hardcoded fallbacks, and potential privilege escalation vectors were audited and remediated.

**Total Issues Identified**: 8  
- **Critical**: 2 (Remediated)  
- **High**: 3 (Remediated)  
- **Medium**: 2 (Remediated)  
- **Low / Architectural Constraints**: 1 (Documented Factual Limitation)

---

## 2. Classified Security Findings & Remediation Details

### Finding SEC-01: Permissive Fallback and Missing Fail-Closed Enforcement for Cryptographic KEKs in Production Mode
* **Severity**: CRITICAL
* **Affected Component**: `backend/app/config/settings.py`, `backend/app/main.py`
* **Description**: The platform previously used pre-seeded development Key Encryption Keys (`DEV_DEFAULT_KEK_BASE64`) and allowed `SECRET_KEY="changeme-secret-key-..."` if explicit environment variables were omitted. In a production environment (`ENVIRONMENT=production`), failure to provide cryptographically random external keys would allow predictable KEK derivation and session token forging.
* **Evidence**:
  ```python
  # Vulnerable logic:
  if self.ENVIRONMENT == "production" and self.DOCUMENT_KEK_BASE64 == DEV_DEFAULT_KEK_BASE64:
      raise ValueError(...)
  # Missing checks for PROVENANCE_KEY_KEK_BASE64, MFA_ENCRYPTION_KEY_BASE64, FORENSIC_MASTER_KEY_BASE64, and SECRET_KEY
  ```
* **Remediation**:
  Implemented strict, fail-closed production startup verification in `validate_cryptographic_configuration()`:
  - Fails startup immediately if `SECRET_KEY` has fewer than 32 characters or matches development defaults.
  - Fails startup if `DOCUMENT_KEK_BASE64`, `RECIPIENT_KEY_KEK_BASE64`, `PROVENANCE_KEY_KEK_BASE64`, `MFA_ENCRYPTION_KEY_BASE64`, or `FORENSIC_MASTER_KEY_BASE64` match default seeds or fail to decode to exactly 32 bytes (256-bit CSPRNG entropy).
  - Rejects CORS wildcard (`*`) when running in production.
* **Verification**: Verified via `test_phase15_e2e_and_hardening.py::test_03_production_mode_fails_closed_on_insecure_secrets` and `test_crypto_phase4.py::test_production_mode_refuses_default_recipient_kek`. Both tests pass.

---

### Finding SEC-02: Multi-Party Approval Replay & Session Token Reuse
* **Severity**: CRITICAL
* **Affected Component**: `backend/app/services/decryption_service.py`, `backend/app/services/viewer_session_service.py`
* **Description**: Multi-party approval requests authorize access to sensitive documents. If an approved request was not marked consumed atomically during decryption, a malicious actor or intercepted session could replay the approval token across multiple decryption or viewer sessions.
* **Evidence**: Verified that attempting to reuse an approval request with status `CONSUMED` is rejected with:
  `{"error":{"code":"FORBIDDEN","message":"Approval request has already been consumed by another decryption session."}}`
* **Remediation**: Atomic transition of approval request status from `APPROVED` to `CONSUMED` inside the transaction boundary of `DecryptionService.request_and_decrypt()`. Subsequent requests fail closed.
* **Verification**: Verified via `test_phase15_e2e_and_hardening.py::test_07_complete_end_to_end_journey_and_investigation` (replay attempt returns HTTP 403 Forbidden with exact code).

---

### Finding SEC-03: Docker Container Runtime Privileges (Root Execution)
* **Severity**: HIGH
* **Affected Component**: `backend/Dockerfile`
* **Description**: The initial backend Dockerfile executed the FastAPI Uvicorn process as `root`. If an unauthenticated or post-compromise vulnerability were exploited, container escape and host filesystem compromise risks would be elevated.
* **Evidence**:
  ```dockerfile
  # Prior state:
  CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
  ```
* **Remediation**:
  Hardened the `backend/Dockerfile` by creating a dedicated, unprivileged system group and user (`appuser`, UID/GID 1000). Chowned `/app` and `/app/storage` to `appuser` and added `USER appuser`.
* **Verification**: Dockerfile inspect confirms non-root `USER appuser` directive and read/write permission containment for storage volumes.

---

### Finding SEC-04: Lack of Distributed Request Tracing and Correlation ID
* **Severity**: HIGH
* **Affected Component**: `backend/app/main.py`, HTTP Request Pipeline
* **Description**: Auditing cross-tier operations (Auth -> MFA -> Decrypt -> Provenance -> Viewer -> Investigation) across distributed logs required correlating distinct records without a unified request correlation ID. This hindered forensic auditing of suspicious transaction sequences.
* **Evidence**: Inbound HTTP requests lacked unified correlation headers in server responses.
* **Remediation**:
  Implemented `correlation_id_middleware` in `backend/app/main.py`. It inspects `X-Request-ID` or `X-Correlation-ID` from client headers or generates a cryptographically random UUIDv4, attaching it to request state and echoing it in response headers.
* **Verification**: Verified via `test_phase15_e2e_and_hardening.py::test_02_request_correlation_id_propagated`. Passes 100%.

---

### Finding SEC-05: Missing Component-Level Health Readiness vs Liveness Distinction
* **Severity**: MEDIUM
* **Affected Component**: `backend/app/api/v1/endpoints/health.py`, `backend/app/schemas/health.py`
* **Description**: `/health` returned static status without verifying underlying persistence, storage writability, cryptographic engine status, or ledger connectivity. Orchestrators (Kubernetes / Docker Compose) could route traffic to instances with dead database pools or unmounted storage.
* **Evidence**: Only basic `GET /health` with `status: ok` was present.
* **Remediation**:
  Implemented comprehensive `GET /ready` (and alias `GET /health/ready`):
  - Database: executes `SELECT 1` ping.
  - Storage: performs isolated write/read/delete check in `/storage/encrypted/.probe`.
  - Cryptography: verifies 256-bit Document and Recipient KEK readiness.
  - Ledger: queries active ledger adapter health status.
  Returns HTTP 200 with status `"READY"` or HTTP 503 Service Unavailable with `"DEGRADED"`.
* **Verification**: Verified via `test_phase15_e2e_and_hardening.py::test_01_health_and_readiness_endpoints`. Passes 100%.

---

### Finding SEC-06: Potential Accidental Production Database Reset
* **Severity**: MEDIUM
* **Affected Component**: `backend/app/cli/reset_demo.py`
* **Description**: Automated demo and test reset utilities could inadvertently be executed against production instances if environment guards were not enforced.
* **Evidence**: Risk of automated CLI tools dropping production tables during operations.
* **Remediation**:
  Created `app.cli.reset_demo` with hard assertion:
  ```python
  if settings.ENVIRONMENT == "production":
      logger.critical("ABORT: reset_demo cannot be executed in production environment!")
      sys.exit(1)
  ```
  Requires interactive `CONFIRM` prompt unless `--force` is specified in non-production.
* **Verification**: Verified via `test_phase15_e2e_and_hardening.py::test_04_reset_demo_utility_refuses_production`. System exits with code 1 immediately.

---

### Finding SEC-07: Incomplete Cryptographic Configuration Guidance in Environment Template
* **Severity**: MEDIUM
* **Affected Component**: `.env.example`, `.gitignore`
* **Description**: `backend/.env.example` omitted variable documentation for `PROVENANCE_KEY_KEK_BASE64`, `MFA_ENCRYPTION_KEY_BASE64`, and `LEDGER_STORAGE_PATH`, risking accidental deployment with incomplete keys.
* **Remediation**: Updated `.env.example` with complete explanations, 256-bit CSPRNG key generation commands (`openssl rand -base64 32`), and ensured `.gitignore` explicitly prevents `.env` and `.env.*` commits while preserving `.env.example`.
* **Verification**: Inspected `.gitignore` and `.env.example`. Validated key generation commands.

---

### Finding SEC-08: Architectural Limitation - Signal Domain Forensic Watermark vs Plain Text
* **Severity**: LOW / DOCUMENTED LIMITATION
* **Affected Component**: `backend/app/forensics/`, `backend/app/investigation/`
* **Description**: The 2D-DCT spread-spectrum forensic fingerprinting engine embeds pseudorandom frequency-domain watermarks into visual representations (rasterized PDF pages, PNG, JPEG, WebP). Raw UTF-8 `.txt` or CSV files cannot carry frequency-domain watermarks without conversion/rasterization.
* **Remediation**:
  - The system explicitly detects unsupported formats and returns `415 Unsupported Media Type` or `UNSUPPORTED_EVIDENCE_FORMAT` with clear legal disclaimers rather than simulating a fake match.
  - Secure Viewer automatically renders documents into visual frames for recipient viewing.
* **Verification**: Fully covered in `test_investigations_phase13.py::test_09_unsupported_evidence_format_returns_unsupported` and verified in Phase 15.

---

## 3. Cryptographic Implementation Compliance Matrix

| Primitive | Standard / RFC | Key Size / Parameter | Verification Status | Tamper Resistance |
| :--- | :--- | :--- | :--- | :--- |
| **Document Encryption** | NIST SP 800-38D | AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag) | Validated via `test_05` | Modified ciphertext, nonce, or AAD fails closed |
| **Recipient Key Encapsulation** | FIPS 203 | ML-KEM-768 (Post-Quantum lattice KEM) | Validated via `test_crypto_phase4` | Tampered KEM ciphertext fails decapsulation |
| **Key Derivation** | RFC 5869 | HKDF-SHA-256 with domain-separated info | Validated via `test_crypto_phase4` | Verified recipient key isolation |
| **Provenance Digital Signatures** | FIPS 204 | ML-DSA-65 (Post-Quantum lattice signature) | Validated via `test_06` | Modified payload or signature bit fails verification |
| **Provenance Hash Chain** | SHA-256 | Deterministic canonical JSON + previous chain hash | Validated via `test_06` | Out-of-sequence or broken links detected |
| **Password Hashing** | RFC 9106 | Argon2id (m=65536, t=3, p=4) | Validated via `test_password_security` | Strict salt uniqueness & timing resistance |
| **MFA Secret Protection** | NIST SP 800-38D | AES-256-GCM with PBKDF2/CSPRNG KEK | Validated via `test_hardening_phase14` | Secrets encrypted at rest |
