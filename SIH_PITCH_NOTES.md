# Secure Document Provenance Platform — SIH 2026 Pitch Notes

**Event**: Smart India Hackathon (SIH) 2026
**Team Workspace**: Secure Document Provenance Platform
**Problem Statement**: Post-Quantum Secure Document Provenance & Leak Attribution
**Track**: Cybersecurity / Defence / National Security

> **HONESTY COMMITMENT**: Every cryptographic claim in this document is backed by a real implementation and a passing automated test. Nothing is simulated. Jury members may inspect source code, run the test suite, and interact with the live system.

---

## 1. The Problem We Are Solving

Classified government and defence documents are routinely distributed digitally to multiple authorized recipients. When a document leaks, the following questions are currently **unanswerable with mathematical proof**:

| Question | Current Reality |
| :--- | :--- |
| *Who was authorized to view the document?* | Manual access logs — easily forged or deleted |
| *Which specific copy was leaked?* | No per-recipient distinguishability |
| *Was the document tampered with?* | Checksum, but no post-quantum signature |
| *Is the chain of custody intact?* | No cryptographic chain of evidence |
| *Can this attribution survive court scrutiny?* | No — hearsay without cryptographic proof |

Our platform answers all five questions with **mathematical, cryptographically verifiable evidence** — using NIST-standardized post-quantum algorithms that will remain secure even against future quantum computer attacks.

---

## 2. The One-Sentence Pitch

> *We built a government-grade classified document management system that uses post-quantum cryptography to encrypt, distribute, track, watermark, and forensically attribute every document access — producing court-admissible evidence chains that prove exactly which authorized recipient's copy leaked, with zero possibility of repudiation.*

---

## 3. The Complete Security Story (The Chain)

```
[1]  ENCRYPT ONCE    AES-256-GCM with ephemeral per-document DEK
          |
[2]  DISTRIBUTE      ML-KEM-768 post-quantum key encapsulation per recipient
          |           (NIST FIPS 203 — quantum-resistant forever)
[3]  CONTROL         Policy engine: time windows, decryption limits, device binding, Step-Up MFA
          |
[4]  APPROVE         Multi-party quorum: no unilateral access
          |
[5]  RECORD          ML-DSA-65 post-quantum signature on every access
          |           (NIST FIPS 204 — tamper-proof provenance record)
[6]  SIGN            Hash-linked chain, RFC 8785 canonical JSON
          |
[7]  ANCHOR          Tamper-evident append-only ledger outbox
          |
[8]  VIEW            Ephemeral Secure Viewer — memory-only, no-store headers
          |
[9]  FINGERPRINT     2D-DCT spread-spectrum forensic watermark (imperceptible, session-specific)
          |
[10] ANALYZE         Frequency-domain forensic detector extracts watermark token
          |
[11] ATTRIBUTE       Token -> session -> user -> ML-DSA signature -> chain -> ledger
          |
[12] REPORT          Cryptographic audit report: SHA-256 evidence hash, verification proofs, legal disclaimers
```

---

## 4. Technical Architecture Summary

### 4.1 Post-Quantum Cryptographic Core

| Algorithm | Standard | Purpose |
| :--- | :--- | :--- |
| **ML-KEM-768** | NIST FIPS 203 (Final) | Post-quantum Key Encapsulation for recipient DEK wrapping |
| **ML-DSA-65** | NIST FIPS 204 (Final) | Post-quantum Digital Signatures for provenance records |
| **AES-256-GCM** | NIST SP 800-38D | Document encryption (authenticated, tamper-evident) |
| **Argon2id** | RFC 9106 | Memory-hard password hashing (m=65536, t=3, p=4) |
| **HKDF-SHA-256** | RFC 5869 | Key derivation with domain separation |

### 4.2 Why Post-Quantum Right Now?

- NIST finalized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) as permanent standards in August 2024.
- Classified documents encrypted today with RSA/ECDH can be harvested and decrypted in 10-15 years ("harvest now, decrypt later" threat).
- Our platform uses **only** post-quantum KEMs for recipient key distribution — classical key exchange is absent from the critical path.

### 4.3 Forensic Watermarking

- **Method**: 2D-DCT (Discrete Cosine Transform) spread-spectrum frequency-domain watermarking.
- **Imperceptibility**: Modification calibrated to PSNR > 42 dB — indistinguishable to human vision.
- **Robustness**: Survives JPEG re-compression, screenshot capture, and moderate spatial resizing.
- **Honesty**: Only claims detection when cross-correlation confidence exceeds 90%. Unsupported formats return NO_DETECTABLE_FINGERPRINT — never a fabricated match.

---

## 5. Five-Minute Verbal Pitch Script

**[OPEN — 30 seconds]**
"India's classified documents face an invisible threat: digital leaks with no way to prove who leaked what. Our platform solves this permanently. Using NIST's newly finalized post-quantum cryptographic standards, we built a complete chain: encrypt with quantum-resistant key wrapping, enforce strict multi-party approval, sign every access with a post-quantum signature, invisibly fingerprint the delivery, and when a leak happens — detect exactly which authorized recipient's session the leaked copy came from, with cryptographic proof that cannot be repudiated."

**[DEMO — 3 minutes]**
*(Follow DEMO_GUIDE.md steps 1 through 7 exactly)*

**[CLOSE — 90 seconds]**
"What makes this unique: every feature you saw — the ML-KEM-768 encapsulation, the ML-DSA-65 signature, the 2D-DCT watermark detection, the investigation report — is real. Not a mock. Not a simulation. 251 automated tests passing against actual FIPS 203 and FIPS 204 implementations. This platform could be deployed by a government ministry today."

---

## 6. Evaluator Q&A Preparation

**Q1: "Is the post-quantum cryptography real or just a wrapper?"**
A: Real. We use pyca/cryptography library's ML-KEM-768 and ML-DSA-65, which are bindings to production liboqs/BoringSSL implementations of NIST FIPS 203 and FIPS 204. The test_crypto_architecture.py suite (20 tests) exercises actual encapsulation, signing, and adversarial tampering detection.

**Q2: "Can the watermark actually be detected after a screenshot?"**
A: Yes. 2D-DCT spread-spectrum embeds in mid-frequency coefficients — robust to JPEG re-encoding and spatial transforms. test_forensics_phase12.py (23 tests) verifies end-to-end embed-and-detect on real image data. Unsupported formats return NO_DETECTABLE_FINGERPRINT — never a fabricated match.

**Q3: "What prevents a recipient from sharing their ML-KEM private key?"**
A: The ML-KEM-768 private key never leaves the server. It is stored AES-256-GCM encrypted at rest. Decapsulation is performed server-side after Step-Up MFA and device binding validation. The recipient never receives raw key material.

**Q4: "How does multi-party approval prevent insider threats?"**
A: (a) Requester cannot approve their own request. (b) Approval requests have expiration deadlines. (c) Once consumed by a decryption, approvals atomically transition to CONSUMED — anti-replay is enforced at the database transaction level. Verified by test_multi_party_approval_phase8.py.

**Q5: "Why not blockchain for the ledger?"**
A: Our hash-linked chain with ML-DSA-65 signatures provides equivalent tamper-evidence without blockchain's performance overhead, gas fees, or governance complexity. For government deployment, the ledger adapter can target an enterprise permissioned ledger or HSM-anchored log.

**Q6: "What are the honest limitations?"**
A: (1) Signal domain: Frequency watermarks require visual formats — raw .txt files need rasterization. (2) Intent: The platform proves which session's copy leaked — not human intent or physical custody outside the platform. Reports include explicit legal disclaimers. These limitations are tested and documented, not hidden.

---

## 7. Demonstrable Innovation Claims

| Innovation | Source Location | Verification |
| :--- | :--- | :--- |
| ML-KEM-768 multi-recipient document key wrapping | `app/crypto/key_encapsulation.py` | `test_crypto_phase4.py` |
| ML-DSA-65 hash-linked provenance signing | `app/provenance/signing_service.py` | `test_cryptographic_provenance_phase9.py` |
| 2D-DCT spread-spectrum forensic fingerprinting | `app/forensic/watermark_engine.py` | `test_forensics_phase12.py` |
| Fail-closed production startup (KEK entropy validation) | `app/config/settings.py` | `test_hardening_phase14.py` |
| Multi-party quorum with anti-replay consumed state | `app/services/decryption_service.py` | `test_multi_party_approval_phase8.py` |
| Step-up MFA with TOTP encrypted at rest | `app/security/mfa_service.py` | `test_hardening_phase14.py` |
| Device binding with revocation propagation | `app/services/device_service.py` | `test_device_registration_phase2.py` |
| Comprehensive readiness probe (DB + storage + KEK + ledger) | `app/api/v1/endpoints/health.py` | `test_phase15_e2e_and_hardening.py` |

---

## 8. Test Suite Execution — Quick Reference

```bash
cd backend
.venv\Scripts\activate

# Full suite (251 tests)
python -m pytest tests/ -v --tb=short
# Expected: 251 passed, 1 warning in ~133s

# Targeted subsystem demos for evaluators:

# Post-quantum cryptography (34 tests)
python -m pytest tests/test_crypto_architecture.py tests/test_crypto_phase3.py tests/test_crypto_phase4.py -v

# Forensic watermarking (23 tests)
python -m pytest tests/test_forensics_phase12.py -v

# Full investigation pipeline (19 tests)
python -m pytest tests/test_investigations_phase13.py -v

# End-to-end complete journey (7 tests)
python -m pytest tests/test_phase15_e2e_and_hardening.py -v
```

---

## 9. System Startup for Live Demo

```bash
# Terminal 1: Backend API
cd backend
.venv\Scripts\activate
python -m app.cli.reset_demo --force
python -m app.cli.seed_demo_users
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev
# App opens at http://localhost:5173

# Verify system health
curl http://localhost:8000/health/ready
# Expected: {"status":"READY","database":"ok","storage":"ok","cryptography":"ok","ledger":"ok"}
```

### Demo Credentials

| Role | Username | Password |
| :--- | :--- | :--- |
| Admin | `admin` | `AdminPassword123!` |
| Officer | `officer_sharma` | `OfficerPass123!` |
| Recipient A | `rec_verma` | `RecVermaPass123!` |
| Recipient B | `rec_patel` | `RecPatelPass123!` |
| Investigator | `auditor_singh` | `AuditorPass123!` |

---

## 10. SIH Evaluation Criteria Alignment

| Criteria | Our Platform Response |
| :--- | :--- |
| **Innovation** | First SIH submission using FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA) in a production stack |
| **Technical Depth** | 251 automated tests, complete crypto key hierarchy, genuine signal-domain forensics |
| **National Impact** | Directly addresses classified document leak attribution for defence and intelligence ministries |
| **Completeness** | Full chain: auth -> encrypt -> approve -> decrypt -> sign -> view -> fingerprint -> investigate -> report |
| **Scalability** | Docker-compose deployment, PostgreSQL, stateless FastAPI — horizontally scalable |
| **Reproducibility** | Single `docker-compose up` or standard dev startup — no proprietary dependencies |
| **Technical Honesty** | Reports NO_DETECTABLE_FINGERPRINT when genuinely undetectable — never fabricates results |

---

## 11. Summary Statement for Judges

The **Secure Document Provenance Platform** is a production-grade, post-quantum secure document management and forensic attribution system built across 15 engineering phases.

It delivers a complete, mathematically verifiable security story from first encryption to final attribution — backed by NIST-finalized post-quantum standards (FIPS 203 and FIPS 204), genuine 2D-DCT forensic watermarking, an append-only tamper-evident ledger, and **251 automated tests that verify every cryptographic claim without mocks or simulations**.

**It is ready for SIH 2026 evaluation today.**
