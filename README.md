# Secure Document Provenance Platform

## 1. Project Purpose
The **Secure Document Provenance Platform** is an enterprise-grade document security and provenance platform designed to enforce rigorous authorization boundaries, role-based access control, post-quantum cryptographic key encapsulation, and immutable audit trails across sensitive organizational documentation.

This phase implements the **Production Cryptographic Key Architecture Hardening**:
- **Single DEK Model**: Exactly ONE cryptographically random 256-bit DEK generated via CSPRNG per document; document ciphertext encrypted once via AES-256-GCM.
- **Post-Quantum Recipient Encapsulation**: NIST FIPS 203 standardized **ML-KEM-768** establishes an independent 32-byte shared secret per recipient.
- **Symmetric KEK Derivation**: RFC 5869 **HKDF-SHA-256** derives a distinct 256-bit recipient Key-Encryption Key (KEK) bound to document, version, recipient, and key version context.
- **Per-Recipient DEK Wrapping**: **AES-256-GCM** wraps the single document DEK using the derived recipient KEK and canonical Authenticated Additional Data (AAD).
- **Recipient Private Key Protection at Rest**: Protected using **Argon2id** key derivation from authentication secrets + **AES-256-GCM** authenticated encryption with dedicated random salt and nonce metadata.
- **Cryptographic Versioning**: Version 1 legacy server envelope compatibility preserved for historical Phase 3 documents; Version 2 (`SDP-CRYPTO-V2`) strictly enforced for all new documents (new documents never fall back to legacy server envelopes).
- **Key Lifecycle Management**: Strict key status transitions (`ACTIVE`, `RETIRED`, `REVOKED`) and seamless key rotation where historical documents remain decryptable while new distributions strictly require active key pairs.
- **Deterministic Canonical AAD**: Centralized, tamper-evident AAD builders (`build_document_aad`, `build_dek_wrap_kdf_info`, `build_dek_wrap_aad`).
- **Cryptographic Self-Checks**: Application startup and test-time validation confirming exact standard algorithms (AES-256-GCM, ML-KEM-768, HKDF-SHA-256, Argon2id, SHA-256) with fail-closed behavior.

---

## 2. Cryptographic Architecture & Key Hierarchy

### Key Hierarchy Diagram

```text
Application / KMS Root
        │
        ├── Protects server-side key envelopes & legacy Phase 3 recovery
        │
        └── Does NOT directly encrypt documents

Document
        │
        └── Random 256-bit DEK (CSPRNG generated once)
                │
                ├── AES-256-GCM (12-byte CSPRNG Nonce + Canonical Document AAD)
                │       └── Document Ciphertext (Stored in storage/encrypted/)
                │
                └── Recipient-Specific Wrapping (Per-Recipient Isolation)
                        │
                        ├── Recipient A
                        │     ML-KEM-768 Encapsulation
                        │       ↓
                        │     Shared Secret (32 bytes)
                        │       ↓
                        │     HKDF-SHA-256 (Canonical Context Info)
                        │       ↓
                        │     KEK-A (32 bytes)
                        │       ↓
                        │     AES-256-GCM (Fresh 12-byte Nonce + Canonical Wrap AAD)
                        │       ↓
                        │     Wrapped DEK-A Envelope
                        │
                        ├── Recipient B
                        │     ML-KEM-768 Encapsulation
                        │       ↓
                        │     Shared Secret (32 bytes)
                        │       ↓
                        │     HKDF-SHA-256 (Canonical Context Info)
                        │       ↓
                        │     KEK-B (32 bytes)
                        │       ↓
                        │     AES-256-GCM (Fresh 12-byte Nonce + Canonical Wrap AAD)
                        │       ↓
                        │     Wrapped DEK-B Envelope
                        │
                        └── Recipient N
```

> **CRITICAL ARCHITECTURAL DISTINCTION:**  
> **ML-KEM does not directly encrypt the document DEK.** It establishes a recipient-specific shared secret, which is converted through HKDF-SHA-256 into a symmetric key (KEK) used to wrap the document DEK with AES-256-GCM.

---

## 3. Cryptographic Primitives & Roles

| Primitive | Standard / RFC | Key / Output Size | Operational Role |
| :--- | :--- | :--- | :--- |
| **AES-256-GCM** | NIST SP 800-38D | 256-bit Key, 96-bit Nonce, 128-bit Tag | Authenticated document encryption and per-recipient DEK wrapping. |
| **ML-KEM-768** | NIST FIPS 203 | 1184B Public Key, 1088B Ciphertext, 32B Shared Secret | Post-quantum recipient asymmetric key encapsulation mechanism. |
| **HKDF-SHA-256** | RFC 5869 / NIST SP 800-56C | 256-bit Derived KEK | Derives symmetric recipient wrapping keys bound to canonical context. |
| **Argon2id** | RFC 9106 | 256-bit Protection Key | Derives private key protection key at rest from authentication secret. |
| **SHA-256** | FIPS 180-4 | 256-bit Digest | Document plaintext & ciphertext integrity hashing and audit event chaining. |

---

## 4. Document Encryption & Multi-Recipient Distribution Flow

For every document encrypted in Version 2 (`SDP-CRYPTO-V2`):

1. **Validation & Atomicity**:
   - All assigned recipients are verified to exist, be active, and possess an `ACTIVE` ML-KEM-768 key pair.
   - If any recipient is invalid, missing a key, or inactive, the entire distribution rolls back atomically.
2. **Document DEK Generation**:
   - `DEK = CSPRNG(32 bytes)`.
   - Never derived from passwords, timestamps, user IDs, or predictable counters.
   - Never logged, never stored in PostgreSQL, never returned in API responses.
3. **Document Encryption**:
   - `Nonce = CSPRNG(12 bytes)`.
   - `Canonical Document AAD = "SDP-CRYPTO-V2|DOC|{document_id}|{version_id}".encode("utf-8")`.
   - `Ciphertext = AES-256-GCM.Encrypt(key=DEK, nonce=Nonce, plaintext=Content, AAD=Canonical Document AAD)`.
   - Stored in isolated disk storage (`storage/encrypted/`).
4. **Per-Recipient DEK Wrapping**:
   - For each recipient:
     - `(shared_secret, kem_ciphertext) = ML-KEM-768.Encapsulate(recipient_public_key)`.
     - `KDF_Info = "SDP-DEK-WRAP-v1|SDP-CRYPTO-V2|{document_id}|{version_id}|{user_id}|{key_id}|v{key_version}".encode("utf-8")`.
     - `KEK = HKDF-SHA-256(IKM=shared_secret, info=KDF_Info, length=32)`.
     - `Wrap_Nonce = CSPRNG(12 bytes)`.
     - `Wrap_AAD = "SDP-CRYPTO-V2|WRAP|{document_id}|{version_id}|{user_id}|{key_id}|v{key_version}".encode("utf-8")`.
     - `Wrapped_DEK = AES-256-GCM.Encrypt(key=KEK, nonce=Wrap_Nonce, plaintext=DEK, AAD=Wrap_AAD)`.
     - Recorded in `document_recipients` table.

---

## 5. Recipient Private Key Protection Model

Recipient ML-KEM private keys are **never stored in plaintext**:

1. A fresh 16-byte random salt is generated via CSPRNG.
2. A 256-bit symmetric protection key is derived using **Argon2id** (`time_cost=2`, `memory_cost=65536` [64 MiB], `parallelism=1`).
3. A fresh 12-byte random nonce is generated via CSPRNG.
4. Deterministic AAD binds recipient identity and key version: `SDP-PRIVKEY-PROTECT-V1|{user_id}|v{key_version}`.
5. The raw FIPS 203 private key seed (64 bytes) is encrypted using **AES-256-GCM**.
6. Stored in `recipient_keys` with encrypted ciphertext, salt, nonce, and KDF metadata.

> **HONEST IMPLEMENTATION DISCLOSURE:**  
> The current SIH implementation protects recipient private keys encrypted at rest using recipient authentication-derived key material. A production deployment should preferably use client-side or hardware-backed private-key custody where the private key never leaves the trusted device.

---

## 6. Key Lifecycle & Rotation

- **Key Statuses**:
  - `ACTIVE`: Key is active and authorized for receiving new document distributions.
  - `RETIRED`: Key has been superseded by a newer version. It cannot be used for new distributions, but remains available to decrypt historical documents.
  - `REVOKED`: Key is explicitly compromised or revoked. Cannot be used for new distributions; private key unwrap is refused.
- **Key Rotation**:
  - Calling `rotate_key` generates a new versioned ML-KEM-768 key pair.
  - The previous key version transitions to `RETIRED`.
  - The new key version transitions to `ACTIVE`.
  - Historical distributions retain their original key version metadata.

---

## 7. Decryption Workflow & Phase 3 Compatibility

When an authorized user requests decryption (`POST /api/v1/documents/{id}/decrypt`):

```text
Authenticated Recipient
        ↓
Policy Evaluation Engine (Identity, Role, Device, Time Window, Max Count)
        ↓
Check Document key_management_version:
        ├─ Version 1 (Legacy Phase 3):
        │    Unwrap DEK using server KEK from doc.encrypted_dek
        │    Decrypt ciphertext using legacy AAD: "SDPP-DOC:{id}"
        │
        └─ Version 2 (SDP-CRYPTO-V2):
             Load active distribution from document_recipients
             Load protected ML-KEM private key matching recipient_key_version
             Recover private key seed using Argon2id + AES-256-GCM
             ML-KEM-768.Decapsulate(kem_ciphertext) → shared_secret
             HKDF-SHA-256(shared_secret, build_dek_wrap_kdf_info(...)) → recipient KEK
             AES-256-GCM.Decrypt(wrapped_dek, build_dek_wrap_aad(...)) → document DEK
             AES-256-GCM.Decrypt(document_ciphertext, build_document_aad(...)) → plaintext
        ↓
Verify Plaintext SHA-256 Hash
        ↓
Return Ephemeral Decrypted Stream to Viewer
```

- **Fail-Closed Security**: At any tag mismatch, tampered nonce, corrupted AAD, or invalid key, decryption aborts immediately with a generic failure to prevent oracle attacks.

---

## 8. Security Assumptions & Production Roadmap

### Assumptions:
1. The host operating system provides a cryptographically secure random number generator (`/dev/urandom` / `CryptGenRandom`).
2. Server configuration secrets (`SECRET_KEY`, `DOCUMENT_KEK_BASE64`) are injected via secure environment variables.
3. Transport layer security (TLS 1.3) protects in-flight client/server traffic.

### Production Hardening Roadmap:
1. **Hardware Security Modules (HSM) / Cloud KMS**:
   - Migrate server-side envelope protection keys to AWS KMS / GCP Cloud KMS / PKCS#11 HSM.
2. **Client-Side Key Custody**:
   - Provision ML-KEM key pairs directly on user devices (WebCrypto / Native PKCS#11 tokens).
   - Encapsulation shared secret decapsulated strictly inside client device enclave.
3. **Hardware-Backed Device Attestation**:
   - Enforce WebAuthn / FIDO2 device attestation alongside registered device IDs.
4. **Phase 6+ Features**:
   - ML-DSA post-quantum digital signatures for document provenance.
   - Immutable provenance ledger and forensic watermarking.

---

## 9. Phase 7: Policy-Controlled Decryption Engine

Phase 7 upgrades the decryption authorization pipeline into a **backend-authoritative, multi-condition policy engine**:

### Policy Architecture
```text
Authenticated Identity
        +
Recipient Authorization (Explicit assignment + Active ML-KEM Key)
        +
Role Authorization (RBAC: Officer, Recipient, Admin, Auditor restriction)
        +
Registered Hardware Device (Active, owned by user, not revoked)
        +
Server-Side Time Window (UTC not_before & expires_at)
        +
Maximum Decryption Allowance (Concurrency-safe atomic consumption)
        +
Document Lifecycle State (ACTIVE / ENCRYPTED vs. REVOKED / ARCHIVED)
        +
Policy State (ACTIVE vs. EXPIRED / REVOKED)
        ↓
PolicyEvaluator (ALL conditions must pass)
        ↓
ALLOW / DENY
        ↓
Only if ALLOW:
Cryptographic Key Recovery (ML-KEM-768 decapsulation + HKDF + AES-GCM DEK unwrap)
        ↓
Document Decryption (AES-256-GCM + SHA-256 integrity verification)
```

### Key Guarantees
1. **Authoritative Backend Decision Point**: The frontend never decides whether a user is permitted to decrypt. Possessing valid cryptographic keys is never sufficient to bypass policy.
2. **Explicit Recipient Assignment**: Admins cannot decrypt documents unless explicitly assigned as recipients.
3. **Atomic Decryption Allowance**: `PolicyService.reserve_and_consume_decryption` uses database row-level locking (`with_for_update`) to prevent race conditions during concurrent decryption requests.
4. **Immutable Policy Versioning**: Editing a policy archives the prior version (`status="EXPIRED", enabled=False`) and increments the `policy_version`. Historical policy records are never overwritten.
5. **Real Access Verification UI**: The recipient decryption screen queries `GET /api/v1/documents/{document_id}/access-check` to display actual backend condition results. Zero fake or simulated checkmarks.

---

## 10. Phase 8 — Multi-Party Approval & Emergency Break-Glass Access

### Multi-Party Approval Architecture

The platform supports threshold-based multi-party authorization for high-sensitivity documents:

```text
Normal policy evaluation passes
         ↓
Does policy require multiple approvals? (require_multi_party_approval == true)
    ├── NO  → Proceed directly to decryption
    └── YES →
          1. Requester creates ApprovalRequest (document, user, policy version, device)
          2. Request enters PENDING state with short-lived UTC expiration (default 30 min)
          3. Independent authorized approvers review request via contextual UI
          4. Approver independence strictly enforced: approver_user_id != requesting_user_id
          5. Approver role must match eligible_approver_roles (e.g. OFFICER, ADMIN)
          6. Each approver records unique ApprovalRecord (UniqueConstraint prevents duplicate voting)
          7. If any approver rejects → Request status becomes REJECTED
          8. Threshold reached (current_approvals >= required_approvals) → APPROVED
          9. Requester triggers decryption → Engine re-evaluates all policy conditions immediately
          10. Concurrency-safe limit checked and cryptographic envelope decrypted
```

### Approval Independence Rules
- **Requester Exclusion**: The backend strictly validates `approver.id != request.requesting_user_id`. A user cannot approve their own decryption request under any circumstance.
- **Role Qualification**: Approvers must be active, unrevoked accounts possessing an authorized role defined in `policy.eligible_approver_roles`.
- **Anti-Duplication**: A database `UniqueConstraint('approval_request_id', 'approver_user_id')` ensures a user cannot approve the same request multiple times to artificially meet the threshold.
- **Short-Lived Expiration**: Approval requests expire after a server-side configured UTC duration. Expired requests immediately reject further approval attempts or decryption execution.

### Approval Lifecycle
```
[PENDING] ──(Approver votes, count < threshold)──→ [PENDING]
    │
    ├──(Threshold reached: N/N)──────────────────→ [APPROVED] ──(Re-evaluate & Decrypt)──→ [COMPLETED]
    ├──(Any eligible approver rejects)────────────→ [REJECTED]
    ├──(Server UTC time > expires_at)─────────────→ [EXPIRED]
    └──(Requester voluntarily cancels)────────────→ [CANCELLED]
```

### Emergency Break-Glass Architecture

> **Critical Security Principle:**
> **Emergency access is an authorization mechanism, not a cryptographic bypass.**

Emergency access provides a separate, strictly controlled operational path when normal recipient access is denied, revoked, or unavailable during an active security incident:

```text
Normal access denied / incident declared
        ↓
Authenticated actor with explicit EMERGENCY_DECRYPT permission
        ↓
Submit Emergency Break-Glass Request
  - Mandatory justification reason (minimum 15 characters)
  - Time-limited duration request (clamped to policy maximum_emergency_duration)
        ↓
Status: REQUESTED
        ↓
Independent Emergency Approver (OFFICER or ADMIN, approver != requester)
        ↓
Status: AUTHORIZED (time-limited window established: approved_at + duration)
        ↓
Execute Emergency Decryption (within time window)
        ↓
Re-evaluate document status + verify emergency authorization validity
        ↓
Normal Cryptographic Envelope Key Recovery (recipient ML-KEM or secure server KEK)
        ↓
Controlled In-Memory Decryption Viewer with Emergency Banner
        ↓
Mandatory Audit / Provenance Logging (EMERGENCY_ACCESS_USED)
        ↓
Status: USED (Single-use or session expiration)
```

### Why Emergency Access Does Not Use a Master Decrypt Key
1. **No Backdoors**: Backdoors and universal master keys destroy the confidentiality guarantees of post-quantum envelope cryptography. If an attacker extracts a master key, all past and future encrypted documents across the agency are compromised.
2. **Key Isolation**: The platform preserves the rule that no unauthorized user receives another user's private key. If the emergency actor is an assigned recipient, their own ML-KEM recipient wrapped key is decapsulated. If the emergency actor is an unassigned incident responder, the server KEK envelope is securely decapsulated by the backend key manager under strict authorization checks.
3. **No ADMIN Privileges by Default**: Ordinary `ADMIN` role membership does not grant emergency privileges. The explicit `EMERGENCY_DECRYPT` permission (`can_emergency_decrypt = True`) must be assigned to the identity.

### Audit Requirements
Every approval and emergency lifecycle event produces an immutable cryptographic audit record in the blockchain-style chained audit log:
- `DECRYPTION_APPROVAL_REQUESTED`
- `DECRYPTION_APPROVED`
- `DECRYPTION_REJECTED`
- `DECRYPTION_APPROVAL_EXPIRED`
- `DECRYPTION_APPROVAL_CANCELLED`
- `EMERGENCY_ACCESS_REQUESTED`
- `EMERGENCY_ACCESS_APPROVED`
- `EMERGENCY_ACCESS_REJECTED`
- `EMERGENCY_ACCESS_USED`
- `EMERGENCY_ACCESS_EXPIRED`

Audit events record document ID, requester ID, approver ID, policy version, request ID, session ID, timestamp, and safe reason code. **Under no circumstances are DEKs, private keys, plaintext, or ML-KEM shared secrets logged.**

### Current SIH Implementation Limitations
1. **SQLite Concurrency Model**: While SQLite handles concurrent transactions with database-level locks, production deployments require PostgreSQL row-level locks (`SELECT ... FOR UPDATE`) for high-throughput multi-party approval queues.
2. **Device Hardware Binding**: The current device fingerprinting uses browser-reported device identity and hardware characteristics; production should integrate TPM 2.0 or WebAuthn/FIDO2 hardware attestations.
3. **Email / Push Notifications**: Approver notifications currently rely on UI polling and dashboard queries rather than asynchronous webhook/email dispatch.

### Production Hardening Recommendations
1. Deploy PostgreSQL with read replicas and row-level locking for the approval state machine.
2. Implement mutual TLS (mTLS) for all client-to-backend and backend-to-storage communications.
3. Integrate HSM (Hardware Security Module) via PKCS#11 for the root server Key Encryption Key (KEK).
4. Require WebAuthn hardware tokens for multi-party approvers and emergency break-glass actors.

---

## 11. Verification & Testing

The platform maintains **151 passing automated tests** verifying all cryptographic and policy boundaries:

```bash
# Run full backend test suite:
& "c:\Users\Vishal\OneDrive\Desktop\Secure Document Provenance Platform\backend\.venv\Scripts\python.exe" -m pytest -v

# Run dedicated Phase 9 Cryptographic Provenance tests:
& "c:\Users\Vishal\OneDrive\Desktop\Secure Document Provenance Platform\backend\.venv\Scripts\python.exe" -m pytest -v tests/test_cryptographic_provenance_phase9.py
```

### Coverage Breakdown (151 Tests):
- `tests/test_cryptographic_provenance_phase9.py` (8 tests): Complete lifecycle signing and verification with ML-DSA-65, comprehensive field-by-field tampering resistance (every signed field tested), signature corruption rejection, wrong public key mismatch rejection, signing key rotation with permanent historical verification, failed decryptions producing zero successful provenance, access type binding (`NORMAL`, `MULTI_PARTY_APPROVED`, `EMERGENCY`), and role-based access control with auditor verification.
- `tests/test_multi_party_approval_phase8.py` (11 tests): Multi-party approval threshold enforcement (1 of 2 denied, 2 of 2 authorized), requester self-approval rejection, duplicate approver deduplication, unauthorized role rejection, inactive user rejection, expired request rejection, cancelled request rejection, rejected request denial, policy change after approval re-evaluation denial, and request tamper resistance.
- `tests/test_emergency_access_phase8.py` (9 tests): Explicit `EMERGENCY_DECRYPT` permission enforcement, reason validation (minimum 15 characters), requester self-authorization rejection, unauthorized emergency approver rejection, time-limited expiration enforcement, rejected emergency access denial, emergency decryption envelope recovery, and complete audit trail verification.
- `tests/test_policy_phase7.py` (13 tests): Recipient authorization enforcement, admin non-bypass, auditor rejection, role restrictions, time window (before/inside/after), registered device enforcement, revoked device rejection, concurrency-safe atomic limit tests (multithreaded race testing), document lifecycle administrative revocation & reactivation, policy versioning & historical persistence, parameter tampering resistance, and real backend access check endpoint.
- `tests/test_crypto_architecture.py` (20 tests): Document encryption roundtrip, tampering resistance (ciphertext, nonce, tag, AAD), ML-KEM wrapping/unwrapping, multi-recipient single DEK isolation, Argon2id private key protection, key rotation, key revocation, version enforcement, and startup self-checks.
- `tests/test_decryption_phase5.py` (8 tests): Policy-controlled decryption, session states, audit logging, device enforcement.
- `tests/test_policy_phase5.py` (6 tests): Time windows, max decryptions, concurrent race conditions.
- `tests/test_recipients_phase4.py` (5 tests): Recipient key provisioning, atomic multi-recipient distribution.
- `tests/test_crypto_phase4.py` (7 tests): Post-quantum ML-KEM-768 primitives, KEK derivation.
- `tests/test_crypto_phase3.py` (7 tests): AES-256-GCM primitives, legacy server envelope.
- `tests/test_documents_phase3.py` (8 tests): Document upload, file validation, storage isolation.
- Phases 1–2 tests (49 tests): Authentication, RBAC, users, departments, devices, audit chaining, Argon2id passwords.

### Frontend Production Build:
```bash
cd frontend
cmd /c npm run build
# Verified: 1595 modules transformed, built in 3.30s, 0 errors.
```

---

## 12. Phase 9: Real Cryptographic Provenance Architecture (ML-DSA-65)

### A. Provenance Flow

```text
Authorized Identity + Policy + Device + Decryption Session
                         ↓
Successful AES-256-GCM Decryption (Verified Plaintext & Tag)
                         ↓
Construct Deterministic Canonical Record (PROVENANCE-V1 format)
                         ↓
SHA-256 Digest (64-character lowercase hexadecimal)
                         ↓
Post-Quantum Digital Signature: ML-DSA-65.Sign(priv_key, digest)
                         ↓
Store Immutable Provenance Record + Public-Key Identity
                         ↓
Commit Transaction & Audit Event (PROVENANCE_CREATED)
```

### B. Cryptographic Key Separation

The platform enforces strict key separation across distinct mathematical roles:

```text
ML-KEM-768    → Recipient Key Encapsulation Mechanism (Confidentiality / Key Agreement)
ML-DSA-65     → Platform Provenance Digital Signatures (Integrity / Authenticity / Non-Repudiation)
AES-256-GCM   → Authenticated Document Encryption & DEK Envelope Wrapping
HKDF-SHA-256  → Recipient KEK Derivation from KEM Shared Secret
Argon2id      → Password Hashing & Private Key Protection at Rest
SHA-256       → Document Integrity & Canonical Provenance Hashing
```

**Why ML-KEM and ML-DSA are strictly separated:**
- **Mathematical Incompatibility**: ML-KEM (Kyber, FIPS 203) operates on the Module Learning with Errors (M-LWE) problem designed specifically for asymmetric key agreement. ML-DSA (Dilithium, FIPS 204) operates on the Module Short Integer Solution (M-SIS) problem designed specifically for digital signatures.
- **Security Principle**: Reusing the same key material across different cryptographic primitives (e.g., encryption vs. signing) violates cryptographic key separation, enables cross-protocol attacks, and creates key management vulnerabilities.
- **Dedicated Provenance Signing Identity**: Provenance signing keys (`provenance_signing_keys`) are managed in a dedicated hierarchy independent of user KEM keys and document DEKs. Private keys are encrypted at rest using AES-256-GCM via a dedicated server KEK (`PROVENANCE_KEY_KEK_BASE64`).

### C. Deterministic Canonicalization & Independent Verification

An authorized investigator or auditor independently verifies provenance without access to plaintext:

1. **Reconstruct Canonical Format**: The provenance payload is formatted using the strict, deterministic `PROVENANCE-V1` length-delimited encoding:
   ```text
   PROVENANCE-V1
   event_id:36:9f62...
   document_id:36:b41e...
   document_version_id:1:1
   user_id:36:8a12...
   ...
   document_plaintext_sha256:64:a1b2...
   document_ciphertext_sha256:64:c3d4...
   event_timestamp:27:2026-09-28T03:15:00.000000Z
   ```
2. **Compute SHA-256**: Recalculate `SHA-256(canonical_bytes)` and verify byte-for-byte identity with `canonical_record_hash`.
3. **Load Public Signing Key**: Retrieve the public key associated with `signature_key_id` and `signature_key_version`. Old public keys remain preserved permanently even after key rotation (`RETIRED`).
4. **Verify ML-DSA-65 Signature**: Call `public_key.verify(signature, canonical_record_hash)` using the standard cryptographic primitive.

### D. Scope & Limitations

> **CRITICAL FORENSIC LIMITATION:**  
> A valid cryptographic provenance record establishes that the recorded decryption event was authorized, conformed to active access policy, successfully authenticated against the stored ciphertext, and was cryptographically signed by the platform's provenance signing identity. **It does not by itself prove that the recipient intentionally leaked the document or establish physical possession of an out-of-band leaked copy.** Forensic attribution of leaked files requires additional watermarking, device attestation, and forensic leak-analysis capabilities (scheduled for future phases).


#   S e c u r e - D o c u m e n t - P r o v e n a n c e - P l a t f o r m  
 