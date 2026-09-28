# Secure Document Provenance Platform - Architecture Specification

**Version**: 1.0 (Phase 15 Final Release)  
**Classification**: Unclassified Technical Reference  
**Core Technologies**: Python 3.14 (FastAPI, SQLAlchemy, PyCA Cryptography FIPS 203/204), React / Vite, PostgreSQL, Append-Only Tamper-Evident Ledger.

---

## 1. System Overview

The **Secure Document Provenance Platform (SDPP)** provides end-to-end mathematical assurance for classified and high-sensitivity electronic records across their entire lifecycle:

```
[Document Upload] ──> [AES-256-GCM Encrypt] ──> [ML-KEM-768 Multi-Recipient Wrap]
        │
[Access Request] ──> [MFA + Device Binding + Policy Engine] ──> [Multi-Party Approval]
        │
[Controlled Decrypt] ──> [ML-DSA-65 Signed Provenance] ──> [Hash-Linked Chain & Ledger Anchor]
        │
[Secure Viewer] ──> [Dynamic 2D-DCT Spread-Spectrum Forensic Watermarking]
        │
[Suspected Leak Evidence] ──> [Forensic Detection & Attribution] ──> [Cryptographic Verification]
```

---

## 2. Authentication & Authorization Architecture

### 2.1 Identity & Credential Protection
* **Password Hashing**: RFC 9106 Argon2id (`m=65536` KiB, `t=3` iterations, `p=4` parallelism).
* **Multi-Factor Authentication (MFA)**:
  - RFC 6238 TOTP (Time-based One-Time Password) with 30-second time steps and SHA-1 HMAC.
  - TOTP shared secrets encrypted at rest using AES-256-GCM via `MFA_ENCRYPTION_KEY_BASE64`.
  - Step-up authentication assurance level (`auth_assurance_level="MFA_VERIFIED"`) enforced with configurable expiration (default: 15 minutes) for all sensitive operations (key generation, document decryption, approvals, investigations).

### 2.2 Device Binding
* Every sensitive request requires client device registration (`Device` entity).
* Device hardware fingerprinting and binding verified against server records. Revocation of any device immediately invalidates sessions and rejects decryption requests.

### 2.3 Role-Based Access Control (RBAC)
* **ADMIN**: System administration, user/device management, security policy configuration, ledger maintenance.
* **OFFICER**: Document upload, policy specification, recipient assignment, approval decisions.
* **RECIPIENT**: Document access requests, authorized policy-controlled decryption, secure viewing.
* **AUDITOR / INVESTIGATOR**: Evidence deposit, forensic signal detection, provenance chain audits, formal report generation.

---

## 3. Cryptographic Key Hierarchy

```
Master Environment Secrets (Hardware / Orchestrator Supplied):
├── DOCUMENT_KEK_BASE64 (256-bit AES-256 Master Key Encryption Key)
├── RECIPIENT_KEY_KEK_BASE64 (256-bit AES-256 Master KEK for Recipient Private Keys)
├── PROVENANCE_KEY_KEK_BASE64 (256-bit AES-256 Master KEK for ML-DSA Private Keys)
├── MFA_ENCRYPTION_KEY_BASE64 (256-bit AES-256 Master KEK for TOTP Secrets)
└── FORENSIC_MASTER_KEY_BASE64 (256-bit CSPRNG Master Key for Forensic Watermarking)

Per-Document Cryptography:
└── DEK (Document Encryption Key, 256-bit CSPRNG, ephemeral)
    ├── Encrypted via AES-256-GCM using DOCUMENT_KEK (Server envelope backup)
    └── Encapsulated for each Recipient via ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM

Post-Quantum Identity & Signing Keys:
├── Recipient Keys: ML-KEM-768 Public / Private Key Pairs (FIPS 203)
└── Provenance Keys: ML-DSA-65 Public / Private Key Pairs (FIPS 204)
```

---

## 4. Document Encryption & Multi-Recipient Key Wrapping

### 4.1 Encryption Flow
1. **DEK Generation**: An ephemeral 256-bit symmetric key ($DEK$) is sampled using the operating system CSPRNG (`os.urandom(32)`).
2. **AES-256-GCM Encryption**: The document plaintext is encrypted under $DEK$ using a unique 96-bit nonce and Additional Authenticated Data (AAD):
   $$AAD = \text{"SDPP-DOC:"} \mathbin{\Vert} \text{document\_id} \mathbin{\Vert} \text{"-v1"}$$
3. **Ciphertext Storage**: The ciphertext + 16-byte authentication tag is written to isolated encrypted storage.

### 4.2 Multi-Recipient ML-KEM-768 Wrapping
For each recipient $R_i \in \{R_1, \dots, R_n\}$:
1. Retrieve recipient's active ML-KEM-768 public key $PK_{R_i}$.
2. Encapsulate a shared secret:
   $$(SS_i, CT_{KEM_i}) \leftarrow \text{ML-KEM-768.Encaps}(PK_{R_i})$$
3. Derive a wrapping key using HKDF-SHA-256:
   $$K_{wrap_i} = \text{HKDF-Expand}(\text{HKDF-Extract}(salt, SS_i), \text{info}_i, 32)$$
   where $\text{info}_i = \text{"SDPP-DEK-WRAP-v1:"} \mathbin{\Vert} \text{doc\_id} \mathbin{\Vert} \text{recipient\_id}$.
4. Wrap $DEK$ with AES-256-GCM:
   $$WrappedDEK_i \leftarrow \text{AES-GCM-Encrypt}(K_{wrap_i}, nonce_i, DEK, AAD_{wrap_i})$$
5. Store $CT_{KEM_i}$, $nonce_i$, and $WrappedDEK_i$ in the `DocumentRecipient` record.

---

## 5. Controlled Decryption & Policy Engine

Before any decryption request is processed, the platform enforces atomic server-side evaluation:
1. **User Identity & Step-up MFA**: Validates active session and step-up MFA assurance.
2. **Device Registration**: Verifies that the client device is registered to the user and not marked `REVOKED`.
3. **Recipient Relationship**: Verifies the user is an authorized recipient with a corresponding `DocumentRecipient` record.
4. **Access Policy Evaluation**:
   - **Time Window**: Current UTC time must be between `valid_from` and `valid_until`.
   - **Maximum Decryptions**: Verifies `current_decryptions < max_decryptions` using row-level locking (`SELECT ... FOR UPDATE`).
   - **Multi-Party Approval**: If `policy_require_multi_party_approval` is enabled, verifies that an approved, non-expired `ApprovalRequest` exists with $\ge N$ independent approvals.
   - **Anti-Replay**: The approval request is atomically marked `CONSUMED` upon decryption.
5. **Decapsulation & Decryption**:
   - Decapsulate $SS_i$ using the recipient's protected ML-KEM private key.
   - Derive $K_{wrap_i}$ and unwrap $DEK$.
   - Authenticate and decrypt document ciphertext using AES-256-GCM.
   - Verify SHA-256 hash of decrypted bytes against `Document.plaintext_sha256`.

---

## 6. Provenance Architecture: ML-DSA-65 & Tamper-Evident Hash Chain

### 6.1 Canonicalization & ML-DSA-65 Signing
1. For every successful decryption, a canonical JSON structure is constructed adhering to deterministic sorting (RFC 8785 principles).
2. The SHA-256 hash of the canonical bytes is computed ($H_{rec}$).
3. An authoritative platform post-quantum signature is generated:
   $$\sigma \leftarrow \text{ML-DSA-65.Sign}(SK_{platform}, \text{canonical\_bytes})$$
4. The record stores $H_{rec}$, $\sigma$, signing key version, and full audit metadata.

### 6.2 Hash-Linked Provenance Chain
Each document maintains an append-only hash chain:
$$ChainHash_n = \text{SHA-256}(ChainHash_{n-1} \mathbin{\Vert} H_{rec_n} \mathbin{\Vert} Sequence_n \mathbin{\Vert} Timestamp_n)$$
Constraint: `UNIQUE(document_id, chain_sequence)` guarantees sequence continuity and prevents race-condition forks.

### 6.3 Tamper-Evident Ledger Anchoring
* Completed provenance events are placed into a database outbox table.
* The ledger worker aggregates batch hashes and anchors them to the configured tamper-evident ledger (local cryptographic append-only log or permissioned enterprise ledger).

---

## 7. Secure Viewer & Forensic Fingerprinting

### 7.1 Ephemeral Memory-Only Delivery
* The Secure Viewer provides short-lived sessions (`ViewerSession`) bounded by strict server-side deadlines (default: 15 minutes).
* Content is delivered directly to memory with `Cache-Control: no-store, no-cache, must-revalidate` and `X-Content-Type-Options: nosniff`.
* Filesystem persistence on the client is minimized.

### 7.2 Dynamic 2D-DCT Spread-Spectrum Forensic Watermarking
* When rendering a document, the platform embeds a pseudorandom, imperceptible watermark in the mid-frequency 2D-DCT (Discrete Cosine Transform) coefficients:
  $$C'(u, v) = C(u, v) + \alpha \cdot W(u, v)$$
* The watermark sequence $W$ is derived deterministically from `FORENSIC_MASTER_KEY` combined with session tokens, user IDs, and document IDs.
* **Factual Verification**: The embedded watermark survives visual rendering, compression, and screen-capture.

---

## 8. Forensic Investigation & Evidence Workflow

1. **Case Creation**: Authorized investigators (ADMIN or AUDITOR) create formal case containers (`InvestigationCase`).
2. **Evidence Deposit**: Suspected leaked documents or photographs are uploaded. Cryptographic SHA-256 hashes are recorded upon deposit.
3. **Signal Detection**: The 2D-DCT detector analyzes the evidence in the frequency domain, extracting the candidate token and calculating cross-correlation confidence.
4. **Cryptographic Provenance Verification**: The detected session is traced to the original `ProvenanceRecord`. The platform re-verifies:
   - SHA-256 canonical record hash.
   - ML-DSA-65 digital signature against historical public key.
   - Hash-linked chain continuity from genesis to leaf.
   - Tamper-evident ledger anchor confirmation.
5. **Formal Investigation Report**: Generates an immutable, cryptographically hashed PDF/JSON report containing factual findings, timeline events, and legal limitations disclaimers.

---

## 9. Security Limitations & Operational Boundaries

1. **Signal-Domain Constraints**: Frequency-domain watermarking applies to visual formats (rasterized PDF, PNG, JPEG, WebP). Raw UTF-8 text files cannot carry frequency-domain watermarks without rasterization.
2. **Human Intent Disclaimer**: While cryptographic provenance proves platform authorization and forensic detection identifies the viewing session, the system explicitly disclaims proving user intent or physical custody outside the platform.
