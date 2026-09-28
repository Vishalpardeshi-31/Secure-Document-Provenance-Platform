# Secure Document Provenance Platform - SIH Live Demonstration Guide

**Event**: Smart India Hackathon (SIH) 2026  
**Problem Statement**: Post-Quantum Secure Document Provenance & Leak Attribution Platform  
**Target Roles**: System Administrator, Departmental Officer, Authorized Recipient, Security Auditor / Leak Investigator.

---

## 1. Demonstration Overview & Narrative

This demonstration proves an unbroken, mathematically verified security narrative:

1. **Classified Upload & Post-Quantum Encryption**: An Officer uploads a classified defense brief. The file is encrypted once using AES-256-GCM, and the Document Encryption Key (DEK) is encapsulated independently for authorized recipients using NIST FIPS 203 **ML-KEM-768**.
2. **Strict Multi-Party Access Policy**: The document cannot be decrypted unilaterally. A multi-party approval threshold is required.
3. **Controlled Decryption & FIPS 204 Signing**: Upon approval, Recipient A decrypts the file. The server creates an immutable, post-quantum digital signature using **ML-DSA-65**, extends the hash-linked chain, and queues an append-only ledger anchor.
4. **Forensically Fingerprinted Secure Viewer**: Recipient A views the document inside the ephemeral Secure Viewer. The platform imperceptibly embeds a session-specific 2D-DCT spread-spectrum forensic watermark.
5. **Leak Investigation & Unambiguous Attribution**: A leaked copy is intercepted. An Investigator deposits the evidence artifact into the investigation engine. The 2D-DCT frequency analyzer extracts the embedded watermark, correlates it to Recipient A's viewing session, cryptographically verifies the ML-DSA-65 signature and chain continuity, and exports an audit-grade report.

---

## 2. Pre-Demo Setup & Environment Reset

Ensure backend and frontend are running:

```bash
# 1. Reset database to clean demo state (Runs only in development/demo mode)
cd backend
python -m app.cli.reset_demo --force

# 2. Pre-seed demo users, devices, and ML-KEM keys
python -m app.cli.init_admin
```

### Pre-Configured Demo Credentials:
| Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `AdminPassword123!` | System administrator |
| **Officer** | `officer_sharma` | `OfficerPass123!` | Ministry Defense Officer |
| **Recipient A** | `rec_verma` | `RecVermaPass123!` | Authorized Field Recipient |
| **Recipient B** | `rec_patel` | `RecPatelPass123!` | Alternate Recipient |
| **Investigator** | `auditor_singh` | `AuditorPass123!` | Military Intelligence / CERT-In |

---

## 3. Step-by-Step Live Demonstration Sequence

### Step 1: Officer Authentication & Step-Up MFA
1. Navigate to `http://localhost:5173/login`.
2. Log in as `officer_sharma` / `OfficerPass123!`.
3. Complete Step-Up MFA verification using Google Authenticator / TOTP.
4. Verify the dashboard displays the `OFFICER` command center.

### Step 2: Document Upload & Post-Quantum Encapsulation
1. Go to **Documents** -> **Encrypt & Distribute**.
2. Select a classified briefing image or PDF (e.g., `classified_briefing.png`).
3. Set Title: `Operation Trishul Tactical Overview`.
4. Select Authorized Recipients:
   - `rec_verma` (Recipient A)
   - `rec_patel` (Recipient B)
5. Configure Policy:
   - Check **Require Multi-Party Approval**.
   - Approvals Required: `1`.
   - Eligible Approver Roles: `OFFICER`, `ADMIN`.
6. Click **Encrypt & Distribute Document**:
   - The file is encrypted with a fresh 256-bit AES-GCM DEK.
   - For `rec_verma`, $DEK$ is encapsulated using their ML-KEM-768 public key.
   - For `rec_patel`, $DEK$ is encapsulated with a completely distinct ML-KEM-768 ciphertext.

### Step 3: Recipient Access Request & Officer Multi-Party Approval
1. Log out and log in as `rec_verma` / `RecVermaPass123!`.
2. Navigate to **Documents** -> locate `Operation Trishul Tactical Overview`.
3. Notice that direct viewing/decryption is blocked by policy: `APPROVAL_REQUIRED`.
4. Click **Request Decryption Approval**:
   - Justification: `Briefing operational field team at forward base`.
5. Switch browser window / log in as `officer_sharma`.
6. Open **Approvals** tab -> Review pending request from `rec_verma`.
7. Click **Approve** -> Provide approval note: `Authorized for 15-minute briefing session`.

### Step 4: Authorized Decryption, ML-DSA-65 Signing & Secure Viewer
1. Switch back to `rec_verma`.
2. Click **Open in Secure Viewer**:
   - Platform evaluates device trust, validates non-expired approval, and marks approval `CONSUMED`.
   - Decrypts DEK via ML-KEM-768 decapsulation + AES-GCM.
   - Computes canonical record hash and generates an **ML-DSA-65 post-quantum signature**.
   - Appends to the document's hash chain and emits a ledger anchor outbox event.
   - Starts an ephemeral, 15-minute memory-only `ViewerSession`.
3. The Secure Viewer displays the document.
4. *Under the hood*: The image delivered to `rec_verma` contains an imperceptible, session-specific 2D-DCT spread-spectrum watermark identifying `rec_verma` and session `vs_...`.
5. Save or screenshot a frame from the viewer to simulate an unauthorized leak (`leaked_evidence.png`).

### Step 5: Investigator Evidence Deposit & Analysis
1. Log out and log in as `auditor_singh` / `AuditorPass123!`.
2. Navigate to **Investigations** -> Click **New Investigation Case**.
   - Case Title: `Unauthorized Leak of Operation Trishul Briefing`.
   - Target Document: `Operation Trishul Tactical Overview`.
3. Click **Deposit Leak Evidence**:
   - Upload `leaked_evidence.png`.
   - Observe immediate SHA-256 fingerprinting and immutable chain-of-custody logging (`EVIDENCE_UPLOADED`, `EVIDENCE_HASHED`).
4. Click **Execute Forensic Signal Analysis**:
   - The 2D-DCT spread-spectrum analyzer processes the mid-frequency coefficients.
   - Detection Status: `FINGERPRINT_DETECTED_PROVENANCE_VALID`.
   - Detected Recipient: `rec_verma`.
   - Confidence Score: `> 90%`.

### Step 6: Full-Stack Cryptographic & Chain Verification
In the investigation panel, review the three verification pillars:
1. **Provenance Signature**: FIPS 204 ML-DSA-65 signature verified against the platform public key. Status: `VALID`.
2. **Provenance Chain**: Hash continuity checked from Genesis to Leaf. Status: `CHAIN_VALID`.
3. **Ledger Anchor**: Confirms the event timestamp and hash were committed to the tamper-evident ledger. Status: `ANCHORED`.

### Step 7: Export Formal Investigation Report
1. Click **Generate Formal Investigation Report**.
2. Review the resulting audit-grade report:
   - Cryptographic Case Reference.
   - Exact SHA-256 of deposited evidence.
   - Factual attribution: Leaked from `rec_verma` during session `vs_...`.
   - Cryptographic verification proofs.
   - Legal limitation disclaimers (factual technical finding vs intent).

---

## 4. Demonstrating Tamper Detection & Security Controls

To showcase the platform's defense against manipulation to evaluators:

1. **Anti-Replay**: Attempt to create a second viewer session with the same approval ID. Result: Denied with `403 Forbidden: Approval request has already been consumed`.
2. **Device Revocation**: Revoke `rec_verma`'s workstation from the Admin portal. Attempt to decrypt -> Immediate rejection `403 Forbidden: Device is revoked`.
3. **Ciphertext Tampering**: Modifying even 1 bit in the ciphertext or nonce immediately fails AES-GCM tag verification.
4. **Signature Tampering**: Tampering with the provenance record or ML-DSA signature causes `ProvenanceVerificationService` to flag `INVALID_SIGNATURE`.
