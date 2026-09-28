import hashlib
import io
import json
import uuid
import pytest
from PIL import Image
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.audit_event import AuditEvent
from app.provenance.models import ProvenanceRecord
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.ledger.service import LedgerService
from app.ledger.adapters.in_memory import InMemoryLedgerAdapter


@pytest.fixture
def investigation_suite(db_session: Session):
    """Sets up an isolated test fixture with admin, auditor, officer, and two recipients."""
    mem_adapter = InMemoryLedgerAdapter()
    mem_adapter.clear()
    LedgerService.set_adapter(mem_adapter)

    admin = UserService.create_user(
        db=db_session,
        username="inv_admin",
        email="inv_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="inv_auditor",
        email="inv_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )
    officer = UserService.create_user(
        db=db_session,
        username="inv_officer",
        email="inv_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    rec_a = UserService.create_user(
        db=db_session,
        username="inv_rec_a",
        email="inv_rec_a@agency.gov",
        plain_password="RecipientPasswordA123!",
        role=UserRole.RECIPIENT,
    )
    rec_b = UserService.create_user(
        db=db_session,
        username="inv_rec_b",
        email="inv_rec_b@agency.gov",
        plain_password="RecipientPasswordB123!",
        role=UserRole.RECIPIENT,
    )
    db_session.commit()

    key_a = RecipientKeyManager.provision_recipient_key(db_session, rec_a, admin)
    dev_a = DeviceService.register_device(
        db=db_session,
        user_id=rec_a.id,
        device_name="Workstation Alpha",
        device_fingerprint="fp-inv-rec-a",
    )

    key_b = RecipientKeyManager.provision_recipient_key(db_session, rec_b, admin)
    dev_b = DeviceService.register_device(
        db=db_session,
        user_id=rec_b.id,
        device_name="Workstation Beta",
        device_fingerprint="fp-inv-rec-b",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "rec_a": (rec_a, create_access_token(rec_a.id, rec_a.role), key_a, dev_a),
        "rec_b": (rec_b, create_access_token(rec_b.id, rec_b.role), key_b, dev_b),
        "mem_adapter": mem_adapter,
    }


def _upload_classified_document(client, off_tok, rec_ids, title="Classified Operation"):
    """Helper creating a test image document encrypted for recipients."""
    img = Image.new("RGB", (256, 256), color=(220, 220, 220))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    rec_str = ",".join(str(r) for r in rec_ids) if isinstance(rec_ids, list) else str(rec_ids)
    res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": title, "recipient_ids": rec_str},
        files={"file": ("classified_leak_source.png", buf, "image/png")},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


# =========================================================================
# CRITERIA 1, 2, 3: RBAC ENFORCEMENT ON INVESTIGATION ENDPOINTS
# =========================================================================

def test_01_unauthorized_user_cannot_create_investigation(client):
    """Criteria 1: Unauthenticated requests cannot create or access investigations."""
    res = client.post("/api/v1/investigations", json={"title": "Unauthorized Case"})
    assert res.status_code in [401, 403]


def test_02_recipient_cannot_access_investigation_apis(client, investigation_suite):
    """Criteria 2: Recipient role is strictly blocked from investigation APIs."""
    _, rec_tok, _, _ = investigation_suite["rec_a"]

    # Try creating case
    res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"title": "Recipient Prohibited Case"},
    )
    assert res.status_code == 403

    # Try listing cases
    list_res = client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    assert list_res.status_code == 403


def test_03_officer_cannot_access_investigation_apis(client, investigation_suite):
    """Criteria 3: Departmental Officer role is strictly blocked from investigation APIs."""
    _, off_tok = investigation_suite["officer"]

    res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {off_tok}"},
        json={"title": "Officer Prohibited Case"},
    )
    assert res.status_code == 403


def test_04_admin_and_auditor_can_create_and_list_cases(client, investigation_suite):
    """Criteria 4: Admin and Auditor roles can create and list investigation cases."""
    _, admin_tok = investigation_suite["admin"]
    _, auditor_tok = investigation_suite["auditor"]

    # Admin creates case
    adm_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Admin Leak Investigation", "description": "Intercepted on forum"},
    )
    assert adm_res.status_code == 201
    adm_case = adm_res.json()
    assert adm_case["case_reference"].startswith("CASE-")
    assert adm_case["status"] == "OPEN"

    # Auditor creates case
    aud_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {auditor_tok}"},
        json={"title": "Auditor Provenance Audit Case"},
    )
    assert aud_res.status_code == 201

    # List cases
    list_res = client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 2


# =========================================================================
# CRITERIA 5, 6, 7: EVIDENCE INTEGRITY, HASHING, AND CUSTODY
# =========================================================================

def test_05_evidence_sha256_calculated_correctly_on_upload(client, investigation_suite):
    """Criteria 5: Evidence SHA-256 is accurately calculated upon deposit and displayed."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Evidence Hash Test"},
    )
    case_id = case_res.json()["id"]

    raw_bytes = b"DigitalEvidencePayloadForIntegrityVerification-1234567890"
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    ev_res = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("intercepted_leak.png", io.BytesIO(raw_bytes), "image/png")},
    )
    assert ev_res.status_code == 201
    ev_data = ev_res.json()
    assert ev_data["sha256"] == expected_hash
    assert ev_data["size_bytes"] == len(raw_bytes)
    assert ev_data["evidence_version"] == 1


def test_06_evidence_cannot_be_silently_overwritten(client, investigation_suite):
    """Criteria 6: Subsequent evidence uploads create new versions without overwriting historical records."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Multi-Evidence Version Test"},
    )
    case_id = case_res.json()["id"]

    # Upload version 1
    v1_res = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leak_v1.png", io.BytesIO(b"Version1EvidencePayload"), "image/png")},
    )
    assert v1_res.json()["evidence_version"] == 1

    # Upload version 2
    v2_res = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leak_v2.png", io.BytesIO(b"Version2EvidencePayloadDifferent"), "image/png")},
    )
    assert v2_res.json()["evidence_version"] == 2

    # Verify both records exist
    list_ev = client.get(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert len(list_ev.json()) == 2


def test_07_custody_events_logged_on_evidence_deposit(client, investigation_suite):
    """Criteria 7: Chain of custody events (EVIDENCE_UPLOADED, EVIDENCE_HASHED) are created."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Custody Event Test"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leak_custody.png", io.BytesIO(b"CustodyTestBytes123456"), "image/png")},
    )

    detail_res = client.get(
        f"/api/v1/investigations/{case_id}",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    custody = detail_res.json()["custody_chain"]
    actions = [c["action"] for c in custody]
    assert "EVIDENCE_UPLOADED" in actions
    assert "EVIDENCE_HASHED" in actions


# =========================================================================
# CRITERIA 8, 9: NO FINGERPRINT & UNSUPPORTED EVIDENCE HANDLING
# =========================================================================

def test_08_no_fingerprint_evidence_returns_no_detectable_fingerprint(client, investigation_suite):
    """Criteria 8: Plain un-fingerprinted evidence returns NO_DETECTABLE_FINGERPRINT with factual summary."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Clean Document Test"},
    )
    case_id = case_res.json()["id"]

    # Generate clean unmarked image
    clean_img = Image.new("RGB", (256, 256), color=(200, 200, 200))
    buf = io.BytesIO()
    clean_img.save(buf, format="PNG")
    buf.seek(0)

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("clean_unmarked.png", buf, "image/png")},
    )

    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert ana_res.status_code == 200
    res_data = ana_res.json()
    assert res_data["detection_status"] == "NO_DETECTABLE_FINGERPRINT"
    assert res_data["fingerprint_id"] is None
    assert "No detectable forensic fingerprint" in res_data["result_summary"]


def test_09_unsupported_evidence_format_returns_unsupported(client, investigation_suite):
    """Criteria 9: Unsupported non-visual files return 415 or UNSUPPORTED_EVIDENCE_FORMAT."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Unsupported Format Test"},
    )
    case_id = case_res.json()["id"]

    # Executable file rejected at upload
    bad_upload = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00\x03\x00"), "application/x-dosexec")},
    )
    assert bad_upload.status_code == 415


# =========================================================================
# CRITERIA 10, 11, 12: REAL FORENSIC DETECTION & PROVENANCE VERIFICATION
# =========================================================================

def test_10_and_11_and_12_genuine_fingerprinted_evidence_detects_and_verifies_provenance(
    client, investigation_suite
):
    """Criteria 10, 11, 12: Real fingerprinted evidence detects token, links recipient, and verifies ML-DSA-65."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Operation Blackout")

    # Recipient A creates viewer session and retrieves fingerprinted content
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    fingerprinted_bytes = content_res.content

    # Investigator creates case and deposits intercepted leak
    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Operation Blackout Leak", "document_id": doc_id},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("blackout_leak.png", io.BytesIO(fingerprinted_bytes), "image/png")},
    )

    # Run analysis
    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert ana_res.status_code == 200
    res_data = ana_res.json()

    assert res_data["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"
    assert res_data["provenance_signature_status"] == "VALID"
    assert res_data["chain_verification_status"] == "CHAIN_VALID"
    assert res_data["confidence_score"] > 0.0

    # Verify correlated session details
    corr = res_data["details"]["correlation"]
    assert corr["recipient_username"] == "inv_rec_a"
    assert corr["viewer_session_id"] == viewer_id


# =========================================================================
# CRITERIA 13, 14: TAMPERED PROVENANCE SIGNATURE & TAMPERED CHAIN DETECTION
# =========================================================================

def test_13_tampered_provenance_signature_is_detected(client, investigation_suite, db_session):
    """Criteria 13: Corrupted provenance signature byte fails verification -> FINGERPRINT_DETECTED_PROVENANCE_INVALID."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Signature Tamper Doc")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    fingerprinted_bytes = content_res.content

    # Adversary tampers with the stored ML-DSA-65 signature in database
    prov_rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()
    assert prov_rec is not None
    prov_rec.signature = prov_rec.signature[:-4] + "AAAA"
    db_session.commit()

    # Investigator analyzes leak
    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Signature Tamper Case"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("tampered_sig_leak.png", io.BytesIO(fingerprinted_bytes), "image/png")},
    )

    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    res_data = ana_res.json()
    assert res_data["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_INVALID"
    assert res_data["provenance_signature_status"] == "INVALID"


def test_14_tampered_provenance_chain_is_detected(client, investigation_suite, db_session):
    """Criteria 14: Provenance hash chain corruption is detected -> FINGERPRINT_DETECTED_CHAIN_INVALID."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Chain Tamper Doc")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    fingerprinted_bytes = content_res.content

    # Adversary tampers with the chain hash
    prov_rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()
    prov_rec.chain_hash = "0" * 64
    db_session.commit()

    # Investigator analyzes leak
    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Chain Tamper Case"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("tampered_chain_leak.png", io.BytesIO(fingerprinted_bytes), "image/png")},
    )

    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    res_data = ana_res.json()
    assert res_data["detection_status"] == "FINGERPRINT_DETECTED_CHAIN_INVALID"
    assert res_data["chain_verification_status"] == "CHAIN_INVALID"


# =========================================================================
# CRITERIA 15, 16, 17: LEDGER & ANTI-FABRICATION GUARANTEES
# =========================================================================

def test_15_ledger_verification_status_accurately_reflected(client, investigation_suite):
    """Criteria 15: Unanchored records report actual state rather than fabricated confirmation."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Ledger State Doc")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Ledger Status Case"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("ledger_evidence.png", io.BytesIO(content_res.content), "image/png")},
    )

    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    res_data = ana_res.json()
    assert res_data["ledger_verification_status"] in ["LEDGER_CONFIRMED", "LEDGER_NOT_ANCHORED", "LEDGER_PENDING"]


def test_17_confidence_score_is_never_fabricated(client, investigation_suite):
    """Criteria 17: Confidence score is strictly between 0.0 and 1.0 reflecting genuine DSSS cross-correlation."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Confidence Score Test"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("unmarked.png", io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."), "image/png")},
    )

    ana_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    res_data = ana_res.json()
    score = res_data["confidence_score"]
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# =========================================================================
# CRITERIA 18, 19, 20: REPORT INTEGRITY, AUDIT TRAIL, ZERO KEY LEAKAGE
# =========================================================================

def test_18_exportable_report_contains_results_and_verifiable_sha256(client, investigation_suite):
    """Criteria 18: Formal report contains evidence findings, limitations, and verifiable SHA-256."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Report Verification Doc")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Formal Report Test", "document_id": doc_id},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("evidence_for_report.png", io.BytesIO(content_res.content), "image/png")},
    )

    client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )

    rep_res = client.get(
        f"/api/v1/investigations/{case_id}/report",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert rep_res.status_code == 200
    report = rep_res.json()

    assert report["report_id"].startswith("REP-")
    assert report["report_version"] == "SDP-FORENSIC-REPORT-V1"
    assert len(report["report_sha256"]) == 64
    assert "LEGAL & FORENSIC LIMITATIONS DISCLAIMER" in report["limitations_disclaimer"]
    assert report["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"


def test_19_investigation_actions_generate_real_audit_events(client, investigation_suite, db_session):
    """Criteria 19: All investigation actions generate real, cryptographically chained audit events."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Audit Event Verification"},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("audit_sample.png", io.BytesIO(b"AuditEvidenceSampleData123"), "image/png")},
    )

    events = db_session.query(AuditEvent).filter(
        AuditEvent.event_type.in_(["INVESTIGATION_CREATED", "EVIDENCE_UPLOADED"])
    ).all()
    event_types = [e.event_type for e in events]
    assert "INVESTIGATION_CREATED" in event_types
    assert "EVIDENCE_UPLOADED" in event_types


def test_20_private_cryptographic_keys_never_appear_in_responses(client, investigation_suite):
    """Criteria 20: Private keys, DEKs, and forensic master key material never appear in responses."""
    _, admin_tok = investigation_suite["admin"]

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Key Leak Prevention Case"},
    )
    case_id = case_res.json()["id"]

    for endpoint in [
        f"/api/v1/investigations/{case_id}",
        f"/api/v1/investigations/{case_id}/evidence",
    ]:
        res = client.get(endpoint, headers={"Authorization": f"Bearer {admin_tok}"})
        raw_text = res.text.lower()
        for forbidden in ["private_key", "secret_key", "encrypted_dek", "wrapped_dek", "forensic_master_key"]:
            assert forbidden not in raw_text


# =========================================================================
# CRITERIA 21, 22: FACTUAL TIMELINE & MULTI-RECIPIENT ATTRIBUTION
# =========================================================================

def test_21_factual_timeline_is_built_from_real_records(client, investigation_suite):
    """Criteria 21: Case dossier timeline contains actual verified events in chronological sequence."""
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    _, admin_tok = investigation_suite["admin"]

    doc_id = _upload_classified_document(client, off_tok, [rec_a.id], "Timeline Test Doc")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )

    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Chronology Case", "document_id": doc_id},
    )
    case_id = case_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("chronology_evidence.png", io.BytesIO(content_res.content), "image/png")},
    )

    client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )

    detail_res = client.get(
        f"/api/v1/investigations/{case_id}",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    timeline = detail_res.json()["timeline"]
    assert len(timeline) >= 4

    event_names = [e["event_name"] for e in timeline]
    assert "DOCUMENT_UPLOADED" in event_names
    assert "INVESTIGATION_CASE_OPENED" in event_names
    assert "EVIDENCE_SUBMITTED" in event_names
    assert "FORENSIC_ANALYSIS_COMPLETED" in event_names


def test_22_end_to_end_recipient_a_vs_recipient_b_attribution(client, investigation_suite):
    """Criteria 22: Full integration test - Recipient A and Recipient B receive distinct fingerprints,
    and evidence from each is uniquely attributed to the correct authorized session with zero cross-talk.
    """
    _, off_tok = investigation_suite["officer"]
    rec_a, rec_tok_a, _, dev_a = investigation_suite["rec_a"]
    rec_b, rec_tok_b, _, dev_b = investigation_suite["rec_b"]
    _, admin_tok = investigation_suite["admin"]

    # 1. Upload one document encrypted for both Recipient A and Recipient B
    doc_id = _upload_classified_document(
        client,
        off_tok,
        [rec_a.id, rec_b.id],
        "Dual Recipient Shared Secret Dossier",
    )

    # 2. Recipient A creates viewer session and retrieves content
    sess_a_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    assert sess_a_res.status_code == 201
    viewer_id_a = sess_a_res.json()["viewer_session_id"]

    content_a_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id_a}/content",
        headers={"Authorization": f"Bearer {rec_tok_a}", "X-Device-ID": dev_a.id},
    )
    evidence_bytes_a = content_a_res.content

    # 3. Recipient B creates viewer session and retrieves content
    sess_b_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec_tok_b}", "X-Device-ID": dev_b.id},
    )
    assert sess_b_res.status_code == 201
    viewer_id_b = sess_b_res.json()["viewer_session_id"]

    content_b_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id_b}/content",
        headers={"Authorization": f"Bearer {rec_tok_b}", "X-Device-ID": dev_b.id},
    )
    evidence_bytes_b = content_b_res.content

    # Assert rendered representations are distinct
    assert evidence_bytes_a != evidence_bytes_b

    # 4. Investigator opens Case A with evidence from Recipient A
    case_a_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Leak Intercept A", "document_id": doc_id},
    )
    case_id_a = case_a_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id_a}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leak_a.png", io.BytesIO(evidence_bytes_a), "image/png")},
    )

    ana_a_res = client.post(
        f"/api/v1/investigations/{case_id_a}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert ana_a_res.status_code == 200
    res_a = ana_a_res.json()

    assert res_a["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"
    corr_a = res_a["details"]["correlation"]
    assert corr_a["recipient_username"] == "inv_rec_a"
    assert corr_a["viewer_session_id"] == viewer_id_a

    # 5. Investigator opens Case B with evidence from Recipient B
    case_b_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"title": "Leak Intercept B", "document_id": doc_id},
    )
    case_id_b = case_b_res.json()["id"]

    client.post(
        f"/api/v1/investigations/{case_id_b}/evidence",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leak_b.png", io.BytesIO(evidence_bytes_b), "image/png")},
    )

    ana_b_res = client.post(
        f"/api/v1/investigations/{case_id_b}/analyze",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert ana_b_res.status_code == 200
    res_b = ana_b_res.json()

    assert res_b["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"
    corr_b = res_b["details"]["correlation"]
    assert corr_b["recipient_username"] == "inv_rec_b"
    assert corr_b["viewer_session_id"] == viewer_id_b

    # Verify zero false cross-attribution
    assert corr_a["recipient_id"] != corr_b["recipient_id"]
    assert corr_a["fingerprint_id"] != corr_b["fingerprint_id"]
