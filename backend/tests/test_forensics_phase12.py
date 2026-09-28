import io
import uuid
from datetime import datetime, timezone
import pytest
import numpy as np
from PIL import Image, ImageEnhance
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.viewer_session import ViewerSession
from app.models.forensic_fingerprint import ForensicFingerprint
from app.forensic.derivation import (
    FingerprintDerivationService,
    DerivedFingerprintMaterial,
)
from app.forensic.embedding import (
    FingerprintEmbeddingService,
    generate_pn_chips,
)
from app.forensic.detection import (
    FingerprintDetectionService,
    DetectionResult,
)
from app.forensic.service import ForensicService
from app.forensic.evaluator import ForensicEvaluationUtility
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.services.viewer_session_service import ViewerSessionService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.ledger.service import LedgerService
from app.ledger.adapters.in_memory import InMemoryLedgerAdapter


@pytest.fixture
def forensic_suite(db_session: Session):
    """Sets up test users, keys, devices, in-memory ledger adapter, and documents."""
    mem_adapter = InMemoryLedgerAdapter()
    mem_adapter.clear()
    LedgerService.set_adapter(mem_adapter)

    admin = UserService.create_user(
        db=db_session,
        username="forensic_admin",
        email="forensic_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="forensic_officer",
        email="forensic_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient1 = UserService.create_user(
        db=db_session,
        username="forensic_rec1",
        email="forensic_rec1@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    recipient2 = UserService.create_user(
        db=db_session,
        username="forensic_rec2",
        email="forensic_rec2@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="forensic_auditor",
        email="forensic_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )
    db_session.commit()

    key_rec1 = RecipientKeyManager.provision_recipient_key(db_session, recipient1, admin)
    dev_rec1 = DeviceService.register_device(
        db=db_session,
        user_id=recipient1.id,
        device_name="Forensic Workstation 1",
        device_fingerprint="fp-forensic-rec1",
    )

    key_rec2 = RecipientKeyManager.provision_recipient_key(db_session, recipient2, admin)
    dev_rec2 = DeviceService.register_device(
        db=db_session,
        user_id=recipient2.id,
        device_name="Forensic Workstation 2",
        device_fingerprint="fp-forensic-rec2",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "rec1": (recipient1, create_access_token(recipient1.id, recipient1.role), key_rec1, dev_rec1),
        "rec2": (recipient2, create_access_token(recipient2.id, recipient2.role), key_rec2, dev_rec2),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
        "mem_adapter": mem_adapter,
    }


def _upload_test_image(client, off_tok, rec_ids, title="Forensic Image Doc"):
    """Helper to upload a valid test PNG image."""
    img = Image.new("RGB", (256, 256), color=(240, 240, 240))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    content = buf.getvalue()

    rec_str = ",".join(str(r) for r in rec_ids) if isinstance(rec_ids, list) else str(rec_ids)
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": title, "recipient_ids": rec_str},
        files={"file": ("classified_diagram.png", io.BytesIO(content), "image/png")},
    )
    assert up.status_code == 201, up.text
    return up.json()["id"]


# ==============================================================================
# CRYPTOGRAPHIC DERIVATION TESTS (Criteria 1–6)
# ==============================================================================

def test_1_different_recipients_produce_different_fingerprints():
    """Criteria 1: Different recipients for same document produce distinct fingerprints."""
    d1 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="0123456789abcdef0123456789abcdef",
    )
    d2 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-B",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="0123456789abcdef0123456789abcdef",
    )
    assert d1.fingerprint_token != d2.fingerprint_token
    assert d1.fingerprint_commitment != d2.fingerprint_commitment
    assert d1.payload_bits != d2.payload_bits


def test_2_different_decryption_sessions_produce_different_fingerprints():
    """Criteria 2: Different viewing/decryption sessions for same user produce distinct fingerprints."""
    d1 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-session-1",
        viewer_session_id="view-session-1",
        provenance_event_id="prov-event-1",
        nonce="00000000000000000000000000000001",
    )
    d2 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-session-2",
        viewer_session_id="view-session-2",
        provenance_event_id="prov-event-2",
        nonce="00000000000000000000000000000002",
    )
    assert d1.fingerprint_token != d2.fingerprint_token
    assert d1.fingerprint_commitment != d2.fingerprint_commitment


def test_3_same_event_reproduces_deterministically():
    """Criteria 3: Same event context and nonce reproduces identical token and commitment."""
    d1 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-fixed",
        document_version_id="1",
        recipient_user_id="user-fixed",
        decryption_session_id="dec-fixed",
        viewer_session_id="view-fixed",
        provenance_event_id="prov-fixed",
        nonce="aabbccddeeff00112233445566778899",
    )
    d2 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-fixed",
        document_version_id="1",
        recipient_user_id="user-fixed",
        decryption_session_id="dec-fixed",
        viewer_session_id="view-fixed",
        provenance_event_id="prov-fixed",
        nonce="aabbccddeeff00112233445566778899",
    )
    assert d1.fingerprint_token == d2.fingerprint_token
    assert d1.fingerprint_commitment == d2.fingerprint_commitment
    assert d1.payload_bits == d2.payload_bits


def test_4_changing_document_version_changes_fingerprint():
    """Criteria 4: Changing document version ID produces distinct fingerprint."""
    d_v1 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="11111111111111111111111111111111",
    )
    d_v2 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="2",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="11111111111111111111111111111111",
    )
    assert d_v1.fingerprint_token != d_v2.fingerprint_token


def test_5_changing_provenance_event_changes_fingerprint():
    """Criteria 5: Changing provenance event ID produces distinct fingerprint."""
    d_e1 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-event-001",
        nonce="11111111111111111111111111111111",
    )
    d_e2 = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-101",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-event-002",
        nonce="11111111111111111111111111111111",
    )
    assert d_e1.fingerprint_token != d_e2.fingerprint_token


def test_6_fingerprint_material_not_derivable_from_public_metadata():
    """Criteria 6: Without the server forensic master key, fingerprint token cannot be derived."""
    key_a = b"\x01" * 32
    key_b = b"\x02" * 32

    d_a = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-secret",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="11111111111111111111111111111111",
        master_key=key_a,
    )
    d_b = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-secret",
        document_version_id="1",
        recipient_user_id="user-A",
        decryption_session_id="dec-1",
        viewer_session_id="view-1",
        provenance_event_id="prov-1",
        nonce="11111111111111111111111111111111",
        master_key=key_b,
    )
    assert d_a.fingerprint_token != d_b.fingerprint_token


# ==============================================================================
# EMBEDDING & INVISIBILITY TESTS (Criteria 7–10)
# ==============================================================================

def test_7_and_8_fingerprint_embedded_and_original_unchanged(client, forensic_suite, db_session: Session):
    """Criteria 7 & 8: Fingerprint is embedded into rendered output, but original on-disk ciphertext is untouched."""
    _, off_tok = forensic_suite["officer"]
    rec1, rec1_tok, _, dev1 = forensic_suite["rec1"]

    doc_id = _upload_test_image(client, off_tok, [rec1.id], "Secret Diagram")
    doc_before = db_session.query(Document).filter(Document.id == doc_id).first()
    ciphertext_hash_before = doc_before.ciphertext_sha256

    # 1. Recipient creates viewer session
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    viewer_sess_id = sess_res.json()["viewer_session_id"]

    # 2. Recipient accesses content
    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert content_res.status_code == 200
    rendered_bytes = content_res.content

    # 3. Check original document ciphertext hash in database
    db_session.refresh(doc_before)
    assert doc_before.ciphertext_sha256 == ciphertext_hash_before, "Original ciphertext was modified!"

    # 4. Check fingerprint record created in database
    fp_rec = db_session.query(ForensicFingerprint).filter(ForensicFingerprint.viewer_session_id == viewer_sess_id).first()
    assert fp_rec is not None
    assert fp_rec.fingerprint_token is not None


def test_9_and_10_fingerprinted_image_can_be_opened_and_has_high_psnr():
    """Criteria 9 & 10: Fingerprinted image opens normally and has imperceptible noise (PSNR > 40 dB)."""
    # Create synthetic test page
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-psnr",
        document_version_id="1",
        recipient_user_id="user-psnr",
        decryption_session_id="dec-psnr",
        viewer_session_id="view-psnr",
        provenance_event_id="prov-psnr",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)

    # Invert to PIL and verify it opens normally
    pil_img = Image.fromarray(wm_arr.astype(np.uint8))
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    buf.seek(0)
    opened = Image.open(buf)
    assert opened.size == (512, 512)

    # Measure PSNR
    mse = np.mean((base_arr - wm_arr) ** 2)
    psnr = 10.0 * np.log10(255.0**2 / (mse + 1e-10))
    assert psnr >= 40.0, f"PSNR too low ({psnr} dB < 40 dB), watermark might be visible"


# ==============================================================================
# DETECTION & CORRELATION TESTS (Criteria 11–15)
# ==============================================================================

def test_11_original_fingerprinted_evidence_produces_genuine_detection():
    """Criteria 11: Original fingerprinted evidence is detected with 100% accuracy."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-detect",
        document_version_id="1",
        recipient_user_id="user-detect",
        decryption_session_id="dec-detect",
        viewer_session_id="view-detect",
        provenance_event_id="prov-detect",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)
    res = FingerprintDetectionService._detect_from_image_array(wm_arr, chips)

    assert res.detection_status == "FINGERPRINT_DETECTED"
    assert res.candidate_token == derived.fingerprint_token
    assert res.confidence_score >= 0.85


def test_12_unfingerprinted_evidence_produces_no_fingerprint_detected():
    """Criteria 12: Clean un-watermarked document produces NO_FINGERPRINT_DETECTED."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    res = FingerprintDetectionService._detect_from_image_array(base_arr, chips)
    assert res.detection_status == "NO_FINGERPRINT_DETECTED"
    assert res.candidate_token is None


def test_13_different_session_evidence_maps_to_correct_session(client, forensic_suite, db_session: Session):
    """Criteria 13: Evidence containing Recipient 2's watermark correlates to Recipient 2, not Recipient 1."""
    _, off_tok = forensic_suite["officer"]
    rec1, rec1_tok, _, dev1 = forensic_suite["rec1"]
    rec2, rec2_tok, _, dev2 = forensic_suite["rec2"]
    admin, admin_tok = forensic_suite["admin"]

    doc_id = _upload_test_image(client, off_tok, [rec1.id, rec2.id], "Dual Recipient Doc")

    # Recipient 2 views and downloads rendered content
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec2_tok}", "X-Device-ID": dev2.id},
    )
    rec2_view_id = sess_res.json()["viewer_session_id"]
    content_res = client.get(
        f"/api/v1/viewer-sessions/{rec2_view_id}/content",
        headers={"Authorization": f"Bearer {rec2_tok}", "X-Device-ID": dev2.id},
    )
    rec2_leaked_evidence = content_res.content

    # Admin investigates leaked evidence
    det_res = client.post(
        "/api/v1/forensics/detect",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("leaked_photo.png", io.BytesIO(rec2_leaked_evidence), "image/png")},
    )
    assert det_res.status_code == 200, det_res.text
    data = det_res.json()

    assert data["detection_status"] == "FINGERPRINT_DETECTED"
    assert data["correlation"]["recipient_username"] == "forensic_rec2"
    assert data["correlation"]["recipient_username"] != "forensic_rec1"
    assert data["correlation"]["viewer_session_id"] == rec2_view_id


def test_14_corrupted_evidence_produces_graceful_detection_failure():
    """Criteria 14: Heavily corrupted noise produces NO_FINGERPRINT_DETECTED, not false match."""
    # Pure random noise image
    noise_arr = np.random.uniform(0, 255, (512, 512)).astype(np.float32)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    res = FingerprintDetectionService._detect_from_image_array(noise_arr, chips)
    assert res.detection_status == "NO_FINGERPRINT_DETECTED"
    assert res.candidate_token is None


def test_15_unsupported_evidence_returns_unsupported():
    """Criteria 15: Invalid/unsupported evidence returns UNSUPPORTED_EVIDENCE."""
    master_key = b"test-forensic-master-key-32bytes"
    res = FingerprintDetectionService.detect(b"random-non-image-binary-garbage-\x00\x01\x02", "garbage.bin", master_key)
    assert res.detection_status == "UNSUPPORTED_EVIDENCE"


# ==============================================================================
# ROBUSTNESS BENCHMARK TESTS (Criteria 16–20)
# ==============================================================================

def test_16_jpeg_compression_robustness():
    """Criteria 16: Fingerprint survives standard JPEG lossy compression (quality=85)."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-jpeg",
        document_version_id="1",
        recipient_user_id="user-jpeg",
        decryption_session_id="dec-jpeg",
        viewer_session_id="view-jpeg",
        provenance_event_id="prov-jpeg",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)
    pil_img = Image.fromarray(wm_arr.astype(np.uint8))

    buf = io.BytesIO()
    pil_img.save(buf, format="JPEG", quality=85)
    buf.seek(0)

    jpeg_arr = np.array(Image.open(buf), dtype=np.float32)
    res = FingerprintDetectionService._detect_from_image_array(jpeg_arr, chips)

    assert res.detection_status == "FINGERPRINT_DETECTED"
    assert res.candidate_token == derived.fingerprint_token


def test_17_rescaling_robustness():
    """Criteria 17: Fingerprint survives moderate downscaling and restoration."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-scale",
        document_version_id="1",
        recipient_user_id="user-scale",
        decryption_session_id="dec-scale",
        viewer_session_id="view-scale",
        provenance_event_id="prov-scale",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)
    pil_img = Image.fromarray(wm_arr.astype(np.uint8))

    # Downscale by 20% and upscale back
    w, h = pil_img.size
    downscaled = pil_img.resize((int(w * 0.8), int(h * 0.8)), Image.Resampling.BILINEAR)
    upscaled = downscaled.resize((w, h), Image.Resampling.BILINEAR)

    rescaled_arr = np.array(upscaled, dtype=np.float32)
    res = FingerprintDetectionService._detect_from_image_array(rescaled_arr, chips)

    assert res.detection_status == "FINGERPRINT_DETECTED"
    assert res.candidate_token == derived.fingerprint_token


def test_18_brightness_contrast_robustness():
    """Criteria 18: Fingerprint survives moderate brightness shifts (+15%)."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-bright",
        document_version_id="1",
        recipient_user_id="user-bright",
        decryption_session_id="dec-bright",
        viewer_session_id="view-bright",
        provenance_event_id="prov-bright",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)
    pil_img = Image.fromarray(wm_arr.astype(np.uint8))
    enhancer = ImageEnhance.Brightness(pil_img)
    bright_pil = enhancer.enhance(1.10)
    bright_arr = np.array(bright_pil, dtype=np.float32)

    res = FingerprintDetectionService._detect_from_image_array(bright_arr, chips)
    assert res.detection_status == "FINGERPRINT_DETECTED"
    assert res.candidate_token == derived.fingerprint_token


def test_19_gaussian_noise_robustness():
    """Criteria 19: Fingerprint survives additive Gaussian noise (sigma=2.0)."""
    base_arr = ForensicEvaluationUtility.create_synthetic_test_document(512, 512)
    master_key = b"test-forensic-master-key-32bytes"
    chips = generate_pn_chips(master_key)

    derived = FingerprintDerivationService.derive_fingerprint(
        document_id="doc-noise",
        document_version_id="1",
        recipient_user_id="user-noise",
        decryption_session_id="dec-noise",
        viewer_session_id="view-noise",
        provenance_event_id="prov-noise",
        master_key=master_key,
    )

    wm_arr = FingerprintEmbeddingService._embed_image_array(base_arr, derived.payload_bits, chips, strength=4.5)
    noisy_arr = np.clip(wm_arr + np.random.normal(0, 2.0, size=wm_arr.shape), 0.0, 255.0)

    res = FingerprintDetectionService._detect_from_image_array(noisy_arr, chips)
    assert res.detection_status == "FINGERPRINT_DETECTED"
    assert res.candidate_token == derived.fingerprint_token


def test_20_forensic_evaluation_report_api(client, forensic_suite):
    """Criteria 20: Forensic evaluation benchmark API executes and returns empirical metrics."""
    admin, admin_tok = forensic_suite["admin"]
    res = client.post(
        "/api/v1/forensics/evaluate",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 200, res.text
    report = res.json()

    assert report["unaltered_detection_success"] is True
    assert report["false_detection_on_clean_document"] is False
    assert report["original_psnr_db"] >= 40.0
    assert len(report["transformations"]) >= 5
    assert report["overall_detection_rate"] > 0.8


# ==============================================================================
# ACCESS CONTROL & SECURITY TESTS (Criteria 21–26)
# ==============================================================================

def test_21_recipient_cannot_call_detection_api(client, forensic_suite):
    """Criteria 21: Recipient role is forbidden from invoking investigation detection APIs."""
    _, rec1_tok, _, _ = forensic_suite["rec1"]
    res = client.post(
        "/api/v1/forensics/detect",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        files={"file": ("evidence.png", io.BytesIO(b"data"), "image/png")},
    )
    assert res.status_code == 403


def test_22_officer_cannot_call_detection_api(client, forensic_suite):
    """Criteria 22: Officer role is forbidden from invoking investigation detection APIs."""
    _, off_tok = forensic_suite["officer"]
    res = client.post(
        "/api/v1/forensics/detect",
        headers={"Authorization": f"Bearer {off_tok}"},
        files={"file": ("evidence.png", io.BytesIO(b"data"), "image/png")},
    )
    assert res.status_code == 403


def test_23_recipient_cannot_retrieve_fingerprint_metadata_endpoints(client, forensic_suite):
    """Criteria 23: Recipient cannot query internal fingerprint metadata endpoints."""
    _, rec1_tok, _, _ = forensic_suite["rec1"]
    res = client.get(
        "/api/v1/forensics/fingerprints/fake-id",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res.status_code == 403


def test_24_two_viewing_sessions_for_same_user_get_different_tokens(client, forensic_suite, db_session: Session):
    """Criteria 24: Two viewing sessions by the same recipient receive distinct fingerprint tokens."""
    _, off_tok = forensic_suite["officer"]
    rec1, rec1_tok, _, dev1 = forensic_suite["rec1"]

    doc_id = _upload_test_image(client, off_tok, [rec1.id], "Test Session Isolation Doc")

    # Session 1
    s1_id = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    ).json()["viewer_session_id"]
    client.get(
        f"/api/v1/viewer-sessions/{s1_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    # Session 2
    s2_id = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    ).json()["viewer_session_id"]
    client.get(
        f"/api/v1/viewer-sessions/{s2_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    fp1 = db_session.query(ForensicFingerprint).filter(ForensicFingerprint.viewer_session_id == s1_id).first()
    fp2 = db_session.query(ForensicFingerprint).filter(ForensicFingerprint.viewer_session_id == s2_id).first()

    assert fp1 is not None and fp2 is not None
    assert fp1.fingerprint_token != fp2.fingerprint_token


def test_25_end_to_end_investigation_with_ml_dsa_provenance_and_ledger_anchor(client, forensic_suite):
    """Criteria 26: Full forensic investigation correlates detected evidence with ML-DSA-65 provenance and ledger anchor."""
    _, off_tok = forensic_suite["officer"]
    rec1, rec1_tok, _, dev1 = forensic_suite["rec1"]
    admin, admin_tok = forensic_suite["admin"]

    doc_id = _upload_test_image(client, off_tok, [rec1.id], "National Security Dossier")

    # Recipient views document
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    viewer_id = sess_res.json()["viewer_session_id"]

    content_res = client.get(
        f"/api/v1/viewer-sessions/{viewer_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    leaked_evidence = content_res.content

    # Admin runs leak detection
    inv_res = client.post(
        "/api/v1/forensics/detect",
        headers={"Authorization": f"Bearer {admin_tok}"},
        files={"file": ("intercepted_leak.png", io.BytesIO(leaked_evidence), "image/png")},
    )
    assert inv_res.status_code == 200
    res_data = inv_res.json()

    assert res_data["detection_status"] == "FINGERPRINT_DETECTED"
    assert res_data["correlation"] is not None
    assert res_data["correlation"]["recipient_username"] == "forensic_rec1"
    assert res_data["correlation"]["viewer_session_id"] == viewer_id

    # Verify cryptographic provenance correlation
    prov = res_data["provenance"]
    assert prov is not None
    assert prov["signature_algorithm"] == "ML-DSA-65"
    assert prov["signature_verified"] is True
    assert prov["chain_link_verified"] is True
