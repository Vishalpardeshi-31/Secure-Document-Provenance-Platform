"""Phase 10: Tamper-Evident Provenance Chain & Permissioned Ledger Tests.

Covers:
1. Deterministic Genesis & Hash Chaining (Genesis -> 1 -> 2 -> 3)
2. Tampering resistance across all chain inputs (sequence, prev_hash, canonical_hash, chain_hash, event_id)
3. Reordering & Deletion detection (SEQUENCE_GAP & PREVIOUS_HASH_MISMATCH)
4. Signature corruption detection (SIGNATURE_INVALID)
5. Ledger anchoring, transaction IDs, idempotency, and outbox retry
6. Ledger anchor verification and mismatch detection (LEDGER_ANCHOR_MISMATCH)
7. Concurrency-safe sequence allocation under multi-threaded execution
8. Full-chain scalability verification (100+ chain records)
"""
import io
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.provenance.models import ProvenanceRecord, ProvenanceChainHead, LedgerOutbox
from app.provenance.service import ProvenanceService
from app.provenance.chain import ProvenanceChainService
from app.provenance.canonicalization import CanonicalizationService
from app.provenance.hashing import ProvenanceHashService
from app.provenance.signing import ProvenanceSigningService
from app.ledger.service import LedgerService
from app.ledger.adapters.in_memory import InMemoryLedgerAdapter
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token


@pytest.fixture
def chain_suite(db_session: Session):
    """Sets up an in-memory ledger adapter and baseline test users."""
    mem_adapter = InMemoryLedgerAdapter()
    mem_adapter.clear()
    LedgerService.set_adapter(mem_adapter)

    admin = UserService.create_user(
        db=db_session,
        username="chain_admin",
        email="chain_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="chain_officer",
        email="chain_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="chain_recipient",
        email="chain_recipient@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="chain_auditor",
        email="chain_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )
    db_session.commit()

    key_rec = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)
    dev_rec = DeviceService.register_device(
        db=db_session,
        user_id=recipient.id,
        device_name="Workstation Chain 1",
        device_fingerprint="fp-chain-rec-01",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role), key_rec, dev_rec),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
        "mem_adapter": mem_adapter,
    }


def _upload_and_decrypt(client, off_tok, rec_tok, dev_id, rec_id, title="Chain Test Doc"):
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": title, "recipient_ids": str(rec_id)},
        files={"file": (f"{title}.txt", io.BytesIO(b"Classified Provenance Payload Content"), "text/plain")},
    )
    assert up.status_code == 201, up.text
    doc_id = up.json()["id"]

    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}", "X-Device-ID": dev_id},
    )
    assert dec.status_code == 200, dec.text
    return doc_id


def test_chain_creation_and_hash_linkage(client, chain_suite, db_session: Session):
    """Section 2, 3, 4: Genesis is created once, and subsequent events link sequentially (0 -> 1 -> 2 -> 3)."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]

    # Before decryptions, genesis head exists upon inspection
    head = ProvenanceService.get_chain_head(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert head.latest_sequence == 0
    assert len(head.genesis_hash) == 64

    # Genesis record in DB
    genesis = (
        db_session.query(ProvenanceRecord)
        .filter(ProvenanceRecord.chain_sequence == 0)
        .first()
    )
    assert genesis is not None
    assert genesis.previous_record_hash == "0" * 64
    assert genesis.chain_hash == head.genesis_hash
    assert genesis.ledger_status == "CONFIRMED"

    # Event 1
    doc1_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc 1")
    rec1 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc1_id).first()
    assert rec1.chain_sequence == 1
    assert rec1.previous_record_hash == genesis.chain_hash
    assert rec1.chain_hash == ProvenanceChainService.calculate_chain_hash(
        rec1.chain_id, rec1.chain_sequence, rec1.previous_record_hash, rec1.canonical_record_hash, rec1.event_id
    )

    # Event 2
    doc2_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc 2")
    rec2 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc2_id).first()
    assert rec2.chain_sequence == 2
    assert rec2.previous_record_hash == rec1.chain_hash

    # Event 3
    doc3_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc 3")
    rec3 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc3_id).first()
    assert rec3.chain_sequence == 3
    assert rec3.previous_record_hash == rec2.chain_hash

    # Full chain audit
    v = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert v.chain_valid is True
    assert v.records_checked == 4  # genesis + 3 events
    assert v.first_invalid_sequence is None
    assert v.signatures_verified == 3
    assert v.ledger_anchors_verified == 4


def test_chain_tamper_detection_every_field(client, chain_suite, db_session: Session):
    """Section 18, 19, 26: Modifying any chain field (sequence, prev_hash, canonical_hash, chain_hash, event_id) causes verification failure."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]

    _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Tamper Target Doc")
    rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.chain_sequence == 1).first()

    orig_seq = rec.chain_sequence
    orig_prev_hash = rec.previous_record_hash
    orig_can_hash = rec.canonical_record_hash
    orig_chain_hash = rec.chain_hash
    orig_event_id = rec.event_id

    # 1. Tamper sequence
    rec.chain_sequence = 99
    db_session.flush()
    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type in ("SEQUENCE_GAP", "CHAIN_HASH_MISMATCH")
    rec.chain_sequence = orig_seq
    db_session.flush()

    # 2. Tamper previous_record_hash
    rec.previous_record_hash = "f" * 64
    db_session.flush()
    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type in ("PREVIOUS_HASH_MISMATCH", "CHAIN_HASH_MISMATCH")
    rec.previous_record_hash = orig_prev_hash
    db_session.flush()

    # 3. Tamper canonical_record_hash
    rec.canonical_record_hash = "e" * 64
    db_session.flush()
    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type == "CHAIN_HASH_MISMATCH"
    rec.canonical_record_hash = orig_can_hash
    db_session.flush()

    # 4. Tamper chain_hash
    rec.chain_hash = "a" * 64
    db_session.flush()
    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type == "CHAIN_HASH_MISMATCH"
    rec.chain_hash = orig_chain_hash
    db_session.flush()

    # 5. Tamper event_id
    rec.event_id = "TAMPERED-EVENT-ID"
    db_session.flush()
    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type == "CHAIN_HASH_MISMATCH"
    rec.event_id = orig_event_id
    db_session.flush()

    # Restored -> valid
    restored = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert restored.chain_valid is True


def test_chain_reordering_and_deletion_detection(client, chain_suite, db_session: Session):
    """Section 26: Swapping records or deleting a record is immediately detected as SEQUENCE_GAP or PREVIOUS_HASH_MISMATCH."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]

    _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc A")
    _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc B")
    _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Doc C")

    rec1 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.chain_sequence == 1).first()
    rec2 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.chain_sequence == 2).first()
    rec3 = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.chain_sequence == 3).first()

    # Reordering test: swap sequence numbers between rec2 and rec3
    # Use temporary sequence to avoid unique constraint collision during swap
    rec2.chain_sequence = 9999
    db_session.flush()
    rec3.chain_sequence = 2
    db_session.flush()
    rec2.chain_sequence = 3
    db_session.flush()
    res_swap = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res_swap.chain_valid is False
    assert res_swap.failure_type in ("PREVIOUS_HASH_MISMATCH", "CHAIN_HASH_MISMATCH")

    # Restore order
    rec2.chain_sequence = 9999
    db_session.flush()
    rec3.chain_sequence = 3
    db_session.flush()
    rec2.chain_sequence = 2
    db_session.flush()

    # Deletion test: delete middle record rec2
    db_session.delete(rec2)
    db_session.flush()
    res_del = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res_del.chain_valid is False
    assert res_del.failure_type == "SEQUENCE_GAP"
    assert res_del.first_invalid_sequence == 3


def test_chain_signature_corruption_detection(client, chain_suite, db_session: Session):
    """Section 18, 26: A corrupted ML-DSA-65 signature on any chain record causes chain verification failure."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]

    _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Sig Test Doc")
    prov_rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.chain_sequence == 1).first()

    orig_sig = prov_rec.signature
    # Corrupt signature string
    corrupted_sig = ("B" if orig_sig[0] != "B" else "A") + orig_sig[1:]
    prov_rec.signature = corrupted_sig
    db_session.flush()

    res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert res.chain_valid is False
    assert res.failure_type == "SIGNATURE_INVALID"
    assert res.first_invalid_sequence == 1


def test_ledger_anchoring_outbox_retry_and_idempotency(client, chain_suite, db_session: Session):
    """Section 12, 14, 15, 16: Real transaction IDs, fail-open outbox retry when ledger temporarily offline, and idempotency."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]
    mem_adapter: InMemoryLedgerAdapter = chain_suite["mem_adapter"]

    # 1. Normal decryption -> immediate ledger anchor
    doc_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Ledger Anchor Doc")
    prov_rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()
    assert prov_rec.ledger_status == "CONFIRMED"
    assert prov_rec.ledger_transaction_id.startswith("TX-")
    assert prov_rec.ledger_record_hash == prov_rec.chain_hash

    # Verify anchor via service
    anchor_check = ProvenanceService.verify_ledger_anchor(db_session, prov_rec.event_id)
    assert anchor_check.is_anchored is True
    assert anchor_check.hash_matched is True
    assert anchor_check.status == "CONFIRMED"

    # 2. Simulate ledger network outage
    mem_adapter.should_fail = True
    doc_offline_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Offline Doc")
    rec_offline = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_offline_id).first()
    assert rec_offline.ledger_status == "SIGNED_BUT_NOT_ANCHORED"

    # Outbox has pending entry
    outbox_item = db_session.query(LedgerOutbox).filter(LedgerOutbox.event_id == rec_offline.event_id).first()
    assert outbox_item is not None
    assert outbox_item.status == "PENDING"

    # 3. Restore ledger network & process outbox
    mem_adapter.should_fail = False
    admin, _ = chain_suite["admin"]
    proc_res = ProvenanceService.process_ledger_outbox(db_session, admin_user=admin, max_items=10)
    assert proc_res.confirmed >= 1

    db_session.refresh(rec_offline)
    assert rec_offline.ledger_status == "CONFIRMED"
    assert rec_offline.ledger_transaction_id is not None

    # Anchor verification now passes
    anchor_offline = ProvenanceService.verify_ledger_anchor(db_session, rec_offline.event_id)
    assert anchor_offline.is_anchored is True
    assert anchor_offline.hash_matched is True

    # 4. Idempotency: Processing again causes zero duplicate entries
    re_proc = ProvenanceService.process_ledger_outbox(db_session, admin_user=admin, max_items=10)
    assert re_proc.processed == 0


def test_ledger_anchor_mismatch_detected(client, chain_suite, db_session: Session):
    """Section 20: Ledger anchor mismatch is detected if the external ledger returns a different hash."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]
    mem_adapter: InMemoryLedgerAdapter = chain_suite["mem_adapter"]

    doc_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "Mismatch Doc")
    rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()

    # Corrupt the ledger's internal record
    ledger_entry = mem_adapter.get_record(rec.ledger_transaction_id)
    assert ledger_entry is not None
    ledger_entry["chain_hash"] = "9" * 64

    # Verify single anchor
    ver_res = ProvenanceService.verify_ledger_anchor(db_session, rec.event_id)
    assert ver_res.is_anchored is True
    assert ver_res.hash_matched is False
    assert ver_res.status == "MISMATCH"

    # Full chain verification catches ledger mismatch
    chain_res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert chain_res.chain_valid is False
    assert chain_res.failure_type == "LEDGER_ANCHOR_MISMATCH"


def test_concurrent_provenance_events_preserve_chain_integrity(client, chain_suite, db_session: Session):
    """Section 25, 26: Concurrent decryptions preserve strictly ordered sequence numbers and valid chain hashes."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]

    # Pre-upload 10 documents
    doc_ids = []
    for i in range(10):
        up = client.post(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {off_tok}"},
            data={"title": f"Concurrent Doc {i}", "recipient_ids": str(rec.id)},
            files={"file": (f"concurrent_{i}.txt", io.BytesIO(f"Concurrent content {i}".encode("utf-8")), "text/plain")},
        )
        assert up.status_code == 201
        doc_ids.append(up.json()["id"])

    # Concurrently execute 10 decryptions across multiple threads
    errors = []

    def _do_decrypt(doc_id):
        try:
            res = client.post(
                f"/api/v1/documents/{doc_id}/decrypt",
                headers={"Authorization": f"Bearer {rec_tok}", "X-Device-ID": dev.id},
            )
            if res.status_code != 200:
                errors.append(f"Decrypt {doc_id} failed: {res.status_code} {res.text}")
        except Exception as e:
            errors.append(str(e))

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(_do_decrypt, doc_ids))

    assert len(errors) == 0, f"Errors during concurrent decryption: {errors}"

    # Verify sequences: must be strictly 1..10 (or continuation from previous tests) with no duplicates
    records = (
        db_session.query(ProvenanceRecord)
        .filter(ProvenanceRecord.chain_id == ProvenanceService.DEFAULT_CHAIN_ID)
        .order_by(ProvenanceRecord.chain_sequence.asc())
        .all()
    )

    sequences = [r.chain_sequence for r in records]
    assert len(sequences) == len(set(sequences)), "Duplicate sequence numbers detected!"
    # Must be contiguous from 0 to N
    assert sequences == list(range(len(sequences)))

    # Full chain audit passes
    v = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert v.chain_valid is True
    assert v.records_checked == len(records)
    assert v.first_invalid_sequence is None


def test_scale_chain_verification_100_records(client, chain_suite, db_session: Session):
    """Section 26: Create 100+ chain records and verify the entire chain from genesis to head."""
    admin, _ = chain_suite["admin"]
    user, _, key_rec, dev = chain_suite["recipient"]

    # Efficiently generate 100 records directly through service
    # ensuring full canonicalization, hashing, signing, chaining, and anchoring
    for i in range(100):
        ProvenanceService.record_decryption_provenance(
            db=db_session,
            document_id=f"scale-doc-{i:04d}",
            document_version_id="1",
            user_id=user.id,
            recipient_key_id=key_rec.id,
            recipient_key_version=key_rec.key_version,
            device_id=dev.id,
            decryption_session_id=str(uuid.uuid4()),
            policy_id="SCALE-POLICY",
            policy_version=1,
            access_type="NORMAL",
            document_plaintext_sha256="a" * 64,
            document_ciphertext_sha256="b" * 64,
        )

    head = ProvenanceService.get_chain_head(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert head.latest_sequence >= 100

    # Execute full chain audit
    audit_res = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID, verifying_user=admin)
    assert audit_res.chain_valid is True
    assert audit_res.records_checked >= 101  # genesis + 100
    assert audit_res.first_invalid_sequence is None
    assert audit_res.signatures_verified >= 100
    assert audit_res.ledger_anchors_verified >= 100


def test_chain_endpoints_via_api(client, chain_suite):
    """Section 17, 18: REST API endpoints for chain head, chain records, and full-chain verification."""
    _, off_tok = chain_suite["officer"]
    rec, rec_tok, _, dev = chain_suite["recipient"]
    _, aud_tok = chain_suite["auditor"]

    doc_id = _upload_and_decrypt(client, off_tok, rec_tok, dev.id, rec.id, "API Test Doc")

    # 1. GET /api/v1/provenance/chain/head
    head_res = client.get(
        "/api/v1/provenance/chain/head",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert head_res.status_code == 200, head_res.text
    head_data = head_res.json()
    assert head_data["chain_id"] == "PLATFORM-PROVENANCE-CHAIN"
    assert head_data["latest_sequence"] >= 1

    # 2. GET /api/v1/provenance/chain/records
    rec_res = client.get(
        "/api/v1/provenance/chain/records?skip=0&limit=5",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert rec_res.status_code == 200
    records = rec_res.json()
    assert len(records) >= 2
    assert records[0]["chain_sequence"] == 0

    # 3. POST /api/v1/provenance/chain/verify
    verify_res = client.post(
        "/api/v1/provenance/chain/verify",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["chain_valid"] is True
    assert v_data["records_checked"] >= 2

    # 4. GET /api/v1/provenance/{event_id}/ledger-anchor
    event_id = records[1]["event_id"]
    anchor_res = client.get(
        f"/api/v1/provenance/{event_id}/ledger-anchor",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert anchor_res.status_code == 200
    a_data = anchor_res.json()
    assert a_data["is_anchored"] is True
    assert a_data["hash_matched"] is True
