"""Ledger orchestration service managing adapter dispatch and outbox processing."""
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.ledger.interface import LedgerAdapter, LedgerTransactionResult, LedgerVerificationResult
from app.ledger.adapters.tamper_evident_file import TamperEvidentFileLedgerAdapter
from app.ledger.adapters.in_memory import InMemoryLedgerAdapter
from app.provenance.models import LedgerOutbox, ProvenanceRecord
from app.config.settings import settings

logger = logging.getLogger("secure_document_platform.ledger")


class LedgerService:
    """High-level service coordinating append-only ledger anchoring and outbox processing."""

    _adapter_instance: Optional[LedgerAdapter] = None

    @classmethod
    def get_adapter(cls) -> LedgerAdapter:
        """Retrieves or initializes the configured LedgerAdapter instance."""
        if cls._adapter_instance is None:
            adapter_type = getattr(settings, "LEDGER_ADAPTER_TYPE", "tamper_evident_file")
            if adapter_type == "in_memory":
                cls._adapter_instance = InMemoryLedgerAdapter()
            else:
                storage_path = getattr(settings, "LEDGER_STORAGE_PATH", "./storage/ledger")
                cls._adapter_instance = TamperEvidentFileLedgerAdapter(storage_dir=storage_path)
        return cls._adapter_instance

    @classmethod
    def set_adapter(cls, adapter: LedgerAdapter) -> None:
        """Explicitly sets the active ledger adapter (useful for testing and failover)."""
        cls._adapter_instance = adapter

    @classmethod
    def anchor_record(cls, record_payload: Dict[str, Any]) -> LedgerTransactionResult:
        """Directly submits a provenance record payload to the ledger adapter."""
        adapter = cls.get_adapter()
        return adapter.append_record(record_payload)

    @classmethod
    def verify_anchor(cls, transaction_id: str, expected_chain_hash: str) -> LedgerVerificationResult:
        """Queries the ledger adapter to verify cryptographic integrity of a recorded anchor."""
        adapter = cls.get_adapter()
        return adapter.verify_record(transaction_id=transaction_id, expected_chain_hash=expected_chain_hash)

    @classmethod
    def enqueue_outbox(
        cls,
        db: Session,
        event_id: str,
        chain_id: str,
        chain_sequence: int,
        chain_hash: str,
        payload_data: Dict[str, Any],
    ) -> LedgerOutbox:
        """Enqueues a provenance event for reliable ledger anchoring via transactional outbox."""
        outbox_entry = LedgerOutbox(
            event_id=event_id,
            chain_id=chain_id,
            chain_sequence=chain_sequence,
            chain_hash=chain_hash,
            payload_json=json.dumps(payload_data, sort_keys=True),
            status="PENDING",
            attempt_count=0,
            max_retries=5,
            created_at=datetime.now(timezone.utc),
        )
        db.add(outbox_entry)
        db.flush()
        return outbox_entry

    @classmethod
    def process_outbox(cls, db: Session, max_items: int = 50) -> Dict[str, int]:
        """Idempotently processes pending outbox entries, submitting each to the ledger adapter."""
        pending_items = (
            db.query(LedgerOutbox)
            .filter(LedgerOutbox.status.in_(["PENDING", "SUBMITTED"]))
            .filter(LedgerOutbox.attempt_count < LedgerOutbox.max_retries)
            .order_by(LedgerOutbox.chain_sequence.asc())
            .limit(max_items)
            .all()
        )

        results = {"processed": 0, "confirmed": 0, "failed": 0}
        now = datetime.now(timezone.utc)

        for item in pending_items:
            results["processed"] += 1
            item.attempt_count += 1
            item.last_attempt_at = now

            try:
                payload = json.loads(item.payload_json)
                tx_result = cls.anchor_record(payload)

                # Update outbox
                item.status = "CONFIRMED"
                item.last_error = None

                # Update associated ProvenanceRecord
                rec = db.query(ProvenanceRecord).filter(ProvenanceRecord.event_id == item.event_id).first()
                if rec:
                    rec.ledger_transaction_id = tx_result.transaction_id
                    rec.ledger_status = "CONFIRMED"
                    rec.ledger_record_hash = tx_result.chain_hash
                    rec.ledger_anchored_at = now

                results["confirmed"] += 1

            except Exception as exc:
                logger.error(
                    "Ledger outbox processing failed for event %s (attempt %d): %s",
                    item.event_id,
                    item.attempt_count,
                    exc,
                )
                item.last_error = str(exc)
                if item.attempt_count >= item.max_retries:
                    item.status = "FAILED"
                    rec = db.query(ProvenanceRecord).filter(ProvenanceRecord.event_id == item.event_id).first()
                    if rec:
                        rec.ledger_status = "FAILED"
                results["failed"] += 1

        db.commit()
        return results
