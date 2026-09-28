"""In-memory tamper-evident ledger adapter for isolated test suites."""
import hashlib
import json
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from app.ledger.interface import LedgerAdapter, LedgerTransactionResult, LedgerVerificationResult


class InMemoryLedgerAdapter(LedgerAdapter):
    """In-memory ledger adapter for high-speed testing."""

    def __init__(self):
        self._lock = threading.Lock()
        self._chains: Dict[str, List[Dict[str, Any]]] = {}
        self._tx_index: Dict[str, Dict[str, Any]] = {}
        self.should_fail = False

    def clear(self):
        with self._lock:
            self._chains.clear()
            self._tx_index.clear()
            self.should_fail = False

    def append_record(self, record_payload: Dict[str, Any]) -> LedgerTransactionResult:
        with self._lock:
            if self.should_fail:
                raise RuntimeError("Simulated permissioned ledger network outage.")

            chain_id = str(record_payload.get("chain_id", "PLATFORM-PROVENANCE-CHAIN"))
            chain_sequence = int(record_payload["chain_sequence"])
            chain_hash = str(record_payload["chain_hash"])
            event_id = str(record_payload["event_id"])

            tx_id = f"TX-MEM-{chain_sequence:08d}-{chain_hash[:16].upper()}"

            # Idempotency
            if tx_id in self._tx_index:
                entry = self._tx_index[tx_id]
                return LedgerTransactionResult(
                    transaction_id=tx_id,
                    chain_id=chain_id,
                    chain_sequence=chain_sequence,
                    chain_hash=chain_hash,
                    status="CONFIRMED",
                    block_or_record_number=entry["block_number"],
                    anchored_at=entry["anchored_at"],
                    ledger_entry_hash=entry["ledger_entry_hash"],
                )

            if chain_id not in self._chains:
                self._chains[chain_id] = []

            now_iso = datetime.now(timezone.utc).isoformat()
            entry_data = {
                "transaction_id": tx_id,
                "chain_id": chain_id,
                "chain_sequence": chain_sequence,
                "event_id": event_id,
                "document_id": str(record_payload.get("document_id") or ""),
                "document_version_id": str(record_payload.get("document_version_id") or ""),
                "canonical_record_hash": str(record_payload.get("canonical_record_hash") or ""),
                "previous_record_hash": str(record_payload.get("previous_record_hash") or ""),
                "chain_hash": chain_hash,
                "signature_algorithm": str(record_payload.get("signature_algorithm") or "ML-DSA-65"),
                "signature_key_version": int(record_payload.get("signature_key_version") or 1),
                "signature": str(record_payload.get("signature") or ""),
                "event_timestamp": str(record_payload.get("event_timestamp") or now_iso),
                "anchored_at": now_iso,
                "block_number": len(self._chains[chain_id]) + 1,
            }

            canonical_json = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
            entry_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().lower()
            entry_data["ledger_entry_hash"] = entry_hash

            self._chains[chain_id].append(entry_data)
            self._tx_index[tx_id] = entry_data

            return LedgerTransactionResult(
                transaction_id=tx_id,
                chain_id=chain_id,
                chain_sequence=chain_sequence,
                chain_hash=chain_hash,
                status="CONFIRMED",
                block_or_record_number=entry_data["block_number"],
                anchored_at=now_iso,
                ledger_entry_hash=entry_hash,
            )

    def get_record(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._tx_index.get(transaction_id)

    def verify_record(self, transaction_id: str, expected_chain_hash: str) -> LedgerVerificationResult:
        entry = self.get_record(transaction_id)
        if not entry:
            return LedgerVerificationResult(
                is_anchored=False,
                transaction_id=transaction_id,
                expected_chain_hash=expected_chain_hash,
                ledger_chain_hash=None,
                hash_matched=False,
                status="NOT_FOUND",
                details="Transaction not found in in-memory ledger.",
            )

        stored_hash = entry.get("chain_hash", "")
        hash_matched = (stored_hash == expected_chain_hash)
        return LedgerVerificationResult(
            is_anchored=True,
            transaction_id=transaction_id,
            expected_chain_hash=expected_chain_hash,
            ledger_chain_hash=stored_hash,
            hash_matched=hash_matched,
            status="CONFIRMED" if hash_matched else "MISMATCH",
            details="Anchor verified." if hash_matched else "Hash mismatch.",
            anchored_at=entry.get("anchored_at"),
        )

    def get_chain_head(self, chain_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            records = self._chains.get(chain_id, [])
            return records[-1] if records else None
