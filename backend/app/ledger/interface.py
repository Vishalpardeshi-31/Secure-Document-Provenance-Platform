"""Abstract interface for the tamper-evident permissioned ledger subsystem."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class LedgerTransactionResult(BaseModel):
    """Result returned by the ledger adapter upon successfully appending a record."""
    transaction_id: str = Field(description="Unique deterministic or ledger-assigned transaction identifier")
    chain_id: str
    chain_sequence: int
    chain_hash: str
    status: str = Field(default="CONFIRMED", description="CONFIRMED, PENDING, or FAILED")
    block_or_record_number: int
    anchored_at: str
    ledger_entry_hash: str
    proof: Optional[Dict[str, Any]] = None


class LedgerVerificationResult(BaseModel):
    """Result returned when verifying a provenance record's anchor against the ledger."""
    is_anchored: bool
    transaction_id: str
    expected_chain_hash: str
    ledger_chain_hash: Optional[str] = None
    hash_matched: bool
    status: str  # CONFIRMED, FAILED, MISMATCH, NOT_FOUND
    details: Optional[str] = None
    anchored_at: Optional[str] = None


class LedgerAdapter(ABC):
    """Abstract base class for all ledger integrations.
    
    Security Guarantee:
    - Never stores plaintext documents, DEKs, or private keys.
    - Stores only cryptographically signed provenance metadata and hashes.
    - Write-once append-only semantics.
    """

    @abstractmethod
    def append_record(self, record_payload: Dict[str, Any]) -> LedgerTransactionResult:
        """Appends a tamper-evident provenance record to the permissioned ledger.
        
        Raises:
            Exception: If ledger append fails.
        """
        pass

    @abstractmethod
    def get_record(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a stored ledger entry by its transaction identifier."""
        pass

    @abstractmethod
    def verify_record(self, transaction_id: str, expected_chain_hash: str) -> LedgerVerificationResult:
        """Verifies that the ledger entry exists, is intact, and matches the expected chain hash."""
        pass

    @abstractmethod
    def get_chain_head(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest chain head known to the ledger."""
        pass
