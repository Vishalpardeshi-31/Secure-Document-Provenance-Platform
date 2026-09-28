"""Deterministic and canonical construction of Authenticated Additional Data (AAD) and KDF Info contexts.

Prevents ciphertext transposition, context substitution, and cut-and-paste attacks
across documents, versions, recipients, and key versions.
"""
from typing import Union


def build_document_aad(
    document_id: str,
    document_version_id: Union[str, int],
    protocol_version: str = "SDP-CRYPTO-V2",
) -> bytes:
    """Constructs the canonical AAD bound to the document ciphertext.
    
    Format:
        {protocol_version}|DOC|{document_id}|{document_version_id}
        
    Guarantees:
    - Ciphertext cannot be swapped into another document.
    - Ciphertext cannot be replayed across different document versions.
    - Protocol version is cryptographically verified before decryption succeeds.
    """
    if not document_id:
        raise ValueError("document_id must not be empty.")
    if not str(document_version_id):
        raise ValueError("document_version_id must not be empty.")
    if not protocol_version:
        raise ValueError("protocol_version must not be empty.")

    canonical = f"{protocol_version}|DOC|{document_id}|{str(document_version_id)}"
    return canonical.encode("utf-8")


def build_dek_wrap_kdf_info(
    protocol_version: str,
    document_id: str,
    document_version_id: Union[str, int],
    recipient_user_id: str,
    recipient_key_id: str,
    recipient_key_version: int,
    kdf_info_version: str = "SDP-DEK-WRAP-v1",
) -> bytes:
    """Constructs the canonical HKDF info context for deriving recipient wrapping key (KEK).
    
    Format:
        {kdf_info_version}|{protocol_version}|{document_id}|{document_version_id}|{recipient_user_id}|{recipient_key_id}|v{recipient_key_version}
        
    Guarantees:
    - Recipient KEK is strictly bound to document, version, recipient identity, and specific key version.
    - Derived KEK cannot be used or confused across different recipients or documents.
    """
    canonical = (
        f"{kdf_info_version}|{protocol_version}|{document_id}|"
        f"{str(document_version_id)}|{recipient_user_id}|{recipient_key_id}|v{recipient_key_version}"
    )
    return canonical.encode("utf-8")


def build_dek_wrap_aad(
    protocol_version: str,
    document_id: str,
    document_version_id: Union[str, int],
    recipient_user_id: str,
    recipient_key_id: str,
    recipient_key_version: int,
) -> bytes:
    """Constructs the canonical AAD for wrapping the document DEK with AES-256-GCM.
    
    Format:
        {protocol_version}|WRAP|{document_id}|{document_version_id}|{recipient_user_id}|{recipient_key_id}|v{recipient_key_version}
        
    Guarantees:
    - Wrapped DEK envelope authentication tag validates the exact document, version, and recipient context.
    - Any tampering with recipient key version or document linkage causes immediate GCM authentication failure.
    """
    canonical = (
        f"{protocol_version}|WRAP|{document_id}|"
        f"{str(document_version_id)}|{recipient_user_id}|{recipient_key_id}|v{recipient_key_version}"
    )
    return canonical.encode("utf-8")


class AADBuilder:
    """Convenience namespace exposing deterministic AAD builders."""
    build_document_aad = staticmethod(build_document_aad)
    build_dek_wrap_kdf_info = staticmethod(build_dek_wrap_kdf_info)
    build_dek_wrap_aad = staticmethod(build_dek_wrap_aad)
