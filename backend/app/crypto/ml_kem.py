"""ML-KEM-768 Post-Quantum Key Encapsulation Mechanism (FIPS 203) using standard cryptography library."""
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import mlkem


class MLKEMService:
    """Standardized ML-KEM-768 Key Encapsulation Mechanism service.
    
    Provides:
    - FIPS 203 standard ML-KEM-768 key pair generation.
    - Public key encapsulation generating a 32-byte shared secret and 1088-byte ciphertext.
    - Private key decapsulation recovering the exact 32-byte shared secret.
    - Strict size validations.
    """

    ALGORITHM = "ML-KEM-768"
    PUBLIC_KEY_SIZE_BYTES = 1184   # FIPS 203 ML-KEM-768 public key size
    CIPHERTEXT_SIZE_BYTES = 1088   # FIPS 203 ML-KEM-768 ciphertext size
    SHARED_SECRET_SIZE_BYTES = 32  # 256-bit shared secret
    SEED_SIZE_BYTES = 64           # FIPS 203 (d, z) seeds

    @classmethod
    def generate_key_pair(cls) -> Tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
        """Generates a fresh standard ML-KEM-768 key pair."""
        priv = mlkem.MLKEM768PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub

    @classmethod
    def encapsulate(cls, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encapsulates a fresh shared secret against a recipient's ML-KEM-768 public key.
        
        Args:
            public_key_bytes: Raw 1184 bytes of the recipient's public key.
            
        Returns:
            Tuple of (shared_secret: 32 bytes, kem_ciphertext: 1088 bytes).
        """
        if len(public_key_bytes) != cls.PUBLIC_KEY_SIZE_BYTES:
            raise ValueError(
                f"ML-KEM-768 public key must be exactly {cls.PUBLIC_KEY_SIZE_BYTES} bytes. "
                f"Received {len(public_key_bytes)} bytes."
            )

        pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_key_bytes)
        shared_secret, kem_ciphertext = pub.encapsulate()

        if len(shared_secret) != cls.SHARED_SECRET_SIZE_BYTES:
            raise ValueError("KEM encapsulation produced an invalid shared secret size.")
        if len(kem_ciphertext) != cls.CIPHERTEXT_SIZE_BYTES:
            raise ValueError("KEM encapsulation produced an invalid ciphertext size.")

        return shared_secret, kem_ciphertext

    @classmethod
    def decapsulate(cls, private_key: mlkem.MLKEM768PrivateKey, kem_ciphertext: bytes) -> bytes:
        """Decapsulates the KEM ciphertext using the recipient's private key to recover the shared secret.
        
        Args:
            private_key: The recipient's MLKEM768PrivateKey instance.
            kem_ciphertext: Exactly 1088 bytes of ML-KEM-768 ciphertext.
            
        Returns:
            The recovered 32-byte shared secret.
        """
        if len(kem_ciphertext) != cls.CIPHERTEXT_SIZE_BYTES:
            raise ValueError(
                f"ML-KEM-768 ciphertext must be exactly {cls.CIPHERTEXT_SIZE_BYTES} bytes. "
                f"Received {len(kem_ciphertext)} bytes."
            )

        shared_secret = private_key.decapsulate(kem_ciphertext)
        if len(shared_secret) != cls.SHARED_SECRET_SIZE_BYTES:
            raise ValueError("KEM decapsulation failed to produce a 32-byte shared secret.")

        return shared_secret

    @classmethod
    def serialize_public_key(cls, public_key: mlkem.MLKEM768PublicKey) -> bytes:
        """Serializes public key to raw FIPS 203 bytes (1184 bytes)."""
        return public_key.public_bytes_raw()

    @classmethod
    def deserialize_public_key(cls, public_key_bytes: bytes) -> mlkem.MLKEM768PublicKey:
        """Deserializes raw bytes into an MLKEM768PublicKey instance."""
        if len(public_key_bytes) != cls.PUBLIC_KEY_SIZE_BYTES:
            raise ValueError(f"Invalid ML-KEM-768 public key length: {len(public_key_bytes)} bytes.")
        return mlkem.MLKEM768PublicKey.from_public_bytes(public_key_bytes)
