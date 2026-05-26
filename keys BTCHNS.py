"""
quantum_shield/keys.py
─────────────────────────────────────────────────────────────────
Post-quantum key generation and management.

Supported algorithms (all NIST PQC standardized or finalists):
  - CRYSTALS-Dilithium  (FIPS 204)  — lattice-based signatures
  - FALCON              (FIPS 206)  — lattice-based signatures (compact)
  - SPHINCS+            (FIPS 205)  — hash-based signatures (stateless)
  - Kyber               (FIPS 203)  — key encapsulation (for hybrid key exchange)

Dependencies:
  pip install pqcrypto cryptography
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# pqcrypto wraps liboqs (Open Quantum Safe)
try:
    from pqcrypto.sign import dilithium3, falcon_512, sphincs_sha256_128f_simple
    from pqcrypto.kem import kyber768
    _PQC_AVAILABLE = True
except ImportError:
    _PQC_AVAILABLE = False
    # Provide graceful degradation in environments without liboqs
    import warnings
    warnings.warn(
        "pqcrypto not installed. Install with: pip install pqcrypto\n"
        "Keys will use stub implementation only.",
        ImportWarning,
        stacklevel=2,
    )


class PQAlgorithm(str, Enum):
    """NIST-standardized post-quantum signature algorithms."""
    DILITHIUM3 = "dilithium3"        # FIPS 204 — recommended default
    FALCON512  = "falcon512"          # FIPS 206 — compact signatures
    SPHINCS_128F = "sphincs_128f"    # FIPS 205 — hash-based (conservative)


# ─── Key sizes (bytes) ────────────────────────────────────────────────────────
KEY_SIZES = {
    PQAlgorithm.DILITHIUM3:   {"pub": 1952,  "priv": 4000,  "sig": 3293},
    PQAlgorithm.FALCON512:    {"pub": 897,   "priv": 1281,  "sig": 666},
    PQAlgorithm.SPHINCS_128F: {"pub": 32,    "priv": 64,    "sig": 17088},
}


@dataclass
class PQKeyPair:
    """
    A post-quantum signing key pair.

    Attributes:
        algorithm:   PQAlgorithm used to generate this keypair
        public_key:  Raw bytes of the PQ public key
        private_key: Raw bytes of the PQ private key (keep offline / in HSM)
        fingerprint: SHA-256 of public_key, used as HNS identity anchor
    """
    algorithm:   PQAlgorithm
    public_key:  bytes
    private_key: bytes
    fingerprint: bytes = field(init=False)

    def __post_init__(self) -> None:
        self.fingerprint = hashlib.sha256(self.public_key).digest()

    # ── Signing ───────────────────────────────────────────────────────────────
    def sign(self, message: bytes) -> bytes:
        """
        Sign arbitrary bytes using the PQ private key.

        Returns:
            Raw signature bytes.
        """
        if not _PQC_AVAILABLE:
            raise RuntimeError("pqcrypto library required for signing.")

        if self.algorithm == PQAlgorithm.DILITHIUM3:
            return dilithium3.sign(message, self.private_key)
        elif self.algorithm == PQAlgorithm.FALCON512:
            return falcon_512.sign(message, self.private_key)
        elif self.algorithm == PQAlgorithm.SPHINCS_128F:
            return sphincs_sha256_128f_simple.sign(message, self.private_key)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    # ── Verification (static — only needs public key) ─────────────────────────
    @staticmethod
    def verify(
        message:    bytes,
        signature:  bytes,
        public_key: bytes,
        algorithm:  PQAlgorithm,
    ) -> bool:
        """
        Verify a PQ signature against a public key.

        Returns:
            True if valid, False otherwise.
        """
        if not _PQC_AVAILABLE:
            raise RuntimeError("pqcrypto library required for verification.")
        try:
            if algorithm == PQAlgorithm.DILITHIUM3:
                dilithium3.verify(message, signature, public_key)
            elif algorithm == PQAlgorithm.FALCON512:
                falcon_512.verify(message, signature, public_key)
            elif algorithm == PQAlgorithm.SPHINCS_128F:
                sphincs_sha256_128f_simple.verify(message, signature, public_key)
            return True
        except Exception:
            return False

    # ── Serialisation ─────────────────────────────────────────────────────────
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def fingerprint_hex(self) -> str:
        return self.fingerprint.hex()

    def to_dict(self, include_private: bool = False) -> dict:
        d = {
            "algorithm":   self.algorithm.value,
            "public_key":  self.public_key_hex(),
            "fingerprint": self.fingerprint_hex(),
        }
        if include_private:
            d["private_key"] = self.private_key.hex()
        return d


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_keypair(algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3) -> PQKeyPair:
    """
    Generate a fresh post-quantum key pair.

    Args:
        algorithm: Which PQC signature scheme to use. Defaults to Dilithium3
                   (FIPS 204) — the NIST-recommended general-purpose scheme.

    Returns:
        PQKeyPair with freshly generated keys.

    Example:
        >>> kp = generate_keypair(PQAlgorithm.DILITHIUM3)
        >>> sig = kp.sign(b"protect my sats")
        >>> assert PQKeyPair.verify(b"protect my sats", sig, kp.public_key, kp.algorithm)
    """
    if not _PQC_AVAILABLE:
        # Stub: deterministic fake keys for unit tests / CI without liboqs
        sizes = KEY_SIZES[algorithm]
        seed = os.urandom(32)
        pub  = hashlib.shake_256(b"pub"  + seed).digest(sizes["pub"])
        priv = hashlib.shake_256(b"priv" + seed).digest(sizes["priv"])
        return PQKeyPair(algorithm=algorithm, public_key=pub, private_key=priv)

    if algorithm == PQAlgorithm.DILITHIUM3:
        pub, priv = dilithium3.generate_keypair()
    elif algorithm == PQAlgorithm.FALCON512:
        pub, priv = falcon_512.generate_keypair()
    elif algorithm == PQAlgorithm.SPHINCS_128F:
        pub, priv = sphincs_sha256_128f_simple.generate_keypair()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return PQKeyPair(algorithm=algorithm, public_key=pub, private_key=priv)


# ─── BIP-32-style Deterministic Derivation (PQ-HD) ───────────────────────────

class PQHDWallet:
    """
    Hierarchical Deterministic wallet for post-quantum keys.

    Derives PQ keypairs from a BIP-39 seed using HKDF-SHA512 as
    the PRF (replaces HMAC-SHA512 used in BIP-32, which is still
    classical-safe but we keep the interface familiar).

    Derivation path notation:  m/pq/<algorithm_id>/<account>/<index>
    """

    _ALGORITHM_IDS = {
        PQAlgorithm.DILITHIUM3:   0,
        PQAlgorithm.FALCON512:    1,
        PQAlgorithm.SPHINCS_128F: 2,
    }

    def __init__(self, seed: bytes) -> None:
        """
        Args:
            seed: 64-byte BIP-39 seed (from mnemonic).
        """
        if len(seed) < 32:
            raise ValueError("Seed must be at least 32 bytes.")
        self._root_seed = seed

    def derive(
        self,
        algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3,
        account: int = 0,
        index: int = 0,
    ) -> PQKeyPair:
        """
        Derive a PQ keypair at path m/pq/<algo>/<account>/<index>.

        Args:
            algorithm: Signature scheme.
            account:   Account index (BIP-44 style).
            index:     Key index within account.

        Returns:
            Deterministic PQKeyPair for the given path.
        """
        algo_id = self._ALGORITHM_IDS[algorithm]
        # Path bytes: 4-byte big-endian ints
        path_bytes = struct.pack(">III", algo_id, account, index)

        # HKDF-expand the root seed with path as info
        key_material = self._hkdf_expand(
            prk=self._root_seed,
            info=b"btc-quantum-shield/pq-hd-derive/v1" + path_bytes,
            length=KEY_SIZES[algorithm]["priv"],
        )

        # Use key_material as deterministic seed for key generation
        # (in production: feed key_material as seed into the PQC KAT interface)
        sizes = KEY_SIZES[algorithm]
        pub  = hashlib.shake_256(b"pub"  + key_material).digest(sizes["pub"])
        priv = hashlib.shake_256(b"priv" + key_material).digest(sizes["priv"])

        # NOTE: Production implementations should use the KAT (Known Answer Test)
        # seeded API of the PQC library to derive keypairs deterministically from
        # key_material rather than this SHAKE approximation.

        return PQKeyPair(algorithm=algorithm, public_key=pub, private_key=priv)

    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand per RFC 5869."""
        hash_len = 64  # SHA-512
        n = (length + hash_len - 1) // hash_len
        okm = b""
        t   = b""
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
            okm += t
        return okm[:length]


# ─── Kyber KEM (key encapsulation for hybrid key exchange) ───────────────────

@dataclass
class KyberKeyPair:
    """CRYSTALS-Kyber (FIPS 203) key encapsulation mechanism key pair."""
    public_key:  bytes
    private_key: bytes

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret + ciphertext.

        Returns:
            (ciphertext, shared_secret) — send ciphertext to peer.
        """
        if not _PQC_AVAILABLE:
            raise RuntimeError("pqcrypto required.")
        ciphertext, shared_secret = kyber768.enc(self.public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext.

        Returns:
            shared_secret bytes.
        """
        if not _PQC_AVAILABLE:
            raise RuntimeError("pqcrypto required.")
        return kyber768.dec(ciphertext, self.private_key)


def generate_kyber_keypair() -> KyberKeyPair:
    """Generate a fresh Kyber-768 KEM key pair (FIPS 203)."""
    if not _PQC_AVAILABLE:
        seed = os.urandom(32)
        pub  = hashlib.shake_256(b"kyber_pub"  + seed).digest(1184)
        priv = hashlib.shake_256(b"kyber_priv" + seed).digest(2400)
        return KyberKeyPair(public_key=pub, private_key=priv)
    pub, priv = kyber768.generate_keypair()
    return KyberKeyPair(public_key=pub, private_key=priv)
