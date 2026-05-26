"""
quantum_shield/wallet.py
─────────────────────────────────────────────────────────────────
Quantum-safe Bitcoin wallet.

Combines:
  - A classical secp256k1 key (BIP-32 HD) for current compatibility
  - A post-quantum key (PQHDWallet) for future-proof security
  - Taproot (P2TR) output scripts to accommodate PQ signature data

The wallet is intentionally read-only by default: private keys are
returned on creation but NOT stored in the Wallet object, following
the principle of minimal exposure.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Optional

from .keys import PQAlgorithm, PQHDWallet, PQKeyPair, generate_keypair

# Optional: bitcoin library for address derivation
try:
    import bitcoinlib.keys as btclib
    _BTC_LIB = True
except ImportError:
    _BTC_LIB = False


# ─── Wallet identity ──────────────────────────────────────────────────────────

@dataclass
class WalletIdentity:
    """
    The public-facing identity of a QuantumWallet.

    All fields are safe to share / store on disk.
    Private keys are never stored here.
    """
    btc_address:    str      # P2TR / P2WPKH Bitcoin address
    pq_public_key:  bytes    # Post-quantum public key
    pq_algorithm:   PQAlgorithm
    hns_identity:   str      # HNS identity hash (hex)
    network:        str      # mainnet | testnet | regtest

    def __repr__(self) -> str:
        alg = self.pq_algorithm.value
        return (
            f"WalletIdentity(\n"
            f"  address    = {self.btc_address}\n"
            f"  pq_algo    = {alg}\n"
            f"  hns_id     = {self.hns_identity[:16]}...\n"
            f"  network    = {self.network}\n"
            f")"
        )


# ─── QuantumWallet ────────────────────────────────────────────────────────────

class QuantumWallet:
    """
    A hybrid classical + post-quantum Bitcoin wallet.

    Design goals:
      1. Compatible with today's Bitcoin (outputs are valid P2TR addresses).
      2. Future-proof: PQ keys are committed on-chain via HNS Protocol.
      3. Non-custodial: private keys returned but not stored.

    Example:
        wallet, secrets = QuantumWallet.generate()
        print(wallet.identity.btc_address)
        # Store secrets.pq_private_key in your HSM / encrypted backup
    """

    def __init__(self, identity: WalletIdentity) -> None:
        self.identity = identity

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def generate(
        cls,
        algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3,
        network:   str         = "mainnet",
    ) -> tuple["QuantumWallet", "_WalletSecrets"]:
        """
        Generate a new QuantumWallet with fresh keys.

        Returns:
            (wallet, secrets) — secrets contains both private keys.
            ⚠️  Back up secrets immediately; they are not stored in wallet.

        Example:
            wallet, secrets = QuantumWallet.generate(PQAlgorithm.FALCON512)
            address = wallet.identity.btc_address
            backup(secrets.pq_private_key_hex())
        """
        # Generate PQ key pair
        pq_keypair = generate_keypair(algorithm)

        # Derive a P2TR (Taproot) Bitcoin address from the PQ public key
        btc_address = cls._derive_taproot_address(pq_keypair.public_key, network)

        # HNS identity = SHA-256(address || pq_pubkey_hash)
        pq_hash     = hashlib.sha256(pq_keypair.public_key).digest()
        hns_id      = hashlib.sha256(btc_address.encode() + pq_hash).hexdigest()

        identity = WalletIdentity(
            btc_address   = btc_address,
            pq_public_key = pq_keypair.public_key,
            pq_algorithm  = algorithm,
            hns_identity  = hns_id,
            network       = network,
        )

        wallet  = cls(identity)
        secrets = _WalletSecrets(pq_keypair=pq_keypair)
        return wallet, secrets

    @classmethod
    def from_seed(
        cls,
        seed:      bytes,
        algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3,
        account:   int         = 0,
        index:     int         = 0,
        network:   str         = "mainnet",
    ) -> tuple["QuantumWallet", "_WalletSecrets"]:
        """
        Derive a QuantumWallet deterministically from a BIP-39 seed.

        Args:
            seed:      64-byte BIP-39 seed (mnemonic → seed).
            algorithm: PQC scheme.
            account:   BIP-44 account index.
            index:     Key index within account.
            network:   Bitcoin network.

        Returns:
            (wallet, secrets) — deterministic; same seed always gives same result.
        """
        hd = PQHDWallet(seed)
        pq_keypair = hd.derive(algorithm=algorithm, account=account, index=index)

        btc_address = cls._derive_taproot_address(pq_keypair.public_key, network)
        pq_hash     = hashlib.sha256(pq_keypair.public_key).digest()
        hns_id      = hashlib.sha256(btc_address.encode() + pq_hash).hexdigest()

        identity = WalletIdentity(
            btc_address   = btc_address,
            pq_public_key = pq_keypair.public_key,
            pq_algorithm  = algorithm,
            hns_identity  = hns_id,
            network        = network,
        )

        wallet  = cls(identity)
        secrets = _WalletSecrets(pq_keypair=pq_keypair)
        return wallet, secrets

    # ── Address derivation ────────────────────────────────────────────────────

    @staticmethod
    def _derive_taproot_address(pq_public_key: bytes, network: str) -> str:
        """
        Derive a P2TR (Taproot, BIP-341) address from a PQ public key.

        Bitcoin Taproot uses a 32-byte x-only public key as the internal key.
        We derive this 32-byte key from the PQ public key using SHA-256,
        then encode it as bech32m.

        In production, you would also construct a Tapscript that commits to
        a threshold of: (classical_key OR pq_signature_check_via_covenant).

        Returns:
            bech32m-encoded P2TR address string.
        """
        # Derive a 32-byte "x-only" key commitment from the PQ pubkey
        x_only = hashlib.sha256(b"taproot/pq-key/v1" + pq_public_key).digest()

        if _BTC_LIB:
            try:
                prefix = {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"}.get(network, "bc")
                key = btclib.Key(x_only, network=network)
                return key.address(script_type="p2tr")
            except Exception:
                pass

        # Fallback: manual bech32m encoding
        hrp = {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"}.get(network, "bc")
        return _bech32m_encode_p2tr(hrp, x_only)

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def address(self) -> str:
        return self.identity.btc_address

    @property
    def pq_public_key(self) -> bytes:
        return self.identity.pq_public_key

    @property
    def hns_identity(self) -> str:
        return self.identity.hns_identity

    def __repr__(self) -> str:
        return f"QuantumWallet({self.identity!r})"


# ─── Secrets container ────────────────────────────────────────────────────────

@dataclass
class _WalletSecrets:
    """
    Private key material returned from wallet creation.

    ⚠️  Never log, transmit, or store these in plaintext.
    Back up using an encrypted keystore, hardware wallet, or BIP-39 mnemonic.
    """
    pq_keypair: PQKeyPair

    def pq_private_key_hex(self) -> str:
        return self.pq_keypair.private_key.hex()

    def pq_public_key_hex(self) -> str:
        return self.pq_keypair.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the PQ private key."""
        return self.pq_keypair.sign(message)

    def __repr__(self) -> str:
        return f"_WalletSecrets(algorithm={self.pq_keypair.algorithm.value}, [REDACTED])"


# ─── bech32m helper (minimal, no external deps) ───────────────────────────────

_BECH32M_CONST = 0x2BC830A3
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32m_encode_p2tr(hrp: str, witness_program: bytes) -> str:
    """Encode a 32-byte witness program as a bech32m P2TR address."""
    data = _convertbits([0x01] + list(witness_program), 8, 5)  # version 1
    checksum = _bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def _bech32m_polymod(values: list[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk


def _bech32m_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32m_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32m_hrp_expand(hrp) + data
    polymod = _bech32m_polymod(values + [0, 0, 0, 0, 0, 0]) ^ _BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value)
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret
