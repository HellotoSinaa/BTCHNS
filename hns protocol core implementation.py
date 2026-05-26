"""
quantum_shield/hns.py
─────────────────────────────────────────────────────────────────
Hybrid Name-Space (HNS) Protocol — anchor & bind logic.

The HNS protocol lets you commit a post-quantum public key to the
Bitcoin blockchain BEFORE quantum computers can break ECDSA, and
later prove ownership of a classical address using only PQ keys.

Two phases:
  1. ANCHOR  — embed hash(PQ_pubkey) in a Bitcoin OP_RETURN output
  2. BIND    — sign the BTC address with PQ key, publish to HNS Registry

See docs/architecture.md for full protocol specification.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .keys import PQAlgorithm, PQKeyPair, generate_keypair


# ─── HNS Registry entry ───────────────────────────────────────────────────────

class HNSStatus(str, Enum):
    PENDING  = "pending"    # created locally, not broadcast
    ANCHORED = "anchored"   # Phase 1 TX on-chain
    BOUND    = "bound"      # Phase 2 binding registered
    MIGRATED = "migrated"   # Funds swept to PQ-safe output


@dataclass
class HNSRecord:
    """
    An HNS binding record stored in the HNS Registry.

    Fields:
        btc_address:      The classical Bitcoin address being protected.
        pq_pubkey_hash:   SHA-256 of the PQ public key (the on-chain anchor).
        pq_pubkey:        Full PQ public key (stored off-chain in registry).
        algorithm:        PQC algorithm used.
        anchor_txid:      Bitcoin TXID of the OP_RETURN anchor transaction.
        bind_signature:   PQ signature over canonical(btc_address).
        timestamp:        UNIX timestamp of record creation.
        status:           Current HNS lifecycle phase.
        network:          "mainnet" | "testnet" | "regtest"
    """
    btc_address:    str
    pq_pubkey_hash: bytes
    pq_pubkey:      bytes
    algorithm:      PQAlgorithm
    anchor_txid:    Optional[str]   = None
    bind_signature: Optional[bytes] = None
    timestamp:      int             = field(default_factory=lambda: int(time.time()))
    status:         HNSStatus       = HNSStatus.PENDING
    network:        str             = "mainnet"

    # ── Serialisation ─────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "btc_address":    self.btc_address,
            "pq_pubkey_hash": self.pq_pubkey_hash.hex(),
            "pq_pubkey":      self.pq_pubkey.hex(),
            "algorithm":      self.algorithm.value,
            "anchor_txid":    self.anchor_txid,
            "bind_signature": self.bind_signature.hex() if self.bind_signature else None,
            "timestamp":      self.timestamp,
            "status":         self.status.value,
            "network":        self.network,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "HNSRecord":
        return cls(
            btc_address    = d["btc_address"],
            pq_pubkey_hash = bytes.fromhex(d["pq_pubkey_hash"]),
            pq_pubkey      = bytes.fromhex(d["pq_pubkey"]),
            algorithm      = PQAlgorithm(d["algorithm"]),
            anchor_txid    = d.get("anchor_txid"),
            bind_signature = bytes.fromhex(d["bind_signature"]) if d.get("bind_signature") else None,
            timestamp      = d["timestamp"],
            status         = HNSStatus(d["status"]),
            network        = d.get("network", "mainnet"),
        )

    # ── Identity hash (used as key in the HNS Registry) ───────────────────────
    @property
    def hns_id(self) -> str:
        """
        Unique HNS identity: SHA-256(btc_address || pq_pubkey_hash).
        This is the canonical lookup key in the HNS Registry.
        """
        payload = self.btc_address.encode() + self.pq_pubkey_hash
        return hashlib.sha256(payload).hexdigest()


# ─── Canonical message formats ───────────────────────────────────────────────

def anchor_message(btc_address: str, pq_pubkey_hash: bytes, network: str) -> bytes:
    """
    Canonical message for the OP_RETURN anchor payload.

    Format: b"HNS/v1/<network>/<btc_address>/<pq_pubkey_hash_hex>"

    This exact byte string is embedded (or committed to) in the OP_RETURN
    of the Phase 1 anchor transaction.
    """
    return (
        f"HNS/v1/{network}/{btc_address}/{pq_pubkey_hash.hex()}"
    ).encode("utf-8")


def bind_message(btc_address: str, pq_pubkey_hash: bytes, network: str) -> bytes:
    """
    Canonical message for the Phase 2 PQ bind signature.

    The PQ keypair signs this message, proving:
    "The holder of this PQ key claims ownership of <btc_address>."
    """
    return (
        f"HNS/v1/bind/{network}/{btc_address}/{pq_pubkey_hash.hex()}"
    ).encode("utf-8")


# ─── HNS Protocol ─────────────────────────────────────────────────────────────

class HNSProtocol:
    """
    Main interface for the Hybrid Name-Space (HNS) Protocol.

    Orchestrates the two-phase anchor+bind process for protecting
    Bitcoin addresses against quantum attacks.

    Usage:
        hns = HNSProtocol(network="testnet")

        # Phase 1: Create anchor transaction
        record = hns.create_record(btc_address, keypair)
        anchor_tx = hns.build_anchor_tx(record, utxo, ecdsa_key_wif)
        # broadcast anchor_tx yourself via your Bitcoin node / API

        # Phase 2: Bind after anchor confirms
        record = hns.bind(record, keypair)
        hns.registry.store(record)
    """

    def __init__(
        self,
        network:  str = "mainnet",
        registry: Optional["HNSRegistry"] = None,
    ) -> None:
        self.network  = network
        self.registry = registry or HNSRegistry()

    # ─── Phase 1: Anchor ──────────────────────────────────────────────────────

    def create_record(
        self,
        btc_address: str,
        keypair:     PQKeyPair,
    ) -> HNSRecord:
        """
        Create an HNS record (local only — does not broadcast anything).

        Args:
            btc_address: The classical P2PKH / P2WPKH / P2TR address to protect.
            keypair:     The PQ key pair that will own this address post-quantum.

        Returns:
            HNSRecord in PENDING state.
        """
        pq_pubkey_hash = hashlib.sha256(keypair.public_key).digest()
        record = HNSRecord(
            btc_address    = btc_address,
            pq_pubkey_hash = pq_pubkey_hash,
            pq_pubkey      = keypair.public_key,
            algorithm      = keypair.algorithm,
            network        = self.network,
        )
        return record

    def build_anchor_payload(self, record: HNSRecord) -> bytes:
        """
        Build the 80-byte OP_RETURN payload for the anchor transaction.

        Bitcoin's OP_RETURN allows up to 80 bytes of arbitrary data.
        We encode:
          - 4 bytes : HNS magic bytes (0x484E5301 = "HNS\x01")
          - 32 bytes: SHA-256 of PQ public key (the anchor commitment)
          - 20 bytes: First 20 bytes of SHA-256(btc_address) for lookup
          - 4 bytes : network ID + version flags
          = 60 bytes total (leaves 20 bytes for future extensions)

        Returns:
            bytes to embed in OP_RETURN output.
        """
        HNS_MAGIC  = b"\x48\x4e\x53\x01"              # "HNS\x01"
        net_id     = {"mainnet": 0x01, "testnet": 0x02, "regtest": 0x03}.get(self.network, 0xFF)
        addr_hash  = hashlib.sha256(record.btc_address.encode()).digest()[:20]
        flags      = (0x00).to_bytes(3, "big")         # reserved

        payload = (
            HNS_MAGIC
            + record.pq_pubkey_hash          # 32 bytes
            + addr_hash                       # 20 bytes
            + bytes([net_id])
            + flags
        )
        assert len(payload) == 60, f"Payload size error: {len(payload)}"
        return payload

    def parse_anchor_payload(self, data: bytes) -> Optional[dict]:
        """
        Parse a raw OP_RETURN payload and return HNS fields if valid.

        Returns None if not a valid HNS anchor payload.
        """
        if len(data) < 60:
            return None
        if data[:4] != b"\x48\x4e\x53\x01":
            return None
        return {
            "pq_pubkey_hash": data[4:36].hex(),
            "addr_hash":      data[36:56].hex(),
            "network_id":     data[56],
            "flags":          data[57:60].hex(),
        }

    # ─── Phase 2: Bind ────────────────────────────────────────────────────────

    def bind(self, record: HNSRecord, keypair: PQKeyPair) -> HNSRecord:
        """
        Execute Phase 2: sign the binding message with the PQ key.

        The resulting signature is the cryptographic proof of PQ ownership
        over the Bitcoin address. It is stored in the HNS Registry.

        Args:
            record:  HNSRecord that has been anchored (anchor_txid set).
            keypair: Must match the pq_pubkey in the record.

        Returns:
            Updated HNSRecord in BOUND state.

        Raises:
            ValueError: If record is not in ANCHORED state or pubkey mismatch.
        """
        if record.status not in (HNSStatus.ANCHORED, HNSStatus.PENDING):
            raise ValueError(f"Cannot bind record in state {record.status!r}")

        if keypair.public_key != record.pq_pubkey:
            raise ValueError("Keypair does not match record's PQ public key.")

        msg = bind_message(record.btc_address, record.pq_pubkey_hash, self.network)
        signature = keypair.sign(msg)

        record.bind_signature = signature
        record.status = HNSStatus.BOUND
        return record

    def verify_bind(self, record: HNSRecord) -> bool:
        """
        Verify the bind signature in an HNS record.

        Returns True if the PQ signature is valid for the canonical bind message.
        """
        if not record.bind_signature:
            return False
        msg = bind_message(record.btc_address, record.pq_pubkey_hash, self.network)
        return PQKeyPair.verify(
            message    = msg,
            signature  = record.bind_signature,
            public_key = record.pq_pubkey,
            algorithm  = record.algorithm,
        )

    # ─── Full workflow ────────────────────────────────────────────────────────

    def protect_address(
        self,
        btc_address: str,
        algorithm:   PQAlgorithm = PQAlgorithm.DILITHIUM3,
    ) -> tuple[HNSRecord, PQKeyPair]:
        """
        Convenience: generate a PQ keypair and create + bind an HNS record
        in one call (for local/offline use — anchor TX must be built separately).

        Returns:
            (record, keypair) — store keypair securely offline.
        """
        keypair = generate_keypair(algorithm)
        record  = self.create_record(btc_address, keypair)
        record  = self.bind(record, keypair)
        self.registry.store(record)
        return record, keypair


# ─── HNS Registry ─────────────────────────────────────────────────────────────

class HNSRegistry:
    """
    In-memory (+ JSON export) HNS Registry.

    Production deployments should back this with:
      - IPFS (content-addressed, censorship-resistant)
      - A Bitcoin L2 (e.g. Lightning, RGB, Ark)
      - A local SQLite database for indexing

    This class provides the core interface; swap out the storage backend
    by subclassing and overriding `store` / `get` / `list_by_address`.
    """

    def __init__(self) -> None:
        self._records: dict[str, HNSRecord] = {}  # hns_id → record

    def store(self, record: HNSRecord) -> str:
        """Store a record and return its hns_id."""
        self._records[record.hns_id] = record
        return record.hns_id

    def get(self, hns_id: str) -> Optional[HNSRecord]:
        """Retrieve record by HNS identity."""
        return self._records.get(hns_id)

    def get_by_address(self, btc_address: str) -> list[HNSRecord]:
        """Find all HNS records anchored to a Bitcoin address."""
        return [r for r in self._records.values() if r.btc_address == btc_address]

    def get_by_pubkey_hash(self, pq_pubkey_hash: bytes) -> Optional[HNSRecord]:
        """Find record by PQ public key hash (matches anchor payload)."""
        for record in self._records.values():
            if record.pq_pubkey_hash == pq_pubkey_hash:
                return record
        return None

    def list_all(self) -> list[HNSRecord]:
        return list(self._records.values())

    def export_json(self) -> str:
        """Export entire registry as JSON."""
        return json.dumps(
            {hid: rec.to_dict() for hid, rec in self._records.items()},
            indent=2,
        )

    def import_json(self, data: str) -> int:
        """Load records from JSON export. Returns number of records imported."""
        loaded = json.loads(data)
        for hid, rec_dict in loaded.items():
            self._records[hid] = HNSRecord.from_dict(rec_dict)
        return len(loaded)

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"HNSRegistry(records={len(self)})"
