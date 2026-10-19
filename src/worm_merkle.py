"""
Journal Immuable WORM (Write-Once-Read-Many) & Arbre de Merkle avec Sceau ISV.

Amélioration majeure (Branche supela-2026-epsilon-level4-prep) :
- ZÉRO CLÉ SECRÈTE EN DUR DANS LE CODE SOURCE.
  Si aucune clé n'est injectée via le constructeur ou la variable d'environnement
  `SUPELA_ISV_SECRET_KEY`, le registre génère une clé CSPRNG éphémère de 256 bits
  (`secrets.token_bytes(32)`) en mémoire vive et expose uniquement son empreinte publique
  irréversible `key_fingerprint_sha256`.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class WormEntry:
    """Entrée scellée et immuable du journal WORM Supela."""

    index: int
    timestamp_utc: str
    root_anchor: str
    parent_hash: str
    module_id: str
    event_type: str
    payload: Dict[str, Any]
    isv_seal: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp_utc": self.timestamp_utc,
            "root_anchor": self.root_anchor,
            "parent_hash": self.parent_hash,
            "module_id": self.module_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "isv_seal": self.isv_seal,
            "entry_hash": self.entry_hash,
        }


def compute_cryptographic_commitment(
    witness_secret: str, proposal_id: str, parent_hash: str
) -> Tuple[str, str]:
    """
    Génère un couple (public_commitment, verification_proof) par hachage SHA-256
    (conservé pour rétrocompatibilité, complété par `src/schnorr_zkp.py` pour le vrai NIZK 2048 bits).
    """
    witness_hash = hashlib.sha256(witness_secret.encode("utf-8")).hexdigest()
    commitment_raw = f"COMMIT|{proposal_id}|{parent_hash}|{witness_hash}".encode("utf-8")
    public_commitment = f"sha256:{hashlib.sha256(commitment_raw).hexdigest()}"
    proof_token = f"zkp-snark:sha256-commit:{witness_hash}"
    return public_commitment, proof_token


def verify_cryptographic_commitment(
    proof_token: str,
    expected_commitment: str,
    proposal_id: str,
    parent_hash: str,
) -> bool:
    prefix = "zkp-snark:sha256-commit:"
    if not isinstance(proof_token, str) or not proof_token.startswith(prefix):
        return False
    witness_hash = proof_token[len(prefix) :]
    if len(witness_hash) != 64:
        return False
    recomputed_raw = f"COMMIT|{proposal_id}|{parent_hash}|{witness_hash}".encode("utf-8")
    recomputed_commitment = f"sha256:{hashlib.sha256(recomputed_raw).hexdigest()}"
    return hmac.compare_digest(recomputed_commitment, expected_commitment)


class SupelaWormLedger:
    """
    Journal append-only scellé par chaîne de hachage SHA-256 et sceau HMAC-ISV
    sans aucune clé secrète codée en dur dans le dépôt.
    """

    GENESIS_ANCHOR = "SUP-0"
    GENESIS_SEED = b"SUPELA-K3-OMEGA-GENESIS-ROOT-SUP-0"

    def __init__(self, isv_secret_key: Optional[bytes] = None) -> None:
        if isv_secret_key is not None:
            resolved_key = bytes(isv_secret_key)
            self._key_origin = "EXPLICIT_INJECTED_KEY"
        elif os.environ.get("SUPELA_ISV_SECRET_KEY"):
            resolved_key = os.environ["SUPELA_ISV_SECRET_KEY"].encode("utf-8")
            self._key_origin = "ENV_SUPELA_ISV_SECRET_KEY"
        else:
            resolved_key = secrets.token_bytes(32)
            self._key_origin = "CSPRNG_EPHEMERAL_256BIT_KEY"

        if len(resolved_key) < 16:
            raise ValueError("La clé secrète HMAC-ISV doit faire au moins 16 octets.")

        self._isv_secret = resolved_key
        self._key_fingerprint = (
            f"sha256:{hashlib.sha256(b'SUPELA-KEY-FP|' + self._isv_secret).hexdigest()}"
        )
        self._entries: List[WormEntry] = []
        self._initialize_genesis()

    @property
    def key_fingerprint_sha256(self) -> str:
        """Empreinte publique irréversible de la clé HMAC active (n'expose jamais la clé)."""
        return self._key_fingerprint

    @property
    def key_origin(self) -> str:
        return self._key_origin

    def _initialize_genesis(self) -> None:
        genesis_hash = f"sha256:{hashlib.sha256(self.GENESIS_SEED).hexdigest()}"
        genesis_payload = {
            "axiom": "We know certain things. We ignore certain things. We know which ones.",
            "mode": "CONTRACTIVE_NORMATIVE_EAAS",
            "status": "SEALED",
            "key_fingerprint": self._key_fingerprint,
        }
        seal = self._compute_isv_seal(
            0, genesis_hash, "GENESIS_SEAL", genesis_payload, self._isv_secret
        )
        entry_hash = self._compute_entry_hash(0, genesis_hash, "GENESIS_SEAL", genesis_payload, seal)
        self._entries.append(
            WormEntry(
                index=0,
                timestamp_utc="2026-01-01T00:00:00Z",
                root_anchor=self.GENESIS_ANCHOR,
                parent_hash=genesis_hash,
                module_id="SUP-0",
                event_type="GENESIS_SEAL",
                payload=genesis_payload,
                isv_seal=seal,
                entry_hash=entry_hash,
            )
        )

    @classmethod
    def _compute_isv_seal(
        cls,
        index: int,
        parent_hash: str,
        event_type: str,
        payload: Dict[str, Any],
        secret_key: bytes,
    ) -> str:
        raw = json.dumps(
            {
                "index": index,
                "anchor": cls.GENESIS_ANCHOR,
                "parent": parent_hash,
                "event": event_type,
                "payload": payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hmac.new(secret_key, raw, hashlib.sha256).hexdigest()
        return f"isv-hmac-sha256:{digest}"

    @classmethod
    def _compute_entry_hash(
        cls,
        index: int,
        parent_hash: str,
        event_type: str,
        payload: Dict[str, Any],
        isv_seal: str,
    ) -> str:
        raw = json.dumps(
            {
                "index": index,
                "root_anchor": cls.GENESIS_ANCHOR,
                "parent_hash": parent_hash,
                "event_type": event_type,
                "payload": payload,
                "isv_seal": isv_seal,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(raw).hexdigest()}"

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash

    @property
    def entries(self) -> Tuple[WormEntry, ...]:
        return tuple(self._entries)

    def append_sealed_event(
        self, module_id: str, event_type: str, payload: Dict[str, Any]
    ) -> WormEntry:
        idx = len(self._entries)
        parent_hash = self.head_hash
        payload_copy = json.loads(json.dumps(payload))
        seal = self._compute_isv_seal(
            idx, parent_hash, event_type, payload_copy, self._isv_secret
        )
        entry_hash = self._compute_entry_hash(idx, parent_hash, event_type, payload_copy, seal)
        entry = WormEntry(
            index=idx,
            timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            root_anchor=self.GENESIS_ANCHOR,
            parent_hash=parent_hash,
            module_id=module_id,
            event_type=event_type,
            payload=payload_copy,
            isv_seal=seal,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def compute_merkle_root(self) -> str:
        level = [e.entry_hash.encode("utf-8") for e in self._entries]
        if not level:
            return "sha256:" + ("0" * 64)
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            next_level = []
            for i in range(0, len(level), 2):
                combined = hashlib.sha256(level[i] + b"|" + level[i + 1]).hexdigest()
                next_level.append(f"sha256:{combined}".encode("utf-8"))
            level = next_level
        return level[0].decode("utf-8")

    def verify_integrity(
        self, verification_key: Optional[bytes] = None
    ) -> Tuple[bool, Optional[str]]:
        key_to_use = verification_key if verification_key is not None else self._isv_secret
        expected_genesis_parent = f"sha256:{hashlib.sha256(self.GENESIS_SEED).hexdigest()}"

        for i, entry in enumerate(self._entries):
            if entry.root_anchor != self.GENESIS_ANCHOR:
                return False, f"Bloc #{i}: Rupture d'ancrage SUP-0 ({entry.root_anchor})"
            if i == 0 and entry.parent_hash != expected_genesis_parent:
                return False, f"Bloc #0: Parent Genesis invalide ({entry.parent_hash})"
            if i > 0 and entry.parent_hash != self._entries[i - 1].entry_hash:
                return False, f"Bloc #{i}: Rupture de chaîne parent_hash"

            expected_seal = self._compute_isv_seal(
                entry.index, entry.parent_hash, entry.event_type, entry.payload, key_to_use
            )
            if not hmac.compare_digest(entry.isv_seal, expected_seal):
                return False, f"Bloc #{i}: Sceau ISV invalide (clé incorrecte ou payload altéré)"

            expected_hash = self._compute_entry_hash(
                entry.index, entry.parent_hash, entry.event_type, entry.payload, entry.isv_seal
            )
            if not hmac.compare_digest(entry.entry_hash, expected_hash):
                return False, f"Bloc #{i}: Hash d'entrée corrompu (mutation détectée)"
        return True, None
