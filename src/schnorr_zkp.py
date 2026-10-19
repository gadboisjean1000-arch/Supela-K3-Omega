"""
Preuve à Divulgation Nulle de Connaissance (NIZK) de Schnorr sur Groupe MODP 2048 bits (RFC 3526 Groupe 14).

Remplace les simples engagements par hachage SHA-256 par un véritable protocole Sigma (Σ)
non-interactif via l'heuristique de Fiat-Shamir :
- Énoncé public (Statement) : (p, g, Y) où Y = g^w mod p
- Témoin secret (Witness)   : w in [1, p-2] (JAMAIS transmis ni stocké dans la preuve)
- Engagement (Commitment)   : R = g^r mod p
- Défi (Fiat-Shamir)        : c = SHA256("SUPELA-SCHNORR-NIZK-V1|" || g || Y || R || context)
- Réponse (Response)        : s = (r + c * w) mod (p - 1)
- Équation de vérification  : g^s mod p == (R * (Y^c mod p)) mod p

Propriétés mathématiques garanties :
1. Complétude (Completeness) : Si Y = g^w mod p, alors g^s = g^(r + c*w) = g^r * (g^w)^c = R * Y^c (mod p).
2. Solidité spéciale (Special Soundness) : Impossible de produire (R, c, s) valide sans connaître w
   (sous l'hypothèse de difficulté du logarithme discret dans le groupe RFC 3526 de 2048 bits).
3. Divulgation nulle (Honest-Verifier Zero-Knowledge) : Le triplet (R, c, s) ne révèle aucune
   information sur le secret w (simulation indiscernable).
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Dict


# Nombre premier sûr (Safe Prime p = 2q + 1) de 2048 bits — Standard IETF RFC 3526 Groupe 14
RFC3526_GROUP14_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P_MODULUS: int = int(RFC3526_GROUP14_PRIME_HEX, 16)
P_MINUS_1: int = P_MODULUS - 1
Q_SUBGROUP: int = (P_MODULUS - 1) // 2
G_GENERATOR: int = 4  # Générateur du sous-groupe d'ordre premier q (2^2 = 4 est un résidu quadratique mod p)


@dataclass(frozen=True)
class SchnorrNizkProof:
    """Preuve NIZK de Schnorr liée cryptographiquement à un contexte (proposal_id + parent_hash)."""

    scheme: str
    public_key_y_hex: str
    commitment_r_hex: str
    challenge_c_hex: str
    response_s_hex: str
    context_binding: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "group": "RFC3526-MODP-2048-PRIME-ORDER-Q",
            "public_key_y_hex": self.public_key_y_hex,
            "commitment_r_hex": self.commitment_r_hex,
            "challenge_c_hex": self.challenge_c_hex,
            "response_s_hex": self.response_s_hex,
            "context_binding": self.context_binding,
        }

    def to_compact_token(self) -> str:
        return f"zkp-schnorr-2048:{self.commitment_r_hex}:{self.challenge_c_hex}:{self.response_s_hex}"


def _derive_scalar_mod_q(seed_bytes: bytes, domain_sep: bytes) -> int:
    """Dérive de manière déterministe un scalaire dans [1, q - 1] (style RFC 6979)."""
    digest = hmac.new(domain_sep, seed_bytes, hashlib.sha512).digest()
    return (int.from_bytes(digest, "big") % (Q_SUBGROUP - 1)) + 1


def _compute_fiat_shamir_challenge(
    public_y: int, commitment_r: int, context_binding: str
) -> int:
    """Calcule le défi Fiat-Shamir c = SHA256(DOM || g || Y || R || context) mod q."""
    hasher = hashlib.sha256()
    hasher.update(b"SUPELA-SCHNORR-NIZK-RFC3526-V1|")
    hasher.update(f"{G_GENERATOR:x}|{public_y:x}|{commitment_r:x}|{context_binding}".encode("utf-8"))
    return int.from_bytes(hasher.digest(), "big") % Q_SUBGROUP


def generate_schnorr_nizk_proof(
    witness_secret: str, proposal_id: str, parent_hash: str
) -> SchnorrNizkProof:
    """
    Prouve la connaissance du témoin secret `w` tel que `Y = g^w mod p` dans le sous-groupe
    d'ordre premier `q`, liée au contexte `proposal_id|parent_hash`, sans jamais exposer `w`.
    """
    context_binding = f"SUP-0|{proposal_id}|{parent_hash}"
    w_secret = _derive_scalar_mod_q(
        witness_secret.encode("utf-8"), b"SUPELA-ZKP-WITNESS-SCALAR"
    )
    public_y = pow(G_GENERATOR, w_secret, P_MODULUS)

    # Nonce éphémère déterministe RFC 6979 (protège contre la réutilisation de nonce)
    r_nonce = _derive_scalar_mod_q(
        f"{w_secret:x}|{context_binding}".encode("utf-8"),
        b"SUPELA-ZKP-EPHEMERAL-NONCE",
    )
    commitment_r = pow(G_GENERATOR, r_nonce, P_MODULUS)
    challenge_c = _compute_fiat_shamir_challenge(public_y, commitment_r, context_binding)

    # Dans le sous-groupe d'ordre premier q (car G_GENERATOR = 4 = 2^2 mod p), g^q ≡ 1 (mod p)
    response_s = (r_nonce + challenge_c * w_secret) % Q_SUBGROUP

    return SchnorrNizkProof(
        scheme="SCHNORR-NIZK-FIAT-SHAMIR-RFC3526-2048",
        public_key_y_hex=f"{public_y:x}",
        commitment_r_hex=f"{commitment_r:x}",
        challenge_c_hex=f"{challenge_c:x}",
        response_s_hex=f"{response_s:x}",
        context_binding=context_binding,
    )


def verify_schnorr_nizk_proof(
    proof_data: Dict[str, Any] | SchnorrNizkProof,
    expected_public_key_y_hex: str,
    proposal_id: str,
    parent_hash: str,
) -> bool:
    """
    Vérifie algébriquement la preuve NIZK de Schnorr sans connaître le secret `w` :
    1. Vérifie que Y et R appartiennent à [2, p - 2] et au sous-groupe d'ordre premier q (Y^q ≡ 1 mod p).
    2. Recalcule le défi Fiat-Shamir c' sur (Y, R, SUP-0|proposal_id|parent_hash) et vérifie c == c'.
    3. Vérifie l'équation algébrique : g^s mod p == (R * Y^c) mod p.
    """
    if isinstance(proof_data, SchnorrNizkProof):
        p_dict = proof_data.to_dict()
    elif isinstance(proof_data, dict):
        p_dict = proof_data
    else:
        return False

    try:
        public_y = int(expected_public_key_y_hex, 16)
        proof_y = int(str(p_dict.get("public_key_y_hex", "0")), 16)
        commitment_r = int(str(p_dict.get("commitment_r_hex", "0")), 16)
        challenge_c = int(str(p_dict.get("challenge_c_hex", "0")), 16)
        response_s = int(str(p_dict.get("response_s_hex", "0")), 16)
    except ValueError:
        return False

    if public_y != proof_y:
        return False
    if not (1 < public_y < P_MODULUS - 1 and 1 < commitment_r < P_MODULUS - 1):
        return False
    if not (0 < response_s < Q_SUBGROUP):
        return False

    # Vérification d'appartenance au sous-groupe d'ordre premier q
    if pow(public_y, Q_SUBGROUP, P_MODULUS) != 1:
        return False
    if pow(commitment_r, Q_SUBGROUP, P_MODULUS) != 1:
        return False

    expected_context = f"SUP-0|{proposal_id}|{parent_hash}"
    if p_dict.get("context_binding") != expected_context:
        return False

    recomputed_c = _compute_fiat_shamir_challenge(public_y, commitment_r, expected_context)
    if challenge_c != recomputed_c:
        return False

    # Équation fondamentale de Schnorr : g^s ≡ R * Y^c (mod p)
    lhs = pow(G_GENERATOR, response_s, P_MODULUS)
    rhs = (commitment_r * pow(public_y, challenge_c, P_MODULUS)) % P_MODULUS
    return lhs == rhs
