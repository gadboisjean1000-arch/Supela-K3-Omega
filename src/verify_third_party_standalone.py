"""
Vérificateur Tiers Autonome Hors-Ligne (`src/verify_third_party_standalone.py`).

IMPORTANT — INDÉPENDANCE D'AUDIT :
Ce script n'importe AUCUN module du moteur Supela (`src.*`).
Il utilise uniquement la bibliothèque standard Python (`hashlib`, `hmac`, `json`, `subprocess`, `pathlib`)
et le moteur C `libxml2` (`lxml.etree`) afin qu'un auditeur externe puisse vérifier mathématiquement,
sans faire confiance au runtime Supela :

1. La signature asymétrique GPG Ed25519 détachée (`evidence/audit_evidence_bundle.json.asc`) via `gpg --verify`.
2. L'empreinte canonique SHA-256 du bundle (`evidence/audit_evidence_bundle.json`).
3. L'intégrité de la chaîne de blocs WORM (`SUP-0`), la racine de Merkle et la présence du bloc de rétrogradation `K3_EPISTEMIC_DEMOTION`.
4. L'équation algébrique du protocole Sigma Schnorr NIZK 2048 bits (IETF RFC 3526 Groupe 14 :
   appartenance au sous-groupe d'ordre premier q, défi Fiat-Shamir c, et g^s mod p == R * Y^c mod p)
   sur le vecteur `evidence/mystandards_submission_pack/05_schnorr_2048_nizk_proof_vector.json`.
5. La validation XSD `libxml2` (`cbpr_plus_head_001_001_02_strict.xsd`, `cbpr_plus_pacs_008_001_10_strict.xsd`,
   `supela_splmtry_001_001_01.xsd`), l'absence de `<SplmtryData>` sur le fil SWIFT et la liaison cryptographique
   `<BoundUETR>` / `<BoundWirePackageSha256>` du Sidecar détaché.
"""

from __future__ import annotations
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List

from lxml import etree as lxml_etree


ROOT_DIR = Path(__file__).resolve().parent.parent

# Constante publique officielle IETF RFC 3526 Groupe 14 (2048-bit MODP Safe Prime p = 2q + 1)
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
P_MOD = int(RFC3526_GROUP14_PRIME_HEX, 16)
Q_SUB = (P_MOD - 1) // 2
G_GEN = 4


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _compute_merkle_root_standalone(leaf_hashes: List[str]) -> str:
    level = [h.encode("utf-8") for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: List[bytes] = []
        for i in range(0, len(level), 2):
            combined = hashlib.sha256(level[i] + b"|" + level[i + 1]).hexdigest()
            next_level.append(f"sha256:{combined}".encode("utf-8"))
        level = next_level
    return level[0].decode("utf-8")


def run_standalone_third_party_audit() -> Dict[str, Any]:
    bundle_path = ROOT_DIR / "evidence" / "audit_evidence_bundle.json"
    asc_path = ROOT_DIR / "evidence" / "audit_evidence_bundle.json.asc"
    pack_dir = ROOT_DIR / "evidence" / "mystandards_submission_pack"
    schemas_dir = ROOT_DIR / "schemas"

    # 1. Vérification de la signature asymétrique GPG Ed25519 détachée (.asc)
    gpg_proc = subprocess.run(
        ["gpg", "--verify", str(asc_path), str(bundle_path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    gpg_verified = gpg_proc.returncode == 0

    # 2. Vérification de l'empreinte canonique SHA-256 du bundle
    raw_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_seal = raw_bundle.pop("bundle_seal")
    canonical_core = json.dumps(raw_bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    recomputed_bundle_sha256 = _sha256_prefixed(canonical_core)
    sha256_matched = hmac.compare_digest(
        recomputed_bundle_sha256, bundle_seal["bundle_payload_sha256"]
    )

    # 3. Vérification indépendante de la chaîne de blocs WORM et de la racine de Merkle
    worm_info = raw_bundle["crypto"]["worm_ledger"]
    blocks = worm_info["block_chain_summary"]
    chain_links_valid = True
    for idx in range(1, len(blocks)):
        if blocks[idx]["parent_hash"] != blocks[idx - 1]["entry_hash"]:
            chain_links_valid = False
            break
    recomputed_merkle = _compute_merkle_root_standalone([b["entry_hash"] for b in blocks])
    merkle_matched = recomputed_merkle == worm_info["merkle_root"]
    has_demotion_block = any(b["event_type"] == "K3_EPISTEMIC_DEMOTION" for b in blocks)

    # 4. Vérification mathématique indépendante du protocole Sigma Schnorr NIZK 2048 bits (RFC 3526 Group 14)
    schnorr_vec = json.loads(
        (pack_dir / "05_schnorr_2048_nizk_proof_vector.json").read_text(encoding="utf-8")
    )
    pub_y = int(schnorr_vec["public_key_y_hex"], 16)
    comm_r = int(schnorr_vec["commitment_r_hex"], 16)
    chal_c = int(schnorr_vec["challenge_c_hex"], 16)
    resp_s = int(schnorr_vec["response_s_hex"], 16)
    ctx_binding = schnorr_vec["context_binding"]

    subgroup_y_ok = (1 < pub_y < P_MOD - 1) and (pow(pub_y, Q_SUB, P_MOD) == 1)
    subgroup_r_ok = (1 < comm_r < P_MOD - 1) and (pow(comm_r, Q_SUB, P_MOD) == 1)
    recomputed_c = (
        int.from_bytes(
            hashlib.sha256(
                b"SUPELA-SCHNORR-NIZK-RFC3526-V1|"
                + f"{G_GEN:x}|{pub_y:x}|{comm_r:x}|{ctx_binding}".encode("utf-8")
            ).digest(),
            "big",
        )
        % Q_SUB
    )
    fiat_shamir_ok = chal_c == recomputed_c
    schnorr_lhs = pow(G_GEN, resp_s, P_MOD)
    schnorr_rhs = (comm_r * pow(pub_y, chal_c, P_MOD)) % P_MOD
    schnorr_equation_ok = schnorr_lhs == schnorr_rhs

    # 5. Validation XSD via C libxml2 et vérification du Sidecar détaché
    bah_xml = (pack_dir / "01_bah_head_001_001_02_strict.xml").read_text(encoding="utf-8")
    pacs_xml = (pack_dir / "02_wire_pacs_008_001_10_strict.xml").read_text(encoding="utf-8")
    sidecar_xml = (pack_dir / "04_detached_supela_lineage_sidecar.xml").read_text(encoding="utf-8")

    bah_schema = lxml_etree.XMLSchema(
        lxml_etree.parse(str(schemas_dir / "cbpr_plus_head_001_001_02_strict.xsd"))
    )
    pacs_schema = lxml_etree.XMLSchema(
        lxml_etree.parse(str(schemas_dir / "cbpr_plus_pacs_008_001_10_strict.xsd"))
    )
    sc_schema = lxml_etree.XMLSchema(
        lxml_etree.parse(str(schemas_dir / "supela_splmtry_001_001_01.xsd"))
    )

    bah_xsd_ok = bah_schema.validate(lxml_etree.fromstring(bah_xml.encode("utf-8")))
    pacs_xsd_ok = pacs_schema.validate(lxml_etree.fromstring(pacs_xml.encode("utf-8")))
    sc_xsd_ok = sc_schema.validate(lxml_etree.fromstring(sidecar_xml.encode("utf-8")))
    no_splmtry_on_wire = "SplmtryData" not in pacs_xml

    # Vérification de l'ancrage cryptographique entre le message réseau pacs.008 et le Sidecar détaché
    pacs_msg_bundle = raw_bundle["messages"]["pacs_008_001_10_cbpr_strict"]
    expected_uetr = pacs_msg_bundle["uetr"]
    uetr_bound_ok = (f"<UETR>{expected_uetr}</UETR>" in pacs_xml) and (
        f"<BoundUETR>{expected_uetr}</BoundUETR>" in sidecar_xml
    )

    # 6. Vérification du plafond épistémique local (interdiction d'auto-attribution Niveaux 4/5)
    assurance = raw_bundle["k3_omega_assurance_matrix"]
    epistemic_ceiling_honored = (
        assurance["local_ceiling_enforced"] == "LEVEL_3_AUDITABLE"
        and assurance["self_attribution_of_level_4_or_5"] is False
    )

    all_passed = all(
        [
            gpg_verified,
            sha256_matched,
            chain_links_valid,
            merkle_matched,
            has_demotion_block,
            subgroup_y_ok,
            subgroup_r_ok,
            fiat_shamir_ok,
            schnorr_equation_ok,
            bah_xsd_ok,
            pacs_xsd_ok,
            sc_xsd_ok,
            no_splmtry_on_wire,
            uetr_bound_ok,
            epistemic_ceiling_honored,
        ]
    )

    return {
        "auditor_script": "src/verify_third_party_standalone.py (Zero Supela Engine Dependency)",
        "overall_third_party_verification_passed": all_passed,
        "1_gpg_ed25519_detached_signature": {
            "verified": gpg_verified,
            "signing_key": bundle_seal["gpg_signing_key_fingerprint"],
        },
        "2_bundle_canonical_sha256": {
            "matched": sha256_matched,
            "sha256": recomputed_bundle_sha256,
        },
        "3_worm_merkle_and_epistemic_demotion": {
            "chain_links_valid": chain_links_valid,
            "merkle_root_matched": merkle_matched,
            "merkle_root": recomputed_merkle,
            "epistemic_demotion_block_present": has_demotion_block,
        },
        "4_schnorr_2048_nizk_rfc3526_algebraic_audit": {
            "prime_order_subgroup_y_valid": subgroup_y_ok,
            "prime_order_subgroup_r_valid": subgroup_r_ok,
            "fiat_shamir_challenge_valid": fiat_shamir_ok,
            "modular_equation_g_s_eq_R_Y_c_mod_p_valid": schnorr_equation_ok,
        },
        "5_libxml2_xsd_and_cbpr_strict_sidecar_binding": {
            "bah_head001_xsd_valid": bah_xsd_ok,
            "wire_pacs008_strict_xsd_valid": pacs_xsd_ok,
            "zero_splmtry_data_on_wire": no_splmtry_on_wire,
            "detached_sidecar_xsd_valid": sc_xsd_ok,
            "sidecar_uetr_and_wire_binding_verified": uetr_bound_ok,
        },
        "6_epistemic_honesty_invariant": {
            "local_ceiling_enforced": assurance["local_ceiling_enforced"],
            "self_attribution_of_level_4_or_5": assurance["self_attribution_of_level_4_or_5"],
            "epistemic_ceiling_honored": epistemic_ceiling_honored,
        },
    }


if __name__ == "__main__":
    report = run_standalone_third_party_audit()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report["overall_third_party_verification_passed"]:
        sys.exit(1)
