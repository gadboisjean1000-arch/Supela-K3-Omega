"""
Extracteur d'Artefacts XML Autonomes pour Dépôt sur SWIFT MyStandards Readiness Portal
et Exécution sur SWIFT Integration Testbed (ITB).

Lit `evidence/audit_evidence_bundle.json` et extrait dans `evidence/mystandards_submission_pack/` :
1. `01_bah_head_001_001_02_strict.xml` : Business Application Header (`swift.cbprplus.02`).
2. `02_wire_pacs_008_001_10_strict.xml` : Message de règlement interbancaire CBPR+ Strict (zéro `<SplmtryData>`).
3. `03_wire_camt_053_001_10.xml` : Relevé de compte bancaire ISO 20022.
4. `04_detached_supela_lineage_sidecar.xml` : Sidecar cryptographique `<SupelaLineage>` (hors réseau SWIFT,
   destiné au registre d'audit WORM et aux contreparties bilatérales, lié via `BoundUETR` et `BoundWirePackageSha256`).
5. `05_schnorr_2048_nizk_proof_vector.json` : Vecteur de test cryptographique autonome pour vérification par auditeur tiers.
6. `SUBMISSION_MANIFEST.json` : Empreintes SHA-256 et critères d'acceptation Niveau 4 (`0 Error / 0 Warning`).
"""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.iso_fatf_mirrors import Iso20022StructuralValidator
from src.schnorr_zkp import verify_schnorr_nizk_proof


def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def export_submission_pack() -> Dict[str, Any]:
    bundle_path = ROOT_DIR / "evidence" / "audit_evidence_bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    pack_dir = ROOT_DIR / "evidence" / "mystandards_submission_pack"
    pack_dir.mkdir(parents=True, exist_ok=True)

    pacs_msg = bundle["messages"]["pacs_008_001_10_cbpr_strict"]
    camt_msg = bundle["messages"]["camt_053_001_10"]
    bah_msg = bundle["messages"]["head_001_001_02_bah"]
    schnorr_vec = bundle["crypto"]["zero_knowledge_proof_scheme"]["sample_verified_proof"]

    bah_xml = bah_msg["raw_xml"]
    pacs_xml = pacs_msg["wire_raw_xml"]
    camt_xml = camt_msg["raw_xml"]
    sidecar_xml = pacs_msg["detached_sidecar_xml"]

    # Pré-validation locale libxml2 avant export du dossier de soumission
    ok_bah, errs_bah = Iso20022StructuralValidator.validate_head001_cbpr_strict_xml(bah_xml)
    ok_pacs, errs_pacs = Iso20022StructuralValidator.validate_pacs008_cbpr_strict_xml(pacs_xml)
    ok_sc, errs_sc = Iso20022StructuralValidator.validate_supela_sidecar_xml(sidecar_xml)

    if not (ok_bah and ok_pacs and ok_sc):
        raise RuntimeError(f"Échec de pré-validation XSD: BAH={errs_bah}, PACS={errs_pacs}, SC={errs_sc}")

    ctx_parts = str(schnorr_vec["context_binding"]).split("|")
    schnorr_ok = verify_schnorr_nizk_proof(
        proof_data=schnorr_vec,
        expected_public_key_y_hex=schnorr_vec["public_key_y_hex"],
        proposal_id=ctx_parts[1],
        parent_hash=ctx_parts[2],
    )
    if not schnorr_ok:
        raise RuntimeError("Échec de vérification du vecteur Schnorr 2048 bits")

    files_to_write = {
        "01_bah_head_001_001_02_strict.xml": bah_xml.encode("utf-8"),
        "02_wire_pacs_008_001_10_strict.xml": pacs_xml.encode("utf-8"),
        "03_wire_camt_053_001_10.xml": camt_xml.encode("utf-8"),
        "04_detached_supela_lineage_sidecar.xml": sidecar_xml.encode("utf-8"),
        "05_schnorr_2048_nizk_proof_vector.json": json.dumps(
            schnorr_vec, indent=2, ensure_ascii=False
        ).encode("utf-8"),
    }

    manifest_files: Dict[str, Dict[str, Any]] = {}
    for fname, raw_bytes in files_to_write.items():
        fpath = pack_dir / fname
        fpath.write_bytes(raw_bytes)
        manifest_files[fname] = {
            "sha256": _sha256_bytes(raw_bytes),
            "size_bytes": len(raw_bytes),
        }

    manifest = {
        "pack_version": "supela.k3.omega.level4.submission.pack.v1",
        "source_bundle_sha256": bundle["bundle_seal"]["bundle_payload_sha256"],
        "candidate_uetr": pacs_msg["uetr"],
        "epistemic_status_before_external_portal": "LEVEL_3_AUDITABLE (CANDIDATE_UETR_UUIDV4)",
        "target_qualification_level": "LEVEL_4_THIRD_PARTY_QUALIFIED",
        "exported_artifacts": manifest_files,
        "local_pre_flight_checks": {
            "libxml2_bah_head001_strict_valid": ok_bah,
            "libxml2_pacs008_cbpr_strict_valid": ok_pacs,
            "zero_splmtry_data_in_wire_pacs008": "SplmtryData" not in pacs_xml,
            "libxml2_detached_sidecar_valid": ok_sc,
            "schnorr_2048_nizk_vector_verified": schnorr_ok,
        },
        "external_qualification_gates": {
            "gate_1_mystandards_readiness_portal": {
                "input_files": [
                    "01_bah_head_001_001_02_strict.xml",
                    "02_wire_pacs_008_001_10_strict.xml",
                ],
                "collection": "CBPR+ Usage Guidelines (current Standard Release)",
                "pass_criteria": "0 Fatal, 0 Error, 0 Warning on XSD + Formal Rules (Cross-Element, FIN-X, SettlementMethod)",
            },
            "gate_2_swift_integration_testbed_itb": {
                "input_files": [
                    "01_bah_head_001_001_02_strict.xml",
                    "02_wire_pacs_008_001_10_strict.xml",
                ],
                "pass_criteria": "Receipt of FINplus ACK (pacs.002.001.12 ACCP/ACSC) with identical UETR preserved",
            },
            "gate_3_cryptographic_hsm_and_zkp_audit": {
                "input_files": [
                    "04_detached_supela_lineage_sidecar.xml",
                    "05_schnorr_2048_nizk_proof_vector.json",
                ],
                "pass_criteria": "Independent verification of RFC 3526 Group 14 Schnorr NIZK equation + PKCS#11 / Cloud KMS FIPS 140-3 key attestation",
            },
        },
    }

    manifest_path = pack_dir / "SUBMISSION_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    result = export_submission_pack()
    print(json.dumps(result, indent=2, ensure_ascii=False))
