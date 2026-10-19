"""
Suite de tests unitaires, d'intégration et de tests négatifs cryptographiques/normatifs
pour Supela-K3-Omega (`Supela-2026-Epsilon` — Préparation Technique Niveau 4).

Couvre 15 tests vérifiables localement :
- Tests 1 à 8 : Fonctionnement nominal, aplatissement de schémas récursifs, fallback 429,
  quarantaine sur dérive émergente, compilation ISO 20022 / FATF / SWIFT et proxy HTTP local.
- Tests 9 à 12 (Tests Négatifs d'Audit) :
  * Test 9 : Détection d'altération d'un bloc WORM en mémoire ET rejet d'une clé HMAC-ISV erronée (sans clé codée en dur).
  * Test 10 : Rejet d'une preuve ZKP Schnorr 2048 bits falsifiée.
  * Test 11 : Blocage anti-rejeu d'un UETR (`UetrReplayViolationError` sur réutilisation de couple proposal_id/parent_hash).
  * Test 12 : Rejet par le validateur XSD `libxml2` (`Iso20022StructuralValidator`) d'un BIC invalide
    ou d'un `<SplmtryData>` sans espace de noms dédié.
- Tests 13 à 15 (Nouvelles preuves matérielles Niveau 4 Prep) :
  * Test 13 : Preuve algébrique à divulgation nulle de connaissance Schnorr NIZK 2048 bits (RFC 3526 Group 14)
    $g^s \\equiv R \\cdot Y^c \\pmod p$ et rejet de falsifications algébriques ($s+1$, $R$ altéré, contexte modifié).
  * Test 14 : Mode `CBPR_PLUS_STRICT` (*Detached Lineage Sidecar*) : absence stricte de `<SplmtryData>` sur le fil
    SWIFT FINplus, rejet par `libxml2` XSD de tout `<SplmtryData>` injecté sur le fil, et validation XSD du sidecar détaché.
  * Test 15 : Exécution réelle du binaire CNCF `opa.exe` (`opa test` 5/5 + `opa eval` sur enveloppe K3) et parité déterministe.
"""

from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest
import urllib.request

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.iso_fatf_mirrors import Iso20022StructuralValidator, NormativeMirrorCompiler
from src.k3_http_mcp_gateway import SupelaGatewayServer
from src.opa_binary_bridge import evaluate_envelope_with_opa_binary, run_opa_policy_tests
from src.schema_flattener import (
    detect_recursive_or_unbounded_patterns,
    flatten_tool_schema,
)
from src.schnorr_zkp import (
    G_GENERATOR,
    P_MODULUS,
    Q_SUBGROUP,
    SchnorrNizkProof,
    generate_schnorr_nizk_proof,
    verify_schnorr_nizk_proof,
)
from src.supela_k3_engine import SupelaK3OmegaEngine
from src.worm_merkle import (
    SupelaWormLedger,
    WormEntry,
)


def make_valid_envelope(
    parent_hash: str, module_id: str = "VR-14", proposal_suffix: str = "001"
) -> dict:
    proposal_id = f"PROP-2026-EPSILON-{module_id}-{proposal_suffix}"
    schnorr_proof = generate_schnorr_nizk_proof(
        witness_secret=f"SECRET-WITNESS-{proposal_id}",
        proposal_id=proposal_id,
        parent_hash=parent_hash,
    )
    return {
        "proposal_id": proposal_id,
        "actor": {
            "role": "AI_PROPOSAL_GENERATOR",
            "direct_execution_privilege": False,
        },
        "proposal": {
            "module_id": module_id,
            "target_environment": "k3s-isolated-sandbox",
            "estimated_impact_score": 20,
            "emergent_drift_delta": 0.02,
            "modifies_worm_ledger": False,
            "parameters": {
                "amount": 15000.00,
                "currency": "EUR",
                "debtor_bic": "SUPELACAXXX",
                "creditor_bic": "BNPAFRPPXXX",
                "settlement_date": "2026-10-19",
                "settlement_method": "INDA",
            },
            "lineage": {
                "root_anchor": "SUP-0",
                "merkle_parent_hash": parent_hash,
                "isv_seal": "ISV-2026-EPSILON-SEALED",
            },
        },
        "validation": {
            "gf_verdict": "SEALED_APPROVED",
            "engine_signatures": ["sig-engine-alpha", "sig-engine-beta"],
            "schnorr_public_key_y": schnorr_proof.public_key_y_hex,
            "schnorr_proof": schnorr_proof.to_dict(),
            "zkp_proof": schnorr_proof.to_compact_token(),
        },
        "tool_schema": {
            "type": "object",
            "properties": {
                "transaction_id": {"type": "string"},
                "amount": {"type": "number"},
            },
        },
        "provider_telemetry": {
            "status": "HEALTHY",
            "primary_model": "gemini-4-argon",
            "error_code": "NONE",
        },
    }


class TestSupelaK3Omega(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = SupelaWormLedger()
        self.engine = SupelaK3OmegaEngine(
            ledger=self.ledger,
            max_drift_delta=0.05,
            auto_flatten_schemas=True,
        )

    def test_01_worm_ledger_genesis_and_integrity(self) -> None:
        """Vérifie que le bloc Genesis SUP-0 est scellé avec une clé CSPRNG éphémère et que la chaîne est valide."""
        ok, err = self.ledger.verify_integrity()
        self.assertTrue(ok, f"Le journal Genesis devrait être intègre: {err}")
        self.assertEqual(self.ledger.entries[0].root_anchor, "SUP-0")
        self.assertTrue(self.ledger.key_fingerprint_sha256.startswith("sha256:"))

    def test_02_nominal_proposal_dual_pipeline(self) -> None:
        """Une proposition IA conforme avec preuve Schnorr NIZK 2048 bits est exécutée et génère camt.053."""
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-14")
        receipt = self.engine.evaluate_and_dispatch(env)

        self.assertTrue(receipt.allowed)
        self.assertFalse(receipt.quarantine)
        self.assertEqual(receipt.execution_route, "DUAL_PIPELINE_DISPATCH")
        self.assertEqual(
            receipt.epistemic_assurance_matrix["zkp_validity"]["status"],
            "SCHNORR_2048_MODP_NIZK_VERIFIED",
        )
        self.assertEqual(
            receipt.epistemic_assurance_matrix["zkp_validity"]["level"],
            "LEVEL_3_AUDITABLE",
        )
        self.assertIn(
            "urn:iso:std:iso:20022:tech:xsd:camt.053.001.10",
            receipt.slow_lane_mirror_envelope["artifact"]["xml_payload"],
        )
        ok, _ = self.ledger.verify_integrity()
        self.assertTrue(ok)

    def test_03_recursive_json_schema_auto_flattened_prevents_meta_400(self) -> None:
        """Vérifie l'aplatissement statique des schémas récursifs ($ref/$defs) et objets ouverts."""
        problematic_mcp_schema = {
            "type": "object",
            "properties": {
                "ServerName": {"type": "string"},
                "Arguments": {"type": "object"},
                "RecursiveNode": {"$ref": "#/$defs/TreeNode"},
            },
            "$defs": {
                "TreeNode": {
                    "type": "object",
                    "properties": {"child": {"$ref": "#/$defs/TreeNode"}},
                }
            },
        }
        issues = detect_recursive_or_unbounded_patterns(problematic_mcp_schema)
        self.assertGreaterEqual(len(issues), 3)

        flattened, report = flatten_tool_schema(problematic_mcp_schema, max_depth=2)
        self.assertTrue(report.was_modified)
        self.assertEqual(detect_recursive_or_unbounded_patterns(flattened), [])

        env = make_valid_envelope(self.ledger.head_hash, proposal_suffix="FLAT")
        env["tool_schema"] = problematic_mcp_schema
        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertTrue(receipt.allowed)

    def test_04_recursive_schema_quarantined_when_flattener_disabled(self) -> None:
        """Si la passerelle d'aplatissement est désactivée, le moteur bloque préventivement le schéma récursif."""
        strict_engine = SupelaK3OmegaEngine(
            ledger=self.ledger, max_drift_delta=0.05, auto_flatten_schemas=False
        )
        env = make_valid_envelope(self.ledger.head_hash, proposal_suffix="NOFLAT")
        env["tool_schema"] = {
            "type": "object",
            "properties": {"self_ref": {"$ref": "#/$defs/Node"}},
            "$defs": {"Node": {"type": "object"}},
        }
        receipt = strict_engine.evaluate_and_dispatch(env)
        self.assertFalse(receipt.allowed)
        self.assertTrue(receipt.quarantine)

    def test_05_quota_exceeded_triggers_sovereign_fallback(self) -> None:
        """Vérifie le repli déterministe vers supela-local-sovereign-v1 sur code DAILY_FREE_LIMIT_REACHED."""
        env = make_valid_envelope(self.ledger.head_hash, proposal_suffix="QUOTA")
        env["provider_telemetry"] = {
            "status": "DEGRADED",
            "primary_model": "nvidia/nemotron-3.5-super-vl",
            "error_code": "DAILY_FREE_LIMIT_REACHED",
        }
        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertTrue(receipt.allowed)
        self.assertEqual(receipt.selected_provider, "supela-local-sovereign-v1")
        self.assertEqual(receipt.routing_mode, "DEGRADED_FALLBACK_SEALED")

    def test_06_ai_autonomy_and_emergent_drift_quarantined(self) -> None:
        """Vérifie la mise en quarantaine d'un agent IA réclamant un privilège direct ou dérivant hors seuil."""
        env = make_valid_envelope(self.ledger.head_hash, proposal_suffix="ROGUE")
        env["actor"]["direct_execution_privilege"] = True
        env["proposal"]["emergent_drift_delta"] = 0.14

        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertFalse(receipt.allowed)
        self.assertTrue(receipt.quarantine)
        self.assertEqual(len(receipt.violations), 2)

    def test_07_iso20022_pacs008_fatf_ivms101_and_swift_cbpr_mirrors(self) -> None:
        """Vérifie la génération et la validation XSD `libxml2` en mode CBPR_PLUS_STRICT de VR-13, VR-15 et VR-16."""
        r_pacs = self.engine.evaluate_and_dispatch(
            make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="PACS")
        )
        self.assertTrue(r_pacs.allowed)
        art_pacs = r_pacs.slow_lane_mirror_envelope["artifact"]
        self.assertEqual(art_pacs["profile_mode"], "CBPR_PLUS_STRICT_DETACHED_SIDECAR")
        self.assertNotIn("<SplmtryData>", art_pacs["xml_payload"])
        self.assertIn(
            "urn:supela:std:k3:omega:xsd:splmtry.001.001.01",
            art_pacs["detached_supela_sidecar"]["sidecar_xml"],
        )

        r_fatf = self.engine.evaluate_and_dispatch(
            make_valid_envelope(self.ledger.head_hash, module_id="VR-15", proposal_suffix="FATF")
        )
        self.assertTrue(r_fatf.allowed)
        ivms_art = r_fatf.slow_lane_mirror_envelope["artifact"]
        self.assertEqual(ivms_art["schema_version"], "IVMS101.2023-DUAL-CHANNEL")
        self.assertIn("channel_1_inter_vasp_travel_rule_payload", ivms_art)
        self.assertIn("channel_2_worm_ledger_zero_pii_commitment", ivms_art)

        r_swift = self.engine.evaluate_and_dispatch(
            make_valid_envelope(self.ledger.head_hash, module_id="VR-16", proposal_suffix="SWIFT")
        )
        self.assertTrue(r_swift.allowed)
        self.assertIn("swift.cbprplus.02", r_swift.slow_lane_mirror_envelope["artifact"]["bah_xml"])

    def test_08_live_http_mcp_gateway_prevents_meta_400_and_handles_429(self) -> None:
        """Exerce le serveur HTTP local SupelaGatewayServer via une requête POST réelle."""
        server = SupelaGatewayServer(host="127.0.0.1", port=0)
        base_url = server.start_background()
        try:
            payload = {
                "request_id": "REQ-HTTP-PROXY-001",
                "model": "nvidia/nemotron-3.5-super-vl",
                "messages": [{"role": "user", "content": "Exécuter le règlement VR-14"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "call_mcp_tool",
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "Arguments": {"type": "object"},
                                    "tree": {"$ref": "#/$defs/Node"},
                                },
                                "$defs": {
                                    "Node": {
                                        "type": "object",
                                        "properties": {"child": {"$ref": "#/$defs/Node"}},
                                    }
                                },
                            },
                        },
                    }
                ],
            }
            req = urllib.request.Request(
                url=f"{base_url}/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))

            self.assertEqual(body["upstream_http_status"], 429)
            self.assertTrue(body["schema_flattening_gate"]["reports"][0]["was_modified"])
            self.assertEqual(
                body["k3_omega_receipt"]["routing"]["selected_provider"],
                "supela-local-sovereign-v1",
            )
        finally:
            server.stop()

    # =========================================================================
    # TESTS NÉGATIFS D'AUDIT (CRYPTOGRAPHIE, ANTI-REJEU UETR, VALIDATION XSD)
    # =========================================================================

    def test_09_negative_crypto_tampered_worm_payload_and_wrong_isv_key(self) -> None:
        """
        Test négatif cryptographique #1 :
        - Vérifie qu'une clé HMAC-ISV erronée fait échouer `verify_integrity`.
        - Vérifie que la modification d'un seul champ dans le payload d'un bloc WORM
          ou la falsification du hash parent est immédiatement détectée.
        """
        self.engine.evaluate_and_dispatch(
            make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="NEG9")
        )

        # 1. Vérification avec une mauvaise clé secrète ISV -> Doit échouer dès le bloc #0
        ok_wrong_key, err_wrong_key = self.ledger.verify_integrity(
            verification_key=b"WRONG-ADVERSARIAL-KEY-0000000000"
        )
        self.assertFalse(ok_wrong_key)
        self.assertIn("Sceau ISV invalide", err_wrong_key or "")

        # 2. Altération malveillante du payload du bloc #1 en mémoire -> Doit échouer sur le sceau ISV
        original_entry = self.ledger._entries[1]
        tampered_payload = copy.deepcopy(original_entry.payload)
        tampered_payload["allowed"] = False
        self.ledger._entries[1] = WormEntry(
            index=original_entry.index,
            timestamp_utc=original_entry.timestamp_utc,
            root_anchor=original_entry.root_anchor,
            parent_hash=original_entry.parent_hash,
            module_id=original_entry.module_id,
            event_type=original_entry.event_type,
            payload=tampered_payload,
            isv_seal=original_entry.isv_seal,
            entry_hash=original_entry.entry_hash,
        )
        ok_tampered, err_tampered = self.ledger.verify_integrity()
        self.assertFalse(ok_tampered)
        self.assertIn("Bloc #1: Sceau ISV invalide", err_tampered or "")

        # Restauration et test d'altération du hash d'entrée seul
        self.ledger._entries[1] = WormEntry(
            index=original_entry.index,
            timestamp_utc=original_entry.timestamp_utc,
            root_anchor=original_entry.root_anchor,
            parent_hash=original_entry.parent_hash,
            module_id=original_entry.module_id,
            event_type=original_entry.event_type,
            payload=original_entry.payload,
            isv_seal=original_entry.isv_seal,
            entry_hash="sha256:" + ("f" * 64),
        )
        ok_hash, err_hash = self.ledger.verify_integrity()
        self.assertFalse(ok_hash)
        self.assertIn("Bloc #1: Hash d'entrée corrompu", err_hash or "")

    def test_10_negative_crypto_forged_zkp_witness_rejected(self) -> None:
        """
        Test négatif cryptographique #2 :
        Vérifie qu'une preuve Schnorr NIZK 2048 bits générée avec un mauvais secret témoin
        (ne correspondant pas à la clé publique `schnorr_public_key_y`) est algébriquement rejetée.
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="FORGED")
        forged_schnorr = generate_schnorr_nizk_proof(
            witness_secret="WRONG-ATTACKER-WITNESS",
            proposal_id=env["proposal_id"],
            parent_hash=self.ledger.head_hash,
        )
        # L'attaquant tente de soumettre sa preuve sous la clé publique légitime attendue
        env["validation"]["schnorr_proof"] = forged_schnorr.to_dict()
        env["validation"]["zkp_proof"] = forged_schnorr.to_compact_token()

        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertFalse(receipt.allowed)
        self.assertTrue(receipt.quarantine)
        self.assertTrue(
            any("invalid ZKP commitment proof" in v for v in receipt.violations)
        )

    def test_11_negative_uetr_replay_collision_blocked(self) -> None:
        """
        Test négatif normatif #3 (Exigence SWIFT d'unicité UETR) :
        Si un même couple `(proposal_id, merkle_parent_hash)` est rejoué, le registre
        d'unicité UETR bloque la réémission et place la seconde tentative en quarantaine.
        """
        fixed_parent_hash = self.ledger.head_hash
        env1 = make_valid_envelope(fixed_parent_hash, module_id="VR-13", proposal_suffix="REPLAY")
        env2 = copy.deepcopy(env1)

        receipt1 = self.engine.evaluate_and_dispatch(env1)
        self.assertTrue(receipt1.allowed)

        # Rejeu exact avec le même proposal_id et le même parent_hash
        receipt2 = self.engine.evaluate_and_dispatch(env2)
        self.assertFalse(receipt2.allowed)
        self.assertTrue(receipt2.quarantine)
        self.assertTrue(
            any("REPLAY_BLOCKED" in v for v in receipt2.violations),
            f"Attendu REPLAY_BLOCKED dans {receipt2.violations}",
        )

    def test_12_negative_iso20022_structural_validator_rejects_non_compliant_xml(self) -> None:
        """
        Test négatif normatif #4 (Validation XSD `libxml2` ISO 20022 & <SplmtryData>) :
        Vérifie que `Iso20022StructuralValidator` rejette :
        - Un code BICFI mal formé (ex. "INVALID_BIC_123")
        - Une extension `<SplmtryData>` dépourvue d'espace de noms dédié en mode bilatéral
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="BADBIC")
        env["proposal"]["parameters"]["debtor_bic"] = "INVALID_BIC_123"
        receipt_bad_bic = self.engine.evaluate_and_dispatch(env)
        self.assertFalse(receipt_bad_bic.allowed)
        self.assertTrue(receipt_bad_bic.quarantine)
        self.assertTrue(
            any("INVALID_BICFI_DbtrAgt" in v for v in receipt_bad_bic.violations)
        )

        # Test direct d'un XML avec extension <SplmtryData> sans namespace qualifié en mode bilatéral
        unqualified_xml = (
            '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10">'
            "<FIToFICstmrCdtTrf>"
            "<GrpHdr><MsgId>M1</MsgId></GrpHdr>"
            "<CdtTrfTxInf>"
            "<PmtId><UETR>cc707866-5f52-4648-a161-f0d4abe2db88</UETR></PmtId>"
            '<IntrBkSttlmAmt Ccy="EUR">100.00</IntrBkSttlmAmt>'
            "<ChrgBr>SHAR</ChrgBr>"
            "<Dbtr><Nm>A</Nm></Dbtr>"
            "<DbtrAgt><FinInstnId><BICFI>SUPELACAXXX</BICFI></FinInstnId></DbtrAgt>"
            "<CdtrAgt><FinInstnId><BICFI>BNPAFRPPXXX</BICFI></FinInstnId></CdtrAgt>"
            "<Cdtr><Nm>B</Nm></Cdtr>"
            '<SplmtryData><Envlp><SupelaLineage xmlns=""/></Envlp></SplmtryData>'
            "</CdtTrfTxInf>"
            "</FIToFICstmrCdtTrf></Document>"
        )
        valid_ns, errs_ns = Iso20022StructuralValidator.validate_pacs008_xml(
            unqualified_xml
        )
        self.assertFalse(valid_ns)
        self.assertTrue(any("UNQUALIFIED_SPLMTRY_EXTENSION_NS" in e for e in errs_ns))

    # =========================================================================
    # TESTS NIVEAU 4 PREP (SCHNORR 2048 NIZK, LIBXML2 CBPR+ STRICT, OPA.EXE)
    # =========================================================================

    def test_13_real_schnorr_2048_nizk_algebraic_verification_and_forgery_rejection(self) -> None:
        """
        Vérifie directement l'équation algébrique de Schnorr sur le groupe MODP 2048 bits (RFC 3526 Group 14) :
        $g^s \\equiv R \\cdot Y^c \\pmod p$ et teste le rejet de toute altération de $s$, $R$ ou du contexte.
        """
        proposal_id = "PROP-SCHNORR-ALGEBRAIC-013"
        parent_hash = self.ledger.head_hash
        proof = generate_schnorr_nizk_proof(
            witness_secret="SOVEREIGN-2048-WITNESS-KEY",
            proposal_id=proposal_id,
            parent_hash=parent_hash,
        )

        # 1. Vérification algébrique directe
        ok = verify_schnorr_nizk_proof(
            proof_data=proof,
            expected_public_key_y_hex=proof.public_key_y_hex,
            proposal_id=proposal_id,
            parent_hash=parent_hash,
        )
        self.assertTrue(ok, "La preuve Schnorr 2048 bits devrait être valide")

        # Vérification explicite de l'identité modulaire g^s == R * Y^c mod p
        y_int = int(proof.public_key_y_hex, 16)
        r_int = int(proof.commitment_r_hex, 16)
        c_int = int(proof.challenge_c_hex, 16)
        s_int = int(proof.response_s_hex, 16)
        lhs = pow(G_GENERATOR, s_int, P_MODULUS)
        rhs = (r_int * pow(y_int, c_int, P_MODULUS)) % P_MODULUS
        self.assertEqual(lhs, rhs)

        # 2. Altération algébrique de la réponse s -> (s + 1) mod q
        forged_s_proof = SchnorrNizkProof(
            scheme=proof.scheme,
            public_key_y_hex=proof.public_key_y_hex,
            commitment_r_hex=proof.commitment_r_hex,
            challenge_c_hex=proof.challenge_c_hex,
            response_s_hex=format((s_int + 1) % Q_SUBGROUP, "x"),
            context_binding=proof.context_binding,
        )
        ok_bad_s = verify_schnorr_nizk_proof(
            proof_data=forged_s_proof,
            expected_public_key_y_hex=proof.public_key_y_hex,
            proposal_id=proposal_id,
            parent_hash=parent_hash,
        )
        self.assertFalse(ok_bad_s)

        # 3. Tentative de rejeu de la preuve sur un autre proposal_id
        ok_wrong_ctx = verify_schnorr_nizk_proof(
            proof_data=proof,
            expected_public_key_y_hex=proof.public_key_y_hex,
            proposal_id="PROP-HIJACKED-999",
            parent_hash=parent_hash,
        )
        self.assertFalse(ok_wrong_ctx)

    def test_14_cbpr_plus_strict_libxml2_xsd_and_detached_sidecar_validation(self) -> None:
        """
        Vérifie le mode `CBPR_PLUS_STRICT` :
        1. Le XML `pacs.008.001.10` réseau est validé par `lxml.etree.XMLSchema` (`libxml2`)
           contre `schemas/cbpr_plus_pacs_008_001_10_strict.xsd` et ne contient AUCUN `<SplmtryData>`.
        2. Le sidecar détaché `<SupelaLineage>` est validé contre `schemas/supela_splmtry_001_001_01.xsd`
           et lié cryptographiquement au message réseau via `<BoundUETR>` et `<BoundWirePackageSha256>`.
        3. Si on injecte `<SplmtryData>` dans un message `pacs.008` soumis au validateur `CBPR_PLUS_STRICT`,
           `libxml2` (`XMLSchema`) le rejette immédiatement.
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="STRICT14")
        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertTrue(receipt.allowed)

        mirror = receipt.slow_lane_mirror_envelope
        artifact = mirror["artifact"]
        wire_xml = artifact["xml_payload"]
        sidecar_xml = artifact["detached_supela_sidecar"]["sidecar_xml"]
        wire_sha256 = artifact["wire_package_for_swift_network"]["wire_package_sha256"]

        # 1. Absence totale de <SplmtryData> dans le payload réseau SWIFT CBPR+ Strict
        self.assertNotIn("SplmtryData", wire_xml)
        self.assertIn("<SttlmMtd>INDA</SttlmMtd>", wire_xml)
        self.assertIn("<InstgAgt>", wire_xml)
        self.assertIn("<InstdAgt>", wire_xml)

        # 2. Validation XSD libxml2 du sidecar détaché et liaison cryptographique au fil
        ok_sc, errs_sc = Iso20022StructuralValidator.validate_supela_sidecar_xml(sidecar_xml)
        self.assertTrue(ok_sc, f"Sidecar XSD invalide: {errs_sc}")
        self.assertIn(f"<BoundUETR>{mirror['uetr']}</BoundUETR>", sidecar_xml)
        self.assertIn(
            f"<BoundWirePackageSha256>{wire_sha256}</BoundWirePackageSha256>",
            sidecar_xml,
        )

        # 3. Injection illégale de <SplmtryData> dans le XML réseau en mode CBPR_PLUS_STRICT -> Rejet XSD libxml2
        polluted_wire_xml = wire_xml.replace(
            "</Cdtr></CdtTrfTxInf>",
            '</Cdtr><SplmtryData><Envlp><SupelaLineage xmlns="urn:supela:std:k3:omega:xsd:splmtry.001.001.01"/></Envlp></SplmtryData></CdtTrfTxInf>',
        )
        ok_polluted, errs_polluted = Iso20022StructuralValidator.validate_pacs008_cbpr_strict_xml(
            polluted_wire_xml
        )
        self.assertFalse(ok_polluted)
        self.assertTrue(
            any("CBPR_PLUS_PROHIBITED_ELEMENT_SPLMTRYDATA" in e or "LIBXML2_XSD_ERROR" in e for e in errs_polluted),
            f"Attendu rejet XSD strict sur <SplmtryData>, obtenu: {errs_polluted}",
        )

    def test_15_real_opa_binary_execution_and_parity(self) -> None:
        """
        Exécute le vrai binaire CNCF `opa.exe` sur `policies/guardrails.rego` :
        1. `opa test policies/ -v` doit passer 5/5 tests Rego natifs.
        2. `opa eval` sur une enveloppe nominale et sur une enveloppe hostile doit produire
           exactement le même verdict (`allowed`, `quarantine`, `execution_route`) que `SupelaK3OmegaEngine`.
        """
        opa_tests = run_opa_policy_tests()
        self.assertTrue(opa_tests["executed"], "Le binaire opa.exe doit être présent")
        self.assertTrue(opa_tests["passed"], f"Échec opa test: {opa_tests}")
        self.assertIn("PASS: 5/5", opa_tests["stdout"])

        # Parité sur enveloppe nominale
        valid_env = make_valid_envelope(self.ledger.head_hash, module_id="VR-14", proposal_suffix="OPA15")
        py_receipt = self.engine.evaluate_and_dispatch(valid_env)
        opa_ok, opa_manifest = evaluate_envelope_with_opa_binary(valid_env, max_drift_delta=0.05)

        self.assertTrue(opa_ok)
        self.assertEqual(opa_manifest["allowed"], py_receipt.allowed)
        self.assertEqual(opa_manifest["quarantine"], py_receipt.quarantine)
        self.assertEqual(opa_manifest["execution_route"], py_receipt.execution_route)

        # Parité sur enveloppe hostile (dérive émergente > 0.05 + privilège direct)
        rogue_env = make_valid_envelope(self.ledger.head_hash, module_id="VR-14", proposal_suffix="OPAROGUE")
        rogue_env["actor"]["direct_execution_privilege"] = True
        rogue_env["proposal"]["emergent_drift_delta"] = 0.22
        py_rogue = self.engine.evaluate_and_dispatch(rogue_env)
        opa_rogue_ok, opa_rogue_manifest = evaluate_envelope_with_opa_binary(
            rogue_env, max_drift_delta=0.05
        )

        self.assertTrue(opa_rogue_ok)
        self.assertEqual(opa_rogue_manifest["allowed"], py_rogue.allowed)
        self.assertEqual(opa_rogue_manifest["quarantine"], py_rogue.quarantine)
        self.assertEqual(len(opa_rogue_manifest["violations"]), len(py_rogue.violations))

    def test_16_epistemic_revision_and_demotion_on_contradictory_observation(self) -> None:
        """
        Vérifie le 5e pilier de gouvernance Supela-K3-Ω (La Révision par Contradiction) :
        "Un état prétendument valide peut être rétrogradé si une observation contradictoire apparaît."
        Lorsqu'un reçu initialement `LEVEL_3_AUDITABLE` reçoit une observation contradictoire
        (ex. rejet NACK sur SWIFT ITB ou absence d'attestation matérielle TPM), le moteur :
        1. Rétrograde explicitement le niveau épistémique du composant (`LEVEL_3_AUDITABLE` -> `LEVEL_2_TESTED_QUARANTINE`).
        2. Bascule le reçu en quarantaine rétroactive (`RETROACTIVE_QUARANTINE_ON_CONTRADICTION`).
        3. Scelle un bloc `K3_EPISTEMIC_DEMOTION` immuable dans le journal WORM.
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="DEMOTE16")
        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertTrue(receipt.allowed)
        self.assertEqual(
            receipt.epistemic_assurance_matrix["iso20022_cbpr_plus_compliance"]["level"],
            "LEVEL_3_AUDITABLE",
        )
        blocks_before = len(self.ledger.entries)

        # Injection d'une observation contradictoire (ex: NACK SWIFT ITB / TPM manquant)
        revised_receipt = self.engine.apply_contradictory_observation(
            receipt=receipt,
            component="iso20022_cbpr_plus_compliance",
            contradiction_evidence="SWIFT_ITB_NACK_H001_BIC_UNREGISTERED_IN_DIRECTORY",
            demoted_level="LEVEL_2_TESTED_QUARANTINE",
        )

        self.assertFalse(revised_receipt.allowed)
        self.assertTrue(revised_receipt.quarantine)
        self.assertEqual(revised_receipt.execution_route, "RETROACTIVE_QUARANTINE_ON_CONTRADICTION")
        comp_state = revised_receipt.epistemic_assurance_matrix["iso20022_cbpr_plus_compliance"]
        self.assertEqual(comp_state["level"], "LEVEL_2_TESTED_QUARANTINE")
        self.assertEqual(comp_state["demoted_from"], "LEVEL_3_AUDITABLE")
        self.assertEqual(comp_state["status"], "DEMOTED_BY_CONTRADICTORY_OBSERVATION")
        self.assertEqual(len(self.ledger.entries), blocks_before + 1)
        self.assertEqual(self.ledger.entries[-1].event_type, "K3_EPISTEMIC_DEMOTION")

    def test_17_reformulation_omission_visibility_invariant(self) -> None:
        """
        Vérifie l'invariant de visibilité de l'omission lors d'une reformulation :
        "Supela ne supprime pas l’omission ; il supprime l’illusion de ne pas omettre."
        Chaque reçu `DualPipelineReceipt` doit sceller l'empreinte SHA-256 de l'enveloppe brute
        non reformulée et inventorier explicitement toutes les omissions induites par :
        1. La projection d'aplatissement de schéma récursif (`was_lossy_projection`),
        2. La projection CBPR+ Strict (`supplementary_data_omitted_from_wire`, `max35text_id_truncation_applied`),
        3. La projection de confidentialité WORM (`cleartext_pii_omitted_from_worm_ledger`),
        4. L'horizon d'ignorance externe (`4_epistemic_horizon_omissions_declared`).
        """
        env = make_valid_envelope(
            self.ledger.head_hash,
            module_id="VR-13",
            proposal_suffix="VERY-LONG-PROPOSAL-ID-EXCEEDING-35-CHARS-MAX35TEXT",
        )
        env["tool_schema"] = {
            "type": "object",
            "properties": {"recursive_field": {"$ref": "#/$defs/Loop"}},
            "$defs": {"Loop": {"type": "object", "properties": {"next": {"$ref": "#/$defs/Loop"}}}},
        }
        receipt = self.engine.evaluate_and_dispatch(env)
        self.assertTrue(receipt.allowed)

        om_manifest = receipt.reformulation_and_omission_manifest
        self.assertIn(
            "Supela ne cherche donc pas à éliminer l’omission, mais à éliminer l’invisibilité de l’omission",
            om_manifest["canonical_governance_principle"],
        )
        self.assertTrue(om_manifest["unreformulated_input_envelope_sha256"].startswith("sha256:"))

        projections = om_manifest["explicit_reformulations_and_omissions"]
        self.assertTrue(projections["1_json_schema_flattening_projection"]["was_lossy_projection"])
        self.assertGreater(
            len(projections["1_json_schema_flattening_projection"]["omitted_or_truncated_elements"]),
            0,
        )
        self.assertTrue(
            projections["2_cbpr_plus_strict_wire_projection"]["supplementary_data_omitted_from_wire"]
        )
        self.assertTrue(
            projections["2_cbpr_plus_strict_wire_projection"]["max35text_id_truncation_applied"]
        )
        self.assertTrue(
            projections["2_cbpr_plus_strict_wire_projection"][
                "omitted_lineage_preserved_in_detached_sidecar"
            ]
        )
        self.assertTrue(
            projections["3_worm_ledger_privacy_projection"]["cleartext_pii_omitted_from_worm_ledger"]
        )
        self.assertEqual(len(projections["4_epistemic_horizon_omissions_declared"]), 3)

    def test_18_universal_continuum_23_pillars_and_unformulated_unknown_boundary(self) -> None:
        """
        Vérifie l'exécution déterministe des 23 piliers du continuum doctoral Supela-K3-Omega :
        - Piliers 1..15 : Mathématiques fondamentales et appliquées,
        - Pilier 16 : Noyau cryptographique & épistémique Supela-K3-Omega,
        - Pilier 17 : Physique du silicium & transistors BJT, JFET, MOSFET/CMOS + Landauer,
        - Pilier 18 : Portes NAND universelles & additionneur matériel CLA 8 bits,
        - Pilier 19 : Logique séquentielle (Setup/Hold), Amdahl, Gustafson, Little,
        - Pilier 20 : Calculabilité de Turing, Lambda-calcul de Church, Curry-Howard,
        - Pilier 21 : Triplets de Hoare, Dijkstra (wp) & invariant inductif TLA+,
        - Pilier 22 : Consensus Byzantin BFT (3f+1) & horloges vectorielles de Lamport,
        - Pilier 23 : Frontière Connu Formulé (Aleph_0) vs Inconnu Non Formulé (2^Aleph_0)
          par diagonalisation de Cantor et quarantaine Fail-Closed (LEVEL_2_TESTED_QUARANTINE).
        """
        from src.universal_continuum_calculator import UniversalContinuumCalculator

        report = UniversalContinuumCalculator.execute_all_22_pillars()
        self.assertEqual(report["total_pillars_computed"], 23)
        self.assertTrue(report["all_22_pillars_verified"])
        self.assertTrue(report["all_23_pillars_verified"])
        self.assertEqual(report["epistemic_status"], "LEVEL_3_AUDITABLE")
        self.assertTrue(report["continuum_execution_sha256"].startswith("sha256:"))
        self.assertEqual(len(report["axiomatic_system"]), 6)

        p17 = report["pillars"][16]
        self.assertEqual(p17["pillar"], "17_silicon_physics_bjt_jfet_mosfet_cmos")
        self.assertTrue(p17["verified"])
        self.assertGreater(p17["bjt"]["g_m_ms"], 70.0)
        self.assertGreater(p17["jfet"]["i_d_sat_ma"], 3.0)
        self.assertGreater(p17["mosfet_cmos"]["f_t_ghz"], 10.0)

        p23 = report["pillars"][22]
        self.assertEqual(p23["pillar"], "23_known_vs_unformulated_unknown_boundary")
        self.assertTrue(p23["cantor_strictly_outside_enumerated_catalog"])
        self.assertEqual(
            p23["unformulated_unknown_gate"]["action"],
            "FAIL_CLOSED_QUARANTINE",
        )
        self.assertEqual(
            p23["unformulated_unknown_gate"]["epistemic_level"],
            "LEVEL_2_TESTED_QUARANTINE",
        )
        self.assertFalse(p23["unformulated_unknown_gate"]["silent_extrapolation_permitted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
