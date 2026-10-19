"""
Suite de tests unitaires, d'intégration et de tests négatifs cryptographiques/normatifs
pour Supela-K3-Omega (`Supela-2026-Delta`).

Couvre 12 tests vérifiables localement :
- Tests 1 à 8 : Fonctionnement nominal, aplatissement de schémas récursifs, fallback 429,
  quarantaine sur dérive émergente, compilation ISO 20022 / FATF / SWIFT et proxy HTTP local.
- Tests 9 à 12 (Tests Négatifs d'Audit) :
  * Test 9 : Détection d'altération d'un bloc WORM en mémoire ET rejet d'une clé HMAC-ISV erronée.
  * Test 10 : Rejet d'une preuve d'engagement cryptographique (ZKP witness) falsifiée.
  * Test 11 : Blocage anti-rejeu d'un UETR (`UetrReplayViolationError` sur réutilisation de couple proposal_id/parent_hash).
  * Test 12 : Rejet par le validateur structurel ISO 20022 (`Iso20022StructuralValidator`) d'un BIC invalide,
    d'un UETR non-UUIDv4, d'une séquence de balises inversée ou d'un `<SplmtryData>` sans espace de noms dédié.
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

from src.iso_fatf_mirrors import Iso20022StructuralValidator
from src.k3_http_mcp_gateway import SupelaGatewayServer
from src.schema_flattener import (
    detect_recursive_or_unbounded_patterns,
    flatten_tool_schema,
)
from src.supela_k3_engine import SupelaK3OmegaEngine
from src.worm_merkle import (
    SupelaWormLedger,
    WormEntry,
    compute_cryptographic_commitment,
)


def make_valid_envelope(parent_hash: str, module_id: str = "VR-14", proposal_suffix: str = "001") -> dict:
    proposal_id = f"PROP-2026-DELTA-{module_id}-{proposal_suffix}"
    public_commit, proof_token = compute_cryptographic_commitment(
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
            },
            "lineage": {
                "root_anchor": "SUP-0",
                "merkle_parent_hash": parent_hash,
                "isv_seal": "ISV-2026-DELTA-SEALED",
            },
        },
        "validation": {
            "gf_verdict": "SEALED_APPROVED",
            "engine_signatures": ["sig-engine-alpha", "sig-engine-beta"],
            "public_commitment": public_commit,
            "zkp_proof": proof_token,
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
        """Vérifie que le bloc Genesis SUP-0 est scellé et que la chaîne initiale est valide."""
        ok, err = self.ledger.verify_integrity()
        self.assertTrue(ok, f"Le journal Genesis devrait être intègre: {err}")
        self.assertEqual(self.ledger.entries[0].root_anchor, "SUP-0")

    def test_02_nominal_proposal_dual_pipeline(self) -> None:
        """Une proposition IA conforme est exécutée sur la Fast Lane et génère un miroir ISO 20022 camt.053."""
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-14")
        receipt = self.engine.evaluate_and_dispatch(env)

        self.assertTrue(receipt.allowed)
        self.assertFalse(receipt.quarantine)
        self.assertEqual(receipt.execution_route, "DUAL_PIPELINE_DISPATCH")
        self.assertEqual(
            receipt.epistemic_assurance_matrix["zkp_validity"]["status"],
            "SHA256_COMMITMENT_WITNESS_VERIFIED",
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
        """Vérifie la génération et la validation structurelle locale de VR-13, VR-15 et VR-16."""
        r_pacs = self.engine.evaluate_and_dispatch(
            make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="PACS")
        )
        self.assertTrue(r_pacs.allowed)
        xml_pacs = r_pacs.slow_lane_mirror_envelope["artifact"]["xml_payload"]
        self.assertIn("urn:supela:std:k3:omega:xsd:splmtry.001.001.01", xml_pacs)

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
        Vérifie qu'un jeton ZKP ayant le bon préfixe syntaxique (`zkp-snark:sha256-commit:...`)
        mais calculé avec un mauvais secret témoin (witness) est mathématiquement rejeté.
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="FORGED")
        # Injection d'une preuve forgée qui ne correspond pas à `public_commitment`
        _, forged_proof = compute_cryptographic_commitment(
            witness_secret="WRONG-ATTACKER-WITNESS",
            proposal_id=env["proposal_id"],
            parent_hash=self.ledger.head_hash,
        )
        env["validation"]["zkp_proof"] = forged_proof

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
        Test négatif normatif #4 (Validation XSD ISO 20022 & <SplmtryData>) :
        Vérifie que `Iso20022StructuralValidator` rejette :
        - Un code BICFI mal formé (ex. "BADBIC")
        - Une extension `<SplmtryData>` dépourvue d'espace de noms dédié
        - Un ordre de balises XSD invalide (`CdtTrfTxInf` avant `GrpHdr`)
        """
        env = make_valid_envelope(self.ledger.head_hash, module_id="VR-13", proposal_suffix="BADBIC")
        env["proposal"]["parameters"]["debtor_bic"] = "INVALID_BIC_123"
        receipt_bad_bic = self.engine.evaluate_and_dispatch(env)
        self.assertFalse(receipt_bad_bic.allowed)
        self.assertTrue(receipt_bad_bic.quarantine)
        self.assertTrue(
            any("INVALID_BICFI_DbtrAgt" in v for v in receipt_bad_bic.violations)
        )

        # Test direct d'un XML avec extension <SplmtryData> sans namespace qualifié
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
            "<SplmtryData><Envlp><SupelaLineage xmlns=\"\"/></Envlp></SplmtryData>"
            "</CdtTrfTxInf>"
            "</FIToFICstmrCdtTrf></Document>"
        )
        valid_ns, errs_ns = Iso20022StructuralValidator.validate_pacs008_xml(unqualified_xml)
        self.assertFalse(valid_ns)
        self.assertTrue(any("UNQUALIFIED_SPLMTRY_EXTENSION_NS" in e for e in errs_ns))


if __name__ == "__main__":
    unittest.main(verbosity=2)
