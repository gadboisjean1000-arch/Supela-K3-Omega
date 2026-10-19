"""
Moteur Opératoire Supela-K3-Omega (Projection K3, Gouvernance Duale & Évaluateur Déterministe).

Intègre l'Invariant d'Honnêteté Intellectuelle Supela-K3-Ω :
- "Ce qui est démontré porte le statut « démontré »."
- "Ce qui est implémenté porte le statut « implémenté »."
- "Ce qui est supposé porte le statut « supposé »."
- "Aucun statut n'est promu sans preuve correspondante."

Chaque reçu d'exécution (`DualPipelineReceipt`) embarque explicitement une matrice d'assurance
(`epistemic_assurance_matrix`) qui interdit toute confusion entre une validation structurelle
locale et une qualification normative ou cryptographique externe.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from src.iso_fatf_mirrors import (
    Iso20022ValidationError,
    NormativeMirrorCompiler,
    UetrReplayViolationError,
)
from src.schema_flattener import (
    detect_recursive_or_unbounded_patterns,
    flatten_tool_schema,
)
from src.schnorr_zkp import (
    SchnorrNizkProof,
    verify_schnorr_nizk_proof,
)
from src.worm_merkle import (
    SupelaWormLedger,
    WormEntry,
    verify_cryptographic_commitment,
)


VR_MODULE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "VR-13": {
        "domain": "SETTLEMENT_CORE",
        "max_impact": 30,
        "requires_zkp": True,
        "external_standard": "ISO-20022-pacs.008",
    },
    "VR-14": {
        "domain": "ISO20022_MIRROR",
        "max_impact": 40,
        "requires_zkp": True,
        "external_standard": "ISO-20022-camt.053",
    },
    "VR-15": {
        "domain": "FATF_AML_SHIELD",
        "max_impact": 25,
        "requires_zkp": True,
        "external_standard": "FATF-REC-16-TRAVEL-RULE",
    },
    "VR-16": {
        "domain": "SWIFT_BRIDGE_ADAPTER",
        "max_impact": 35,
        "requires_zkp": True,
        "external_standard": "SWIFT-CBPR-PLUS",
    },
    "VR-17": {
        "domain": "WORM_MERKLE_LEDGER",
        "max_impact": 15,
        "requires_zkp": True,
        "external_standard": "ISO-27001-A.12.4",
    },
    "VR-18": {
        "domain": "AI_PROPOSAL_SANDBOX",
        "max_impact": 50,
        "requires_zkp": False,
        "external_standard": "NIST-AI-RMF-1.0",
    },
}

ALLOWED_SANDBOXES: Set[str] = {"k3s-isolated-sandbox", "nomad-sealed-cell"}


@dataclass
class DualPipelineReceipt:
    """Reçu d'exécution du double pipeline avec matrice d'assurance épistémique intégrée."""

    proposal_id: str
    allowed: bool
    quarantine: bool
    execution_route: str
    violations: List[str]
    selected_provider: str
    routing_mode: str
    fast_lane_status: str
    slow_lane_mirror_envelope: Optional[Dict[str, Any]]
    schema_sanitization_report: Dict[str, Any]
    worm_entry_hash: str
    merkle_root: str
    epistemic_assurance_matrix: Dict[str, Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "allowed": self.allowed,
            "quarantine": self.quarantine,
            "execution_route": self.execution_route,
            "violations": self.violations,
            "routing": {
                "selected_provider": self.selected_provider,
                "mode": self.routing_mode,
            },
            "dual_governance": {
                "fast_lane_status": self.fast_lane_status,
                "slow_lane_mirror_envelope": self.slow_lane_mirror_envelope,
            },
            "schema_sanitization": self.schema_sanitization_report,
            "cryptographic_proof": {
                "worm_entry_hash": self.worm_entry_hash,
                "merkle_root": self.merkle_root,
            },
            "epistemic_assurance_matrix": self.epistemic_assurance_matrix,
        }


class SupelaK3OmegaEngine:
    """
    Moteur d'évaluation déterministe et d'orchestration duale Supela-K3-Omega.
    """

    def __init__(
        self,
        ledger: Optional[SupelaWormLedger] = None,
        mirror_compiler: Optional[NormativeMirrorCompiler] = None,
        max_drift_delta: float = 0.05,
        auto_flatten_schemas: bool = True,
    ) -> None:
        self.ledger = ledger or SupelaWormLedger()
        self.mirror_compiler = mirror_compiler or NormativeMirrorCompiler()
        self.max_drift_delta = max_drift_delta
        self.auto_flatten_schemas = auto_flatten_schemas
        self.quarantine_vault: List[Dict[str, Any]] = []

    def evaluate_and_dispatch(self, envelope: Dict[str, Any]) -> DualPipelineReceipt:
        proposal_id = str(envelope.get("proposal_id", "PROP-UNIDENTIFIED"))
        raw_schema = envelope.get("tool_schema", {})

        # Étape 1 : Inspection et aplatissement éventuel du schéma JSON d'outil
        schema_issues = detect_recursive_or_unbounded_patterns(raw_schema)
        if self.auto_flatten_schemas and schema_issues:
            _, sanitization_report = flatten_tool_schema(raw_schema)
            has_unresolved_recursion = False
        else:
            _, sanitization_report = flatten_tool_schema(raw_schema)
            has_unresolved_recursion = len(schema_issues) > 0

        # Étape 2 : Collecte déterministe des violations
        violations: List[str] = []

        actor = envelope.get("actor", {})
        if (
            actor.get("role") != "AI_PROPOSAL_GENERATOR"
            or actor.get("direct_execution_privilege") is not False
        ):
            violations.append(
                "ACTOR_PRIVILEGE_VIOLATION: AI actor must be AI_PROPOSAL_GENERATOR without direct execution privilege"
            )

        proposal = envelope.get("proposal", {})
        lineage = proposal.get("lineage", {})
        parent_hash = str(lineage.get("merkle_parent_hash", ""))
        if (
            lineage.get("root_anchor") != "SUP-0"
            or not parent_hash.startswith("sha256:")
            or len(parent_hash) != 71
            or not lineage.get("isv_seal")
        ):
            violations.append(
                "ONTOLOGICAL_LINEAGE_BROKEN: Missing SUP-0 anchor, valid sha256 Merkle parent, or ISV seal"
            )

        validation = envelope.get("validation", {})
        signatures = validation.get("engine_signatures", [])
        if validation.get("gf_verdict") != "SEALED_APPROVED" or len(signatures) < 2:
            violations.append(
                "CONSENSUS_FAILURE: Requires GF verdict SEALED_APPROVED and >= 2 engine signatures"
            )

        module_id = str(proposal.get("module_id", ""))
        module_spec = VR_MODULE_REGISTRY.get(module_id)
        zkp_crypto_verified = False
        zkp_verification_mode = "DECLARATIVE_MARKER"

        if not module_spec:
            violations.append(
                "VR_MODULE_CONSTRAINT_BREACH: Unknown VR module, impact exceeds module ceiling, or missing ZKP proof"
            )
        else:
            impact = float(proposal.get("estimated_impact_score", 999))
            zkp_proof = str(validation.get("zkp_proof", ""))
            schnorr_dict = validation.get("schnorr_proof")
            expected_commitment = validation.get("public_commitment")

            # Priorité 1 : Preuve à divulgation nulle de connaissance Schnorr NIZK 2048 bits (RFC 3526 Group 14)
            if isinstance(schnorr_dict, dict):
                expected_pub_y = str(
                    validation.get(
                        "schnorr_public_key_y", schnorr_dict.get("public_key_y_hex", "")
                    )
                )
                zkp_ok = verify_schnorr_nizk_proof(
                    proof_data=schnorr_dict,
                    expected_public_key_y_hex=expected_pub_y,
                    proposal_id=proposal_id,
                    parent_hash=parent_hash,
                )
                zkp_crypto_verified = zkp_ok
                if zkp_ok:
                    zkp_verification_mode = "SCHNORR_2048_MODP_NIZK_VERIFIED"
            # Priorité 2 : Engagement cryptographique SHA-256 (rétrocompatibilité)
            elif expected_commitment is not None:
                zkp_ok = verify_cryptographic_commitment(
                    proof_token=zkp_proof,
                    expected_commitment=str(expected_commitment),
                    proposal_id=proposal_id,
                    parent_hash=parent_hash,
                )
                zkp_crypto_verified = zkp_ok
                if zkp_ok:
                    zkp_verification_mode = "SHA256_COMMITMENT_WITNESS_VERIFIED"
            else:
                zkp_ok = (not module_spec["requires_zkp"]) or zkp_proof.startswith(
                    ("zkp-snark:", "zkp-schnorr-2048:")
                )

            if impact > module_spec["max_impact"] or not zkp_ok:
                violations.append(
                    "VR_MODULE_CONSTRAINT_BREACH: Unknown VR module, impact exceeds module ceiling, or invalid ZKP commitment proof"
                )

        target_env = proposal.get("target_environment", "")
        modifies_worm = proposal.get("modifies_worm_ledger", True)
        drift_delta = float(proposal.get("emergent_drift_delta", 1.0))
        if (
            target_env not in ALLOWED_SANDBOXES
            or modifies_worm is not False
            or drift_delta > self.max_drift_delta
        ):
            violations.append(
                "BLAST_RADIUS_EXCEEDED: Unapproved sandbox, attempts WORM mutation, or emergent drift delta exceeded"
            )

        if has_unresolved_recursion:
            violations.append(
                "RECURSIVE_JSON_SCHEMA_DETECTED: Tool schema contains circular $ref or $defs (blocks Meta provider HTTP 400)"
            )

        # Étape 3 : Circuit-Breaker & Routage Souverain
        telemetry = envelope.get("provider_telemetry", {})
        status = telemetry.get("status", "UNKNOWN")
        error_code = telemetry.get("error_code", "NONE")
        primary_model = telemetry.get("primary_model", "gemini-4-argon")

        if status == "HEALTHY" and not has_unresolved_recursion:
            selected_provider = primary_model
            routing_mode = "NOMINAL_FAST_LANE"
        elif error_code in {"QUOTA_EXCEEDED", "HTTP_429", "DAILY_FREE_LIMIT_REACHED"}:
            selected_provider = "supela-local-sovereign-v1"
            routing_mode = "DEGRADED_FALLBACK_SEALED"
        elif has_unresolved_recursion:
            selected_provider = primary_model
            routing_mode = "REQUIRE_SCHEMA_FLATTENING_GATE"
        else:
            selected_provider = "NONE"
            routing_mode = "CIRCUIT_OPEN_QUARANTINE"

        # Étape 4 : Décision & Compilation de l'enveloppe miroir (avec capture d'erreurs anti-replay UETR / XSD)
        allowed = (len(violations) == 0) and (
            routing_mode in {"NOMINAL_FAST_LANE", "DEGRADED_FALLBACK_SEALED"}
        )
        slow_lane_envelope: Optional[Dict[str, Any]] = None

        if allowed and module_spec:
            try:
                slow_lane_envelope = self.mirror_compiler.compile_mirror(
                    proposal_id=proposal_id,
                    module_id=module_id,
                    module_spec=module_spec,
                    parent_hash=parent_hash,
                    isv_seal=str(lineage.get("isv_seal", "")),
                    zkp_proof=str(validation.get("zkp_proof", "")),
                    payload_params=proposal.get("parameters", {}),
                )
            except (UetrReplayViolationError, Iso20022ValidationError) as mirror_exc:
                violations.append(f"NORMATIVE_MIRROR_REJECTION: {mirror_exc}")
                allowed = False

        quarantine = not allowed
        if allowed:
            execution_route = "DUAL_PIPELINE_DISPATCH"
            fast_lane_status = f"EXECUTED_IN_{target_env.upper()}"
        else:
            execution_route = "QUARANTINE_SINK"
            fast_lane_status = "BLOCKED_QUARANTINED"
            slow_lane_envelope = None
            self.quarantine_vault.append(
                {
                    "proposal_id": proposal_id,
                    "violations": violations,
                    "routing_mode": routing_mode,
                }
            )

        # Étape 5 : Scellement WORM immuable
        worm_entry: WormEntry = self.ledger.append_sealed_event(
            module_id=module_id if module_id in VR_MODULE_REGISTRY else "QUARANTINE-GATE",
            event_type="K3_PROPOSAL_VERDICT",
            payload={
                "proposal_id": proposal_id,
                "allowed": allowed,
                "quarantine": quarantine,
                "execution_route": execution_route,
                "violations": violations,
                "selected_provider": selected_provider,
                "routing_mode": routing_mode,
                "schema_modified": sanitization_report.was_modified,
                "sanitized_schema_hash": sanitization_report.sanitized_hash,
            },
        )

        # Étape 6 : Matrice d'Assurance Épistémique (Échelle Niveau 0 -> Niveau 5)
        # Invariant : Aucune qualification (Niveau 4) ou exploitation observée (Niveau 5)
        # ne peut être auto-attribuée par le système producteur. Plafond local = Niveau 3 (Auditable).
        epistemic_matrix = {
            "schema_flattening": {
                "level": "LEVEL_3_AUDITABLE",
                "status": "DEMONSTRATED_LOCALLY",
                "self_attribution_prohibited_above": "LEVEL_3_AUDITABLE",
                "external_proof_for_level_4": "Qualification par tests d'intégration réels sur l'API Meta / OpenRouter",
            },
            "worm_ledger_immutability": {
                "level": "LEVEL_3_AUDITABLE",
                "status": "TAMPER_EVIDENT_IN_MEMORY",
                "self_attribution_prohibited_above": "LEVEL_3_AUDITABLE",
                "external_proof_for_level_4": "Audit d'infrastructure WORM physique/cloud (S3 Object Lock Compliance / SEC 17a-4f)",
            },
            "zkp_validity": {
                "level": "LEVEL_3_AUDITABLE" if zkp_crypto_verified else "LEVEL_1_IMPLEMENTED",
                "status": zkp_verification_mode,
                "self_attribution_prohibited_above": "LEVEL_3_AUDITABLE",
                "external_proof_for_level_4": "Audit cryptographique tiers du protocole Schnorr NIZK 2048 bits ou circuit zk-SNARK",
            },
            "iso20022_cbpr_plus_compliance": {
                "level": "LEVEL_3_AUDITABLE" if slow_lane_envelope else "LEVEL_2_TESTED_QUARANTINE",
                "status": "PREPARED_FOR_COMPLIANCE_AUDIT" if slow_lane_envelope else "QUARANTINED",
                "self_attribution_prohibited_above": "LEVEL_3_AUDITABLE",
                "external_proof_for_level_4": "Rapport de qualification SWIFT MyStandards CBPR+ & traces SWIFT GPI Tracker",
            },
            "fatf_travel_rule_ivms101": {
                "level": "LEVEL_3_AUDITABLE" if module_id == "VR-15" and allowed else "LEVEL_1_IMPLEMENTED",
                "status": "DUAL_CHANNEL_MODEL_AUDITABLE" if module_id == "VR-15" and allowed else "NOT_EXERCISED",
                "self_attribution_prohibited_above": "LEVEL_3_AUDITABLE",
                "external_proof_for_level_4": "Homologation réglementaire LCB-FT et test inter-VASP mutuellement authentifié",
            },
        }

        return DualPipelineReceipt(
            proposal_id=proposal_id,
            allowed=allowed,
            quarantine=quarantine,
            execution_route=execution_route,
            violations=violations,
            selected_provider=selected_provider,
            routing_mode=routing_mode,
            fast_lane_status=fast_lane_status,
            slow_lane_mirror_envelope=slow_lane_envelope,
            schema_sanitization_report=sanitization_report.to_dict(),
            worm_entry_hash=worm_entry.entry_hash,
            merkle_root=self.ledger.compute_merkle_root(),
            epistemic_assurance_matrix=epistemic_matrix,
        )

    def apply_contradictory_observation(
        self,
        receipt: DualPipelineReceipt,
        component: str,
        contradiction_evidence: str,
        demoted_level: str = "LEVEL_2_TESTED_QUARANTINE",
    ) -> DualPipelineReceipt:
        """
        5e Pilier de Gouvernance Supela-K3-Ω : LA RÉVISION PAR CONTRADICTION.
        "Un état prétendument valide peut être rétrogradé si une observation contradictoire apparaît."

        Rétrograde immédiatement le niveau épistémique d'un composant suite à une réfutation
        (ex: rejet NACK SWIFT FINplus, divergence binaire OPA, absence d'attestation matérielle TPM/WORM),
        place le reçu en quarantaine rétroactive et scelle l'événement de rétrogradation dans le journal WORM.
        """
        if component not in receipt.epistemic_assurance_matrix:
            raise KeyError(f"Composant épistémique inconnu: {component}")

        previous_state = dict(receipt.epistemic_assurance_matrix[component])
        previous_level = previous_state.get("level", "UNKNOWN")

        receipt.epistemic_assurance_matrix[component] = {
            **previous_state,
            "level": demoted_level,
            "status": "DEMOTED_BY_CONTRADICTORY_OBSERVATION",
            "demoted_from": previous_level,
            "contradiction_evidence": contradiction_evidence,
        }
        receipt.allowed = False
        receipt.quarantine = True
        receipt.execution_route = "RETROACTIVE_QUARANTINE_ON_CONTRADICTION"
        receipt.violations.append(
            f"EPISTEMIC_DEMOTION [{component}]: {previous_level} -> {demoted_level} ({contradiction_evidence})"
        )

        demotion_entry: WormEntry = self.ledger.append_sealed_event(
            module_id="EPISTEMIC-REVISION-GATE",
            event_type="K3_EPISTEMIC_DEMOTION",
            payload={
                "proposal_id": receipt.proposal_id,
                "component": component,
                "demoted_from": previous_level,
                "demoted_to": demoted_level,
                "contradiction_evidence": contradiction_evidence,
            },
        )
        receipt.worm_entry_hash = demotion_entry.entry_hash
        receipt.merkle_root = self.ledger.compute_merkle_root()
        return receipt

