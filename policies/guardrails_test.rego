package supela.k3.omega.guardrails_test

import data.supela.k3.omega.guardrails
import rego.v1

# Payload nominal valide (SUP-0 scellé, VR-14 ISO20022, ZKP valide, Schéma plat)
valid_base_input := {
	"actor": {
		"role": "AI_PROPOSAL_GENERATOR",
		"direct_execution_privilege": false,
	},
	"proposal": {
		"module_id": "VR-14",
		"target_environment": "k3s-isolated-sandbox",
		"estimated_impact_score": 25,
		"emergent_drift_delta": 0.02,
		"modifies_worm_ledger": false,
		"lineage": {
			"root_anchor": "SUP-0",
			"merkle_parent_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"isv_seal": "ISV-2026-DELTA-SEALED",
		},
	},
	"validation": {
		"gf_verdict": "SEALED_APPROVED",
		"engine_signatures": ["engine-alpha-sig", "engine-beta-sig"],
		"zkp_proof": "zkp-snark:9f86d081884c7d659a2feaa0c55ad015",
	},
	"tool_schema": {
		"type": "object",
		"properties": {
			"query": {"type": "string"},
		},
	},
	"provider_telemetry": {
		"status": "HEALTHY",
		"primary_model": "gemini-4-argon",
		"error_code": "NONE",
	},
}

mock_limits := {"max_drift_delta": 0.05}

# Test 1 : Proposition nominale valide -> Autorisée sur le double pipeline
test_nominal_proposal_allowed if {
	decision := guardrails.decision_manifest with input as valid_base_input
		with data.supela.limits as mock_limits
	decision.allowed == true
	decision.quarantine == false
	decision.execution_route == "DUAL_PIPELINE_DISPATCH"
	decision.routing.mode == "NOMINAL_FAST_LANE"
}

# Test 2 : Tentative d'exécution directe par l'IA -> Mise en quarantaine immédiate
test_reject_ai_direct_execution_privilege if {
	bad_input := json.patch(valid_base_input, [{"op": "replace", "path": "/actor/direct_execution_privilege", "value": true}])
	decision := guardrails.decision_manifest with input as bad_input
		with data.supela.limits as mock_limits
	decision.allowed == false
	decision.quarantine == true
	decision.execution_route == "QUARANTINE_SINK"
}

# Test 3 : Schéma JSON récursif ($ref circulaire type erreur Meta HTTP 400) -> Rejeté & Sanitization imposée
test_reject_recursive_json_schema if {
	recursive_input := json.patch(valid_base_input, [{
		"op": "replace",
		"path": "/tool_schema",
		"value": {
			"type": "object",
			"properties": {
				"subnode": {"$ref": "#/$defs/Node"},
			},
			"$defs": {
				"Node": {"type": "object"},
			},
		},
	}])
	decision := guardrails.decision_manifest with input as recursive_input
		with data.supela.limits as mock_limits
	decision.allowed == false
	decision.quarantine == true
	"RECURSIVE_JSON_SCHEMA_DETECTED: Tool schema contains circular $ref or $defs (blocks Meta provider HTTP 400)" in decision.violations
}

# Test 4 : Dépassement de quota fournisseur (ex. Nemotron Daily Limit) -> Fallback Souverain scellé sans arrêt
test_quota_exceeded_triggers_sovereign_fallback if {
	quota_input := json.patch(valid_base_input, [
		{"op": "replace", "path": "/provider_telemetry/status", "value": "DEGRADED"},
		{"op": "replace", "path": "/provider_telemetry/error_code", "value": "DAILY_FREE_LIMIT_REACHED"},
	])
	decision := guardrails.decision_manifest with input as quota_input
		with data.supela.limits as mock_limits
	decision.allowed == true
	decision.quarantine == false
	decision.routing.selected_provider == "supela-local-sovereign-v1"
	decision.routing.mode == "DEGRADED_FALLBACK_SEALED"
	decision.execution_route == "DUAL_PIPELINE_DISPATCH"
}

# Test 5 : Dérive émergente inter-modules hors périmètre (emergent_drift_delta > max_drift_delta)
test_emergent_drift_quarantined if {
	drift_input := json.patch(valid_base_input, [{"op": "replace", "path": "/proposal/emergent_drift_delta", "value": 0.12}])
	decision := guardrails.decision_manifest with input as drift_input
		with data.supela.limits as mock_limits
	decision.allowed == false
	decision.quarantine == true
	"BLAST_RADIUS_EXCEEDED: Unapproved sandbox, attempts WORM mutation, or emergent drift delta exceeded" in decision.violations
}
