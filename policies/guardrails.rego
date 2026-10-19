package supela.k3.omega.guardrails

import rego.v1

# ============================================================================
# 0. POSTULAT ZERO-TRUST (SUP-0) : Tout est hostile et rejeté par défaut
# ============================================================================
default allow_proposal := false
default quarantine_required := true
default execution_route := "QUARANTINE_SINK"

# Catalogue des modules fractals autorisés (VR-13 à VR-18)
valid_vr_modules := {
	"VR-13": {"domain": "SETTLEMENT_CORE", "max_impact": 30, "requires_zkp": true},
	"VR-14": {"domain": "ISO20022_MIRROR", "max_impact": 40, "requires_zkp": true},
	"VR-15": {"domain": "FATF_AML_SHIELD", "max_impact": 25, "requires_zkp": true},
	"VR-16": {"domain": "SWIFT_BRIDGE_ADAPTER", "max_impact": 35, "requires_zkp": true},
	"VR-17": {"domain": "WORM_MERKLE_LEDGER", "max_impact": 15, "requires_zkp": true},
	"VR-18": {"domain": "AI_PROPOSAL_SANDBOX", "max_impact": 50, "requires_zkp": false},
}

# Environnements d'exécution confinés autorisés (K3s / Nomad)
allowed_sandboxes := {"k3s-isolated-sandbox", "nomad-sealed-cell"}

# ============================================================================
# 1. VALIDATION DE LA PROPOSITION IA (Chaînage SUP-0 & Confinement)
# ============================================================================
allow_proposal if {
	is_valid_proposal_generator
	has_valid_ontological_lineage
	has_multi_engine_consensus
	has_valid_vr_module_constraints
	valid_blast_radius
	not has_recursive_schema(input.tool_schema)
	count(violation_reasons) == 0
}

is_valid_proposal_generator if {
	input.actor.role == "AI_PROPOSAL_GENERATOR"
	input.actor.direct_execution_privilege == false
}

has_valid_ontological_lineage if {
	input.proposal.lineage.root_anchor == "SUP-0"
	startswith(input.proposal.lineage.merkle_parent_hash, "sha256:")
	count(input.proposal.lineage.merkle_parent_hash) == 71 # "sha256:" + 64 hex chars
	input.proposal.lineage.isv_seal != ""
}

has_multi_engine_consensus if {
	input.validation.gf_verdict == "SEALED_APPROVED"
	count(input.validation.engine_signatures) >= 2
}

has_valid_vr_module_constraints if {
	module_id := input.proposal.module_id
	spec := valid_vr_modules[module_id]
	input.proposal.estimated_impact_score <= spec.max_impact
	zkp_satisfied(spec.requires_zkp)
}

zkp_satisfied(false)

zkp_satisfied(true) if {
	startswith(input.validation.zkp_proof, "zkp-snark:")
}

zkp_satisfied(true) if {
	startswith(input.validation.zkp_proof, "zkp-schnorr-2048:")
}

valid_blast_radius if {
	input.proposal.target_environment in allowed_sandboxes
	input.proposal.modifies_worm_ledger == false
	input.proposal.emergent_drift_delta <= data.supela.limits.max_drift_delta
}

# ============================================================================
# 2. PRÉVENTION DES ERREURS DE SCHÉMA (Anti-Crash Meta HTTP 400)
# ============================================================================
has_recursive_schema(schema) if {
	some path, value
	walk(schema, [path, value])
	path[count(path) - 1] == "$ref"
	startswith(value, "#")
}

has_recursive_schema(schema) if {
	some path, value
	walk(schema, [path, value])
	key := path[count(path) - 1]
	key in {"$defs", "definitions"}
	count(value) > 0
}

# ============================================================================
# 3. DIAGNOSTIC EXPLICITE DES VIOLATIONS (Traçabilité Audit WORM)
# ============================================================================
violation_reasons contains "ACTOR_PRIVILEGE_VIOLATION: AI actor must be AI_PROPOSAL_GENERATOR without direct execution privilege" if {
	not is_valid_proposal_generator
}

violation_reasons contains "ONTOLOGICAL_LINEAGE_BROKEN: Missing SUP-0 anchor, valid sha256 Merkle parent, or ISV seal" if {
	not has_valid_ontological_lineage
}

violation_reasons contains "CONSENSUS_FAILURE: Requires GF verdict SEALED_APPROVED and >= 2 engine signatures" if {
	not has_multi_engine_consensus
}

violation_reasons contains "VR_MODULE_CONSTRAINT_BREACH: Unknown VR module, impact exceeds module ceiling, or missing ZKP proof" if {
	not has_valid_vr_module_constraints
}

violation_reasons contains "BLAST_RADIUS_EXCEEDED: Unapproved sandbox, attempts WORM mutation, or emergent drift delta exceeded" if {
	not valid_blast_radius
}

violation_reasons contains "RECURSIVE_JSON_SCHEMA_DETECTED: Tool schema contains circular $ref or $defs (blocks Meta provider HTTP 400)" if {
	has_recursive_schema(input.tool_schema)
}

# ============================================================================
# 4. CIRCUIT-BREAKER & ROUTAGE SOUVERAIN (Gestion des Quotas & Pannes Tiers)
# ============================================================================
provider_routing_decision := route if {
	input.provider_telemetry.status == "HEALTHY"
	not has_recursive_schema(input.tool_schema)
	route := {
		"selected_provider": input.provider_telemetry.primary_model,
		"mode": "NOMINAL_FAST_LANE",
		"worm_audit_flag": "STANDARD",
	}
} else := route if {
	input.provider_telemetry.error_code in {"QUOTA_EXCEEDED", "HTTP_429", "DAILY_FREE_LIMIT_REACHED"}
	route := {
		"selected_provider": "supela-local-sovereign-v1",
		"mode": "DEGRADED_FALLBACK_SEALED",
		"worm_audit_flag": "QUOTA_FALLBACK_TRIGGERED",
	}
} else := route if {
	has_recursive_schema(input.tool_schema)
	route := {
		"selected_provider": input.provider_telemetry.primary_model,
		"mode": "REQUIRE_SCHEMA_FLATTENING_GATE",
		"worm_audit_flag": "SCHEMA_SANITIZATION_ENFORCED",
	}
} else := {
	"selected_provider": "NONE",
	"mode": "CIRCUIT_OPEN_QUARANTINE",
	"worm_audit_flag": "CRITICAL_PROVIDER_ANOMALY",
}

# ============================================================================
# 5. DÉCISION FINALE D'ORCHESTRATION K3 (Gouvernance Duale)
# ============================================================================
quarantine_required := false if allow_proposal

execution_route := "DUAL_PIPELINE_DISPATCH" if {
	allow_proposal
	provider_routing_decision.mode in {"NOMINAL_FAST_LANE", "DEGRADED_FALLBACK_SEALED"}
}

decision_manifest := {
	"allowed": allow_proposal,
	"quarantine": quarantine_required,
	"execution_route": execution_route,
	"violations": violation_reasons,
	"routing": provider_routing_decision,
	"normative_layers": {
		"fast_lane_k3": allow_proposal,
		"slow_lane_iso_fatf_mirror": allow_proposal,
	},
}
