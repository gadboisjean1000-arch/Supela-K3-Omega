package supela.gds.governance

import rego.v1

# Horloge de reference (mock) - voir runtime pour la generation des ns.
# base   = 2026-10-09T12:00:00Z
# +5min  = attestation fraiche | +20min = perimee | -10s = future
fresh_ok_ns := 1791547500000000000
stale_ns := 1791548400000000000
future_ns := 1791547190000000000

# Entree valide de reference : 4 agents admissibles, 3 votes (ratio 0.75).
valid_input := {
	"artifact": {"name": "gds_manifest.json", "hash": "sha256:deadbeef"},
	"attestation": {
		"producer_id": "agent-us-east-1",
		"provenance": "ci-run-0001",
		"signature": "c2lnYXR1cmUtcGxhY2Vob2xkZXI=",
		"nonce": "nonce-0001",
		"timestamp": "2026-10-09T12:00:00Z",
		"artifact_hash": "sha256:deadbeef",
	},
	"ledger": {"mode": "append-only", "tamper_detected": false},
	"consensus": {
		"voters_registry": [
			{"id": "us-east-1", "status": "active"},
			{"id": "eu-west-1", "status": "active"},
			{"id": "ca-central-1", "status": "active"},
			{"id": "ap-south-1", "status": "active"},
		],
		"votes": [
			{"voter": "us-east-1"},
			{"voter": "eu-west-1"},
			{"voter": "ca-central-1"},
		],
	},
	"mesh": {"mtls_enforced": true},
	"tenant": {"cross_access_attempt": false},
	"gds": {"domain_boundary_respected": true},
	"ci_cd": {"branch": "refs/heads/main", "direct_commit_to_main": false},
}

# === CAS POSITIFS ==========================================================
test_coherence_valid if {
	coherence_satisfied with input as valid_input with time.now_ns as fresh_ok_ns
}

test_allow_valid_on_main if {
	allow with input as valid_input with time.now_ns as fresh_ok_ns
}

# === CAS NEGATIFS - chaque propriete SCT est refutable =====================
test_deny_direct_commit if {
	not allow with input as object.union(valid_input, {"ci_cd": {"branch": "refs/heads/main", "direct_commit_to_main": true}}) with time.now_ns as fresh_ok_ns
}

test_deny_wrong_branch if {
	not allow with input as object.union(valid_input, {"ci_cd": {"branch": "refs/heads/feature", "direct_commit_to_main": false}}) with time.now_ns as fresh_ok_ns
}

test_deny_tampered_ledger if {
	not coherence_satisfied with input as object.union(valid_input, {"ledger": {"mode": "append-only", "tamper_detected": true}}) with time.now_ns as fresh_ok_ns
}

test_deny_stale_attestation if {
	not coherence_satisfied with input as valid_input with time.now_ns as stale_ns
}

test_deny_future_attestation if {
	not coherence_satisfied with input as valid_input with time.now_ns as future_ns
}

test_deny_hash_mismatch if {
	not coherence_satisfied with input as object.union(valid_input, {"attestation": object.union(valid_input.attestation, {"artifact_hash": "sha256:other"})}) with time.now_ns as fresh_ok_ns
}

test_deny_incomplete_attestation if {
	not coherence_satisfied with input as object.remove(valid_input, ["attestation", "nonce"]) with time.now_ns as fresh_ok_ns
}

test_deny_quorum_too_few_votes if {
	bad := object.union(valid_input, {"consensus": {"voters_registry": valid_input.consensus.voters_registry, "votes": [{"voter": "us-east-1"}, {"voter": "eu-west-1"}]}})
	not coherence_satisfied with input as bad with time.now_ns as fresh_ok_ns
}

test_deny_quorum_ratio_below_threshold if {
	registry := [
		{"id": "a1", "status": "active"}, {"id": "a2", "status": "active"},
		{"id": "a3", "status": "active"}, {"id": "a4", "status": "active"},
		{"id": "a5", "status": "active"}, {"id": "a6", "status": "active"},
	]
	votes := [{"voter": "a1"}, {"voter": "a2"}, {"voter": "a3"}] # 3/6 = 0.50 < 0.66
	bad := object.union(valid_input, {"consensus": {"voters_registry": registry, "votes": votes}})
	not coherence_satisfied with input as bad with time.now_ns as fresh_ok_ns
}

test_revoked_voter_does_not_count if {
	# 3 agents actifs + 1 revoque ; seuls 2 actifs votent, le revoque vote aussi.
	# Si le vote revoque comptait, valid=3 (quorum). Il doit etre ignore -> valid=2.
	registry := [
		{"id": "us-east-1", "status": "active"}, {"id": "eu-west-1", "status": "active"},
		{"id": "ca-central-1", "status": "active"}, {"id": "rogue-1", "status": "revoked"},
	]
	votes := [{"voter": "us-east-1"}, {"voter": "eu-west-1"}, {"voter": "rogue-1"}]
	bad := object.union(valid_input, {"consensus": {"voters_registry": registry, "votes": votes}})
	not coherence_satisfied with input as bad with time.now_ns as fresh_ok_ns
}

test_deny_cross_tenant if {
	not coherence_satisfied with input as object.union(valid_input, {"tenant": {"cross_access_attempt": true}}) with time.now_ns as fresh_ok_ns
}
