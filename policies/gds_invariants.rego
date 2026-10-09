# ---------------------------------------------------------------------------
# Generale du Savoir (GDS) - operateur de coherence gamma encode en politique
# Nomenclature canonique : GDS = <D, O, A, gamma>
#   D = Diffusion | O = Ouverture | A = Absorption | gamma = operateur de coherence
# Rego v1. Ce module EXPRIME les conditions C1-C3 et les proprietes SCT comme
# regles verifiables. Il ne se proclame pas valide : il definit les conditions
# de validite et laisse au pipeline CI le soin de les mesurer et de les refuter.
# ---------------------------------------------------------------------------
package supela.gds.governance

import rego.v1

# Fenetre de fraicheur des attestations : 15 minutes, en nanosecondes.
max_attestation_age_ns := 900000000000

# --- Preuve 1 : completude de l attestation (anti booleen declaratif) -------
# Toute propriete doit etre PORTEE par une attestation tracable, pas affirmee.
attestation_complete if {
	att := input.attestation
	att.producer_id != ""
	att.provenance != ""
	att.signature != ""
	att.nonce != ""
	att.timestamp != ""
	att.artifact_hash != ""
}

# --- Preuve 2 : fraicheur (anti-rejeu temporel) -----------------------------
attestation_fresh if {
	age_ns := time.now_ns() - time.parse_rfc3339_ns(input.attestation.timestamp)
	age_ns >= 0 # horodatage non situe dans le futur
	age_ns <= max_attestation_age_ns
}

# --- Preuve 3 : l attestation couvre le bon artefact -----------------------
attestation_hash_matches if {
	input.attestation.artifact_hash == input.artifact.hash
}

# --- Invariant O (Ouverture) : registre append-only non altere --------------
worm_immutable if {
	input.ledger.mode == "append-only"
	input.ledger.tamper_detected == false
}

# --- Invariant D (Diffusion) : cloisonnement Zero-Trust des tenants ---------
tenant_isolated if {
	input.mesh.mtls_enforced == true
	input.tenant.cross_access_attempt == false
}

# --- Invariant A (Absorption) : quorum RECALCULE (pas declare) --------------
# Le quorum n accepte pas un pourcentage fourni : il le recalcule depuis un
# registre d agents admissibles et une liste de votes. Les agents revoques
# ne comptent pas ; les doublons sont dedupliques par le set.
admissible_voters contains voter_id if {
	some voter in input.consensus.voters_registry
	voter.status == "active"
	voter_id := voter.id
}

valid_votes contains vote.voter if {
	some vote in input.consensus.votes
	admissible_voters[vote.voter]
}

quorum_ratio := count(valid_votes) / n if {
	n := count(admissible_voters)
	n > 0
}

quorum_valid if {
	count(admissible_voters) > 0
	count(valid_votes) >= 3
	quorum_ratio >= 0.66
}

# --- Operateur gamma* : synthese de coherence (SCT) -------------------------
# gamma* est satisfait ssi toutes les preuves et invariants tiennent.
coherence_satisfied if {
	worm_immutable # O : ouverture sans alteration
	tenant_isolated # D : diffusion cloisonnee
	quorum_valid # A : absorption par consensus prouve
	attestation_complete # provenance tracable
	attestation_fresh # anti-rejeu
	attestation_hash_matches # integrite de l artefact
	input.gds.domain_boundary_respected
}

# --- Barriere de commit CI/CD (gate gamma) ----------------------------------
# Note honnete : SOC 2 est un audit externe periodique, PAS une propriete
# verifiable par commit ; il est retire de ce gate (defaut booleen declaratif).
# Branche cible et interdiction de commit direct sont structurelles.
allow if {
	input.ci_cd.branch == "refs/heads/main"
	input.ci_cd.direct_commit_to_main == false
	coherence_satisfied
}

# --- Ce que cette politique NE fait PAS (transparence) ----------------------
# - Elle ne verifie pas la validite CRYPTOGRAPHIQUE de attestation.signature ;
#   c est le role d un verificateur en amont (ex. cosign / Sigstore). Elle
#   verifie la presence, la fraicheur et la coherence des preuves.
# - Elle ne cree pas de stockage WORM materiel ; elle lit un etat de registre
#   produit en amont. L immutabilite physique reste a la charge du runtime.
