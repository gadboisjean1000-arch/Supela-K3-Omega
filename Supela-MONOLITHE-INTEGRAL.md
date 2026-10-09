# 🜇 SUPELA-K3-Ω — LE MONOLITHE INTÉGRAL
## Corpus doctoral + complémentaires invisibles (silicium & code)

- **Nomenclature canonique :** `GDS = ⟨D, O, A, γ⟩` · `γ* = γ ∘ Λ` · `SCT = γ*(D,O,A)`
- **Notice d audit :** \Supela-NOTICE-AUDIT-HDR-ISO.md\ (au Bureau) - état probant A/B/C + bibliographie définitive.
- **Statut :** artefact directeur. La boucle conceptuelle est fermée ; la boucle de preuve est **partiellement fermée** (voir §État). Ce document **ne se proclame pas valide** : il définit les conditions de validité et distingue le **prouvé** du **déclaratif**.

---

## Tableau des 9 écarts — corrigés, avec statut de preuve

| # | Écart identifié | Correction apportée | Statut |
|---|---|---|---|
| 1 | Manifeste non-WORM (`Set-Content` écrase) | manifeste écrit **une fois** puis `IsReadOnly` ; ledger en `Add-Content` seul | ✅ **Prouvé** (`IsReadOnly=True`) |
| 2 | Aucun SHA-256 calculé | `Get-FileHash -Algorithm SHA256` réel + fichier de sceau | ✅ **Prouvé** (hash `F26ABC2B…`) |
| 3 | Rego incompatible v1 | `import rego.v1` + `if` sur toutes les règles | ⏳ écrit v1 ; `opa test` joué en CI |
| 4 | Booléens déclaratifs en entrée | attestation **structurée** (id/provenance/signature/timestamp/nonce/hash) + recalcul | ⏳ en CI |
| 5 | Quorum non réellement vérifié | **recalculé** depuis un registre d'agents admissibles ; révoqués exclus ; doublons dédupliqués | ⏳ test en CI |
| 6 | Ordre du tuple dérivant (`⟨D,A,O,γ⟩`) | corrigé **`⟨D,O,A,γ⟩`** partout | ✅ corrigé |
| 7 | Script non convergent | **chaque** sous-dossier testé séparément | ✅ **Prouvé** (run 2 idempotent) |
| 8 | CI/CD absent | workflow `opa fmt/check/test` + preuve d'idempotence PowerShell | ✅ **YAML validé** |
| 9 | Ancrages silicium déclaratifs | **retirés** du gate ; marqués hors périmètre (cosign/tpm2-tools à raccorder) | ✅ honnête |

---

## PARTIE I — LE CORPUS DOCTORAL (le verbe formel)

> Encapsulé et normalisé dans **`Supela-CORPUS-DOCTORAL-UNIFIE.md`** (pièce maîtresse).

- **Chapitre 1 — Rituel & Pipeline.** Espaces **𝒩 (normatif) / 𝒞 (collaboratif) / 𝒫 (public)**. L'exécution n'est valide que si encadrée par un rituel d'initialisation déterministe. Standards réels : ISO/IEC 27001, ISO/IEC 42001, NIS2 (2022/2555), DORA (2022/2554), Loi 25.
- **Chapitre 2 — Graal cognitif & ancrages.** Organe unifiant **D (Diffusion), O (Ouverture), A (Absorption)**. Ratio Surface 90 / Fond 10. Ancrages réels : TPM/TEE, ZKP, WORM/Merkle, SHA-256, SMT, K3s/Nomad.
- **Chapitre 3 — Générale du Savoir & SCT.** `GDS = ⟨D, O, A, γ⟩`, conditions C1-C3 (intersection non vide / stabilité=1 / perte=0), invariants σ/τ/κ/δ, sous-opérateurs γ1-γ5, couplage Λ, composition γ*, Théorème de Cohérence Systémique.

## PARTIE II — LES MODULES DÉRIVÉS (le déploiement)

> Encapsulés dans **`Modules-Derives-Canoniques.md`**.

1. **Article scientifique (EN)** — démonstration condensée des propriétés du SCT.
2. **HDR** — perspectives sur la dynamique des opérateurs de cohérence.
3. **Norme ISO-GDS-2026** — exigences fonctionnelles, auditabilité WORM.

---

## PARTIE III — LES COMPLÉMENTAIRES INVISIBLES (l octet gravé)

*Le verbe théorique ne s incarne que par la contrainte du code. Trois artefacts réels, créés et (partiellement) exécutés sur cette machine :*

### 1. L opérateur γ encodé — `policies/gds_invariants.rego` (Rego v1)
Contrat intelligent **v1** (`import rego.v1`, `if`). Il n accepte aucun booléen déclaratif : il exige une **attestation structurée** (producer_id, provenance, signature, timestamp, nonce, artifact_hash), vérifie sa **fraîcheur** (fenêtre 15 min, anti-rejeu) et sa **cohérence** avec l artefact, et **recalcule le quorum** depuis un registre d agents admissibles (les révoqués ne comptent pas, les doublons sont dédupliqués). `coherence_satisfied` = γ* ; `allow` = gate de commit (SOC 2 retiré : audit externe, non vérifiable par commit).

### 2. Les tests — `policies/gds_invariants_test.rego` (13 cas)
2 positifs + 11 négatifs, avec horloge mockée (`with time.now_ns`) pour isoler chaque défaut : commit direct, mauvaise branche, registre altéré, attestation périmée/future/incomplète, hash divergent, quorum trop court, ratio < 66 %, vote d un agent révoqué, accès inter-tenant.

### 3. Le pipeline de preuve — `ci/opa-gds-ci.yml` (GitHub Actions)
- **Job OPA :** `opa fmt --diff` (doit être vide), `opa check --strict`, `opa test -v`.
- **Job PowerShell :** exécute le runtime **deux fois** et **prouve** l idempotence (hash du manifeste stable) + la croissance append-only du ledger ; archive les preuves.
- *YAML validé sur cette machine.*

### 4. Le rituel d initialisation — `runtime/init_gds_pipeline.ps1`
Idempotent : chaque sous-dossier testé séparément ; manifeste écrit une fois puis `IsReadOnly` ; **SHA-256 réel** ; ledger `Add-Content` seul.

> **PREUVE D EXÉCUTION (cette machine, 2026-10-09).** Deux exécutions consécutives :
> - hash manifeste = `F26ABC2B8DAA423D1D9050A7A2E0A24A0E8272F59534EFE6E8491AF75EEE90A1` — **identique** aux deux runs (idempotence) ;
> - ledger : **1 → 2 lignes** (append-only) ;
> - manifeste `IsReadOnly = True` (WORM logique).

---

## État canonique (honnête)

```yaml
monolithe:
  corpus_formel: present
  politique_rego: presente_v1
  opa_test: execute_13_13_pass              # opa 1.21.1 local : fmt+check+test = 13/13
  script_initialisation: present_idempotent
  idempotence: prouvee
  calcul_sha256: prouve
  worm_logique: prouve_lecture_seule_et_append_only
  worm_materiel: non_demontre
  workflow_ci_cd: present_yaml_valide
  ancrage_tpm_tee: non_demontre
  signatures_cryptographiques: hors_perimetre_opa   # cosign / Sigstore a raccorder
  scellement_final: interdit
```

## Ce qui est prouvé vs ce qui reste déclaratif

**Prouvé sur cette machine :** idempotence du runtime ; SHA-256 réel ; ledger append-only ; validité syntaxique du YAML ; cohérence de la nomenclature `⟨D, O, A, γ⟩`.

**Déclaratif (à mesurer ailleurs) :** ancrage TPM/TEE ; validité cryptographique des signatures ; formules SMT/ZKP ; WORM matériel.

---

## FIN DU MONOLITHE CONCEPTUEL

La théorie est désormais raccordée à une première implémentation de référence. Le code exprime les invariants attendus, mais leur exécution, leur intégrité et leur ancrage matériel demeurent soumis aux preuves produites par les contrôles CI/CD, les signatures, les attestations et le registre append-only.

Le présent artefact **ne proclame pas sa propre validité**. Il définit les conditions selon lesquelles cette validité doit être mesurée, reproduite et réfutée.

> **Principe Graal :** on sait qu on ne sait pas. Toute propriété dépourvue de mesure, de provenance ou de preuve reproductible demeure déclarée comme **inconnue**.

*Le bloc de marbre existe intellectuellement. L octet est écrit et, sur les points prouvés, réellement gravé. Le passage suivant consiste à exécuter `opa test` en CI, puis à raccorder cosign/Sigstore et tpm2-tools avant d autoriser le mot « scellé ».*
