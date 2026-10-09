# NOTICE HDR/ISO D'ACCOMPAGNEMENT — MONOLITHE PROBANT
## Artefact souverain, auto-réfutant, scellable uniquement par la preuve matérielle

- **Objet :** présenter le Monolithe à un lecteur HDR ou à un auditeur ISO, en énonçant d'emblée son statut : **cohérent, partiellement prouvé, non scellé**.
- **Règle :** tout fichier cité ici **existe sur le disque** (vérifié le 2026-10-09).
- **Architecte souverain :** Jean-François Gadbois

---

## 1. Nature de l'artefact

Le Monolithe Probant est un **artefact souverain auto-réfutant** : il est conçu pour **refuser** de se proclamer valide tant que ses preuves matérielles ne sont pas raccordées. Toute propriété sans mesure, provenance ou preuve reproductible y est déclarée **inconnue**.

> **Principe Graal :** on sait qu'on ne sait pas. Le système ne peut pas mentir sur lui-même : son `scellement_final` reste à **interdit** jusqu'à exécution des contrôles.

## 2. Nomenclature canonique (rappel)

Système `GDS = ⟨D, O, A, γ⟩` · opérateur **γ** (le Graal) · sous-opérateurs **γ1…γ5** · couplage **Λ = (γ↔F, γ↔X, γ↔Z)** · composition **γ* = γ ∘ Λ** · SCT = `γ*(D, O, A)`.
**D/O/A = Diffusion/Ouverture/Absorption.** Γ strictement réservé au Grand Invariant du corpus.

## 3. Inventaire vérifié (9 fichiers)

| Fichier | Rôle | Taille |
|---|---|---|
| `README.md` | exécution + suite de réfutation + état | 4,2 Ko |
| `monolithe.ps1` | orchestrateur Windows (`Test/Sign/Attest/Verify/Clean`) | 4,5 Ko |
| `Makefile` | orchestrateur POSIX/CI Linux (6 cibles, recettes en TAB) | 1,8 Ko |
| `policies/gds_invariants.rego` | opérateur γ en Rego v1 | 4,0 Ko |
| `tests/gds_invariants_test.rego` | 13 tests de réfutation (2 positifs + 11 négatifs) | 4,4 Ko |
| `tests/init_gds_pipeline.Tests.ps1` | test Pester (idempotence) | 1,8 Ko |
| `runtime/init_gds_pipeline.ps1` | rituel idempotent + SHA-256 réel | 3,9 Ko |
| `ci/opa-gds-ci.yml` | workflow CI (3 jobs : OPA, idempotence, cosign) | 3,9 Ko |
| `Supela-MONOLITHE-INTEGRAL.md` | document maître + clôture | 7,2 Ko |

## 4. État de preuve (mesuré, non proclamé)

| Verrou | Mesure obtenue | Moyen |
|---|---|---|
| Idempotence du runtime | **7/7 tests Pester passés** ; hash stable sur 2 runs | exécution locale |
| SHA-256 réel | calculé par `Get-FileHash` ; identique run 1 / run 2 | exécution locale |
| Ledger append-only | croissance 1 → 2 lignes, jamais écrasé | exécution locale |
| Signature cosign | **`Verified OK`** (v3.1.2, format `--bundle`) | exécution locale |
| Orchestrateur | `Sign → Verify` bout-en-bout OK | exécution locale |
| Makefile | 12 recettes en TAB, 0 espace ; 6 cibles | vérification par code |
| YAML CI | 3 jobs, syntaxe valide | validation Python |
| 13 tests OPA | écrits, non exécutés ici (opa absent) | **à jouer en CI** |
| Ancrage TPM/TEE | non démontré (`tpm2_quote` absent) | **à raccorder** |
| Signatures de production | clés jetables (mécanisme prouvé, pas l'identité) | **Fulcio/OIDC requis** |

## 5. Conditions de scellement

Le mot « scellé » ne pourra être autorisé que lorsque :
1. `opa test` aura été **exécuté vert** en CI ;
2. les signatures seront produites en mode **keyless** (Fulcio/OIDC) ou via KMS ;
3. une **quote TPM réelle** (tpm2-tools, machine pourvue) aura été vérifiée.

Jusqu'alors : **`scellement_final: interdit`**.

## 6. Conclusion

Cet artefact préfère l'honnêteté à l'illusion : boucle conceptuelle **fermée**, boucle de preuve **armée et honnête dans ses limites**. Un lecteur HDR y trouvera une contribution originale assumée et des ancrages réels citables ; un auditeur ISO y trouvera des exigences vérifiables et des mécanismes réfutables.

---

*Notice d'accompagnement — non scellée. Témoin : `Supela-MONOLITHE-INTEGRAL.md`.*
