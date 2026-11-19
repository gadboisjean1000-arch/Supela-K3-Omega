# Politique de Sécurité & Divulgation Coordonnée (`SECURITY.md`)

> **Alignement d'ingénierie :** RFC 9116 (CVD), NIST SP 800-218 (SSDF), ISO/IEC 27001 / 42001.  
> **Discipline Supela :** Ce dépôt **mesure** sa validité sans jamais la proclamer.

---

## 1. Signalement d'une Vulnérabilité

1. **Ne pas ouvrir d'issue publique** pour une faille exploitable ou une fuite de clé.
2. Utiliser **GitHub Private Vulnerability Reporting** (*Security → Advisories → Report a vulnerability*) sur `gadboisjean1000-arch/Supela-K3-Omega`.
3. Inclure le commit SHA exact, un cas de réfutation minimal (`opa test`, Pester ou Dockerfile) et l'invariant GDS impacté (`D`, `O`, `A`, `γ*`).

---

## 2. Contrôles Vérifiés vs Hors Périmètre CI

### Vérifiés mécaniquement en CI
- **OPA Rego v1 (`policies/gds_invariants.rego`)** : 13 tests de réfutation (commit direct interdit, branche `main`, intégrité WORM, anti-rejeu 15 min, hash artefact, quorum recalculé hors révoqués/doublons, cloisonnement Zero-Trust inter-tenant).
- **Chaîne d'approvisionnement CI** : binaires `opa` (`v1.22.4`) et `cosign` (`v3.1.4`) vérifiés par empreinte **SHA-256** avant exécution ; scan de configuration `Dockerfile` par Trivy versionné (`@0.28.0`).
- **Idempotence & WORM logique** : double exécution PowerShell vérifiant la stabilité SHA-256 du manifeste (`IsReadOnly`) et la croissance append-only du ledger (`tests/init_gds_pipeline.Tests.ps1`).
- **Hygiène des secrets** : aucune clé `cosign.key` n'est versionnée ; le CI emploie une clé jetable pour prouver le mécanisme `--bundle`.

### Limites explicites (déclaratif / hors périmètre CI)
- **Ancrage silicium TPM / TEE** : `make attest` et `.\monolithe.ps1 -Task Attest` exigent un TPM matériel (`tpm2_quote`) et échouent honnêtement en son absence.
- **Identité production** : le scellement de production exige **Fulcio/OIDC keyless** ou un **HSM/KMS** dédié.
- **Accréditation officielle** : l'alignement ISO/NIST/NIS2/DORA/Loi 25 relève de l'ingénierie vérifiable et ne constitue pas une certification délivrée par un tiers accrédité.

Voir également la politique sœur du moteur exécutable : [`omega-zero-4d/SECURITY.md`](https://github.com/gadboisjean1000-arch/omega-zero-4d/blob/main/SECURITY.md).
