# Alignement Institutionnel & Matrice de Vérification · Supela-K3-Omega

> **Auteur souverain :** Jean-François Gadbois ([ORCID 0009-0001-5361-6795](https://orcid.org/0009-0001-5361-6795)) · Organisation *Supela K Omega*  
> **Écosystème unifié :** Ce monolithe (`GDS = ⟨D, O, A, γ⟩`) forme un ensemble indissociable avec le moteur exécutable [`gadboisjean1000-arch/omega-zero-4d`](https://github.com/gadboisjean1000-arch/omega-zero-4d) (voir [`MATRICE_CONFORMITE_INSTITUTIONNELLE.md`](https://github.com/gadboisjean1000-arch/omega-zero-4d/blob/main/docs/constitution/MATRICE_CONFORMITE_INSTITUTIONNELLE.md)).

## Matrice Synthétique (Prouvé vs Aligné vs Déclaratif)

| Domaine | Référentiel | Preuve / Contrôle dans `Supela-K3-Omega` | Statut |
|---|---|---|---|
| **Défense / Supply-Chain** | NIST SP 800-218 (SSDF) / SLSA | Binaires CI et `Dockerfile` `opa v1.22.4`, `cosign v3.1.4` & `trivy v0.76.2` épinglés SHA-256 ; signature `--bundle` ; `SECURITY.md` | ✅ Mécanisme prouvé en CI |
| **Gouvernance OSBL & Pyramide Internationale** | *Loi sur les compagnies du Québec* (Partie III), Convention de Berne, Convention de Vienne (CVIM), Convention de New York (1958), Droit matériel suisse (CO), TCB minimal, *Strictum Jus* | [`CADRE_DIRECTEUR_OSBL_VALORISATION.md`](https://github.com/gadboisjean1000-arch/omega-zero-4d/blob/main/docs/constitution/CADRE_DIRECTEUR_OSBL_VALORISATION.md) | 🔷 Cadre directeur documenté |
| **Zero-Trust & Gouvernance** | ISO/IEC 27001 / 42001, NIST AI RMF | `policies/gds_invariants.rego` : quorum recalculé, révocations exclues, anti-rejeu 15 min, cloisonnement inter-tenant | ✅ 13/13 PASS (`opa test`) |
| **Résilience / Souveraineté** | UE NIS2 (2022/2555), DORA (2022/2554), Loi 25 | WORM logique (`IsReadOnly` + append-only SHA-256), idempotence prouvée sur 2 runs (Pester 6/6) | ✅ WORM logique prouvé · 🔷 Aligné |
| **Université & HDR** | ORCID, CFF 1.2.0, Reproductibilité mathématique | `CITATION.cff`, `NOTICE-HDR-ISO-Monolithe-Probant.md`, théorème `VR-Fractal-Ω` vérifié dans `omega-zero-4d/src/omega_zero/supela_math_core.py` | ✅ Vérifié & citable |
| **Silicium & Accréditation** | TPM 2.0 / TEE, Fulcio/OIDC, Audit ISO externe | `make attest` échoue explicitement sans `tpm2_quote` ; `scellement_final: interdit` jusqu'à raccordement | ⏳ Déclaratif (non simulé) |
