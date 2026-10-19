# Supela‑K3‑Ω (`Supela-2026-Δ`) — Architecture de Référence & Moteur d'Exécution

Implémentation exécutable de l'écosystème normatif **Supela‑EaaS‑K3‑Ω**, fondée sur :
1. **Rigueur normative & Chaînage ontologique (`SUP-0`)** : Journal immuable WORM (Arbre de Merkle SHA-256 + sceau HMAC-ISV).
2. **Confinement Zero-Trust de l'IA** : L'IA est strictement bornée au rôle de `AI_PROPOSAL_GENERATOR` sans privilège d'exécution directe.
3. **Gouvernance Duale (Fast Lane / Slow Lane)** : Exécution rapide dans les cellules isolées (`k3s-isolated-sandbox`, `nomad-sealed-cell`) couplée à la génération asynchrone d'enveloppes miroirs d'opposabilité universelle (`ISO 20022`, `FATF/GAFI`, `SWIFT`) avec contrat de compensation.
4. **Anticorps d'Infrastructure (Schema Flattener & Circuit-Breaker)** :
   - Neutralisation proactive de l'erreur `HTTP 400 : Recursive JSON schemas are not currently supported` (fournisseur Meta) via aplatissement statique des références `$ref`/`$defs` et scellement des objets ouverts.
   - Continuité opératoire sur erreur `Daily free model limit reached` via bascule déterministe vers le moteur souverain de secours.

## Structure du Projet

- `policies/guardrails.rego` : Politique **Open Policy Agent (OPA / Rego v1)** définissant les règles de validation, le budget de dérive émergente et le routage fournisseur.
- `policies/guardrails_test.rego` : Suite de tests unitaires Rego (`opa test policies/ -v`).
- `src/worm_merkle.py` : Journal immuable WORM, arbre de Merkle et vérification d'intégrité `SUP-0`.
- `src/schema_flattener.py` : Passerelle d'aplatissement de schémas JSON récursifs et de verrouillage des objets génériques (MCP / Function Calling).
- `src/supela_k3_engine.py` : Moteur opératoire K3-Omega (évaluation Zero-Trust, gouvernance duale et mise en quarantaine).
- `tests/test_supela_k3_omega.py` : Simulation en direct et suite de tests unitaires Python (100 % bibliothèque standard, zéro dépendance tierce).

## Exécution

```powershell
python tests/test_supela_k3_omega.py
```
