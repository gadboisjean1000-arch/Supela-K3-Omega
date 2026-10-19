# Trilogie Canonique `Supela‑K3‑Ω` (`Supela‑2026‑Epsilon` | `17/17` Tests) : *Executive Board*, *Master Governance Document* & *N4 Qualification Dossier*

> [!IMPORTANT]
> **Définition Canonique Officielle de `Supela‑K3‑Ω` :**
> **« Supela‑K3‑Ω est désormais un moteur qui n’encode pas seulement ce qu’il affirme, mais le niveau de preuve de chaque affirmation, la nature de chaque reformulation, et les conditions explicites sous lesquelles il doit cesser de croire ce qu’il dit. »**

---

## VERSION I — Résumé « Executive Board » *(Direction Générale, Comité des Risques & Audit Interne)*

### 1. Le Problème Stratégique Résolu : Éliminer le « Faux Vert Normatif » et le Mensonge par Omission
Dans les architectures financières et d'intelligence artificielle classiques, le risque critique n'est pas la panne visible, mais **l'illusion de conformité** : un test logiciel local qui passe au vert et qui laisse croire au Conseil d'Administration qu'une transaction est conforme aux normes interbancaires (SWIFT CBPR+, LCB‑FT/FATF) ou que son journal est matériellement inviolable, alors qu'aucune autorité externe ne l'a encore qualifié.

`Supela‑K3‑Ω` (`Version Supela‑2026‑Epsilon`) résout structurellement ce risque en imposant trois garanties au cœur même de son exécution :
1. **Confinement Zéro‑Confiance de l'IA & Continuité Souveraine** :
   * L'agent IA ne dispose d'aucun privilège d'exécution directe. Toute proposition est filtrée par le binaire officiel CNCF Open Policy Agent (`opa.exe`) et un moteur déterministe.
   * Les schémas d'outils récursifs sont automatiquement aplatis en amont (éliminant les pannes `HTTP 400` chez les fournisseurs LLM) et un disjoncteur bascule sans interruption sur un moteur local souverain en cas de dépassement de quota (`HTTP 429`).
2. **Plafond d'Honnêteté Épistémique (`Niveaux 0 → 5`) & Visibilité des Omissions** :
   * Le système distingue formellement ce qui est *déclaré (`N0`)*, *implémenté (`N1`)*, *testé (`N2`)*, *auditable localement (`N3`)*, *qualifié par un tiers (`N4`)* et *observé en production (`N5`)*.
   * **Interdiction d'auto‑certification** : Le moteur local s'interdit par code de s'auto‑attribuer les niveaux `N4` ou `N5`.
   * **Traçabilité des reformulations** : Toute troncature ou omission imposée par un standard bancaire (retrait des métadonnées propriétaires `<SplmtryData>` sur le réseau SWIFT, troncature à 35 caractères) est inventoriée dans le reçu et conservée dans un *Sidecar* cryptographique détaché.
3. **Rétrogradation Automatique en Cas de Contradiction** :
   * Si une autorité externe (banc d'essai SWIFT, sonde matérielle HSM/TPM) contredit un état antérieurement jugé valide, le moteur rétrograde immédiatement son statut en quarantaine (`N3 → N2`) et grave cet aveu dans sa chaîne de Merkle (`K3_EPISTEMIC_DEMOTION`).

### 2. Tableau de Bord Exécutif des Garanties (`Jalon Epsilon Scellé`)

| Indicateur de Gouvernance | État Vérifié (`Supela‑2026‑Epsilon`) | Niveau Épistémique Actuel | Condition de Passage au `Niveau 4` |
| :--- | :--- | :---: | :--- |
| **Gouvernance des Politiques IA** | Binaire officiel `opa.exe` (`v1.21.1`, `5/5 PASS`) + Parité Python `100 %` | **`LEVEL_3_AUDITABLE`** | Audit d'intégration en environnement cible |
| **Conformité Bancaire ISO 20022 / CBPR+** | Mode `CBPR_PLUS_STRICT` validé par `libxml2` XSD (zéro `<SplmtryData>` sur le fil) | **`LEVEL_3_AUDITABLE`** (`CANDIDATE_UETR`) | Rapport `0 Error` sur **SWIFT MyStandards** + `ACK` sur **SWIFT ITB** |
| **Preuve Cryptographique ZKP** | Protocole $\Sigma$ **Schnorr NIZK 2048 bits** (RFC 3526 Groupe 14) | **`LEVEL_3_AUDITABLE`** | Contre‑audit tiers via [`verify_third_party_standalone.py`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/src/verify_third_party_standalone.py) |
| **Intégrité du Journal & Signatures** | Zéro clé en dur (CSPRNG 256 bits) + Signature GPG Ed25519 détachée (`.asc`) | **`LEVEL_3_AUDITABLE`** | Séquestration **HSM FIPS 140‑3** + Cloud Object Lock `COMPLIANCE` |
| **Couverture Contradictoire** | **17 / 17 Tests Réussis** (incluant falsifications cryptographiques et rétrogradation) | **`17/17 PASSED`** | Maintien de `100 %` de réussite sous audit externe |

---

## VERSION II — « Master Governance Document » *(Charte Constitutionnelle du Référentiel `Supela‑K3‑Ω`)*

### Article 1 — Objet et Définition Canonique
**`Supela‑K3‑Ω`** est un cadre de gouvernance épistémique et d'exécution déterministe dans lequel chaque action, chaque artefact et chaque affirmation de conformité sont soumis à une obligation de preuve graduée, à une contre‑vérification contradictoire et à une règle de révision automatique.

> **Invariant Constitutionnel :**
> *« Supela‑K3‑Ω est un moteur qui n’encode pas seulement ce qu’il affirme, mais le niveau de preuve de chaque affirmation, la nature de chaque reformulation, et les conditions explicites sous lesquelles il doit cesser de croire ce qu’il dit. »*

### Article 2 — Les Quatre Axiomes Opposables
1. **Axiome de Lucidité Épistémique** : *« Nous savons certaines choses. Nous ignorons certaines choses. Nous savons lesquelles. »*
2. **Axiome de Légitimité d'Affirmation** : *« Les autres systèmes cherchent à prouver qu’ils fonctionnent. Supela cherche aussi à prouver qu’ils ont le droit de le prétendre. »*
3. **Axiome de Visibilité de l'Omission** : *« Un système qui reformule ne peut pas éviter l’omission. Supela ne cherche donc pas à éliminer l’omission, mais à éliminer l’invisibilité de l’omission. Il ne garantit pas la perfection de ce qu’il affirme, mais la transparence de ce qu’il sait, de ce qu’il ignore, et de ce qu’il pourrait avoir omis. »* (*« Supela ne supprime pas l’omission ; il supprime l’illusion de ne pas omettre. »*)
4. **Axiome de Révisabilité par Contradiction** : *« Ce n’est pas un système qui cherche à avoir raison ; c’est un système qui cherche à rendre visible pourquoi il pense avoir raison, et quand il devrait cesser de le penser. »*

### Article 3 — Les 5 Dimensions Gouvernées et la Chaîne Opératoire à 9 Étapes
Toute transaction soumise à `Supela‑K3‑Ω` traverse obligatoirement les **neuf étapes** suivantes, gouvernant simultanément **cinq dimensions** :

$$\underbrace{\text{1. Proposition} \rightarrow \text{2. Politique} \rightarrow \text{3. Exécution bornée}}_{\text{I. L'Exécution}} \rightarrow \underbrace{\text{4. Artefact} \rightarrow \text{5. Preuve}}_{\text{II. La Preuve}} \rightarrow \underbrace{\text{6. Contre-vérification}}_{\text{IV. La Contradiction}} \rightarrow \underbrace{\text{7. Statut épistémique} \rightarrow \text{8. Publication vérifiable}}_{\text{III. La Qualification}} \rightarrow \underbrace{\text{9. Révision possible}}_{\text{V. La Révision}}$$

### Article 4 — Échelle des Niveaux de Connaissance (`LEVEL_0` à `LEVEL_5`)
* **`LEVEL_0_DECLARED`** : Spécifié dans la documentation, sans implémentation.
* **`LEVEL_1_IMPLEMENTED`** : Implémenté dans le code, non exercé par des tests contradictoires.
* **`LEVEL_2_TESTED_QUARANTINE`** : Exercé par des tests locaux ou rétrogradé en quarantaine suite à une contradiction.
* **`LEVEL_3_AUDITABLE`** *(Plafond Local Strict)* : Scellé dans un bundle reproductible accompagné de preuves algébriques (Schnorr 2048 bits), de validations XSD (`libxml2`), d'évaluations binaires (`opa.exe`) et d'une signature asymétrique détachée (`.asc`) vérifiable par un script tiers sans dépendance.
* **`LEVEL_4_THIRD_PARTY_QUALIFIED`** *(Auto‑attribution interdite)* : Qualifié par un rapport signé d'une autorité ou d'un banc d'essai externe officiel (SWIFT MyStandards, SWIFT ITB, HSM FIPS 140‑3, Auditeur ZKP).
* **`LEVEL_5_OBSERVED_IN_PRODUCTION`** *(Auto‑attribution interdite)* : Observé de bout en bout en production réelle (persistance interbancaire de l'UETR sur le SWIFT GPI Tracker, attestation matérielle TPM/HSM continue) avec rétrogradation temps réel `N5 → N2` à la moindre anomalie.

### Article 5 — Loi Formelle de Reformulation ($\hat{\pi}$) et de Rétrogradation (`apply_contradictory_observation`)
1. **Loi de Reformulation Certifiée** : Toute projection réductrice $\pi(x)$ (aplatissement JSON Schema, profilage `CBPR_PLUS_STRICT`, masquage PII WORM) doit produire dans [`DualPipelineReceipt.reformulation_and_omission_manifest`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/src/supela_k3_engine.py#L368-L415) le quadruplet :
   $$\hat{\pi}(x) = \Big(\pi(x),\; \operatorname{SHA256}(x),\; \Delta_{\text{omis}}(x),\; \mathcal{H}_{\text{ext}}\Big)$$
2. **Loi de Rétrogradation Scellée** : Toute observation contradictoire invoquant [`apply_contradictory_observation()`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/src/supela_k3_engine.py#L436-L485) dégrade immédiatement le niveau épistémique du composant concerné, bascule la route sur `RETROACTIVE_QUARANTINE_ON_CONTRADICTION` et inscrit un bloc `K3_EPISTEMIC_DEMOTION` irréversible dans l'arbre de Merkle `SUP‑0`.

---

## VERSION III — « N4 Qualification Dossier » *(Bordereau Technique pour Évaluateurs Tiers SWIFT, ZKP & HSM)*

### 1. Identifiants Cryptographiques du Jalon Soumis à Qualification (`v2026.10.19-epsilon-level4-prep`)

| Paramètre du Dossier | Valeur Exacte / Empreinte `SHA‑256` | Statut |
| :--- | :--- | :---: |
| **Branche & Tag Git Signés GPG** | Branche `supela-2026-epsilon-level4-prep` / Tag `v2026.10.19-epsilon-level4-prep` | **`Verified: true` (GitHub API)** |
| **Commit Final (`17/17` Tests)** | `3bfdf70f71fd1c849fdf129340b425714fd61c12` | **`Verified: true` (Ed25519)** |
| **Clé Publique GPG du Signataire** | `962E7595BA84F3422646093F83830D7037197404` (`ed25519/83830D7037197404`) | **Active** |
| **Bundle d'Évidence ([`audit_evidence_bundle.json`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/audit_evidence_bundle.json))** | `sha256:20f495d89cf5f2d33091f2468f6d6b76c0ee3778f6236d523f5016f1282088ad` | **`17/17` Tests Réussis** |
| **Signature GPG Détachée ([`audit_evidence_bundle.json.asc`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/audit_evidence_bundle.json.asc))** | `sha256:6d537f9dd3c6094c7c54ec5ad28794ecdbab940bf2b81f5b3b6050c1c177e94a` | **`Good signature` (`gpg --verify`)** |
| **Racine de Merkle WORM (`SUP‑0`)** | `sha256:80d5fa0887f2125a58b485435b0ddad004dd074458ae033ff13be299918cb58d` | **7 Blocs (dont 1 Rétrogradation)** |
| **Candidat UETR Soumis (`VR‑13`)** | `1ba3b8da-5631-45d4-af6c-893f5d49d29b` (`CANDIDATE_UETR_UUIDV4`) | **Prêt pour MyStandards / ITB** |

### 2. Inventaire des 5 Pièces du Pack de Soumission ([`evidence/mystandards_submission_pack/`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/SUBMISSION_MANIFEST.json))

| Réf. | Fichier Autonome | Empreinte `SHA‑256` | Portail / Auditeur Destinataire |
| :---: | :--- | :--- | :--- |
| **P‑01** | [`01_bah_head_001_001_02_strict.xml`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/01_bah_head_001_001_02_strict.xml) | `sha256:29007dc7545bc94f427ab118d374a94d38b004904aa68229c0d4ebc3d3d55d05` | **SWIFT MyStandards Readiness Portal & ITB** |
| **P‑02** | [`02_wire_pacs_008_001_10_strict.xml`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/02_wire_pacs_008_001_10_strict.xml) | `sha256:19da4d0923e50070b2a333b09bb3bbb73d1763d2477d3feaf8d9caa95df05572` | **SWIFT MyStandards Readiness Portal & ITB** (Zéro `<SplmtryData>`) |
| **P‑03** | [`03_wire_camt_053_001_10.xml`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/03_wire_camt_053_001_10.xml) | `sha256:ccf32a54f83bb6ccc96928bfd4530876ed08e0c0654cfeb99c1e6910800dc166` | **SWIFT MyStandards Readiness Portal** |
| **P‑04** | [`04_detached_supela_lineage_sidecar.xml`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/04_detached_supela_lineage_sidecar.xml) | `sha256:4b0ce59c3ddf176fc3dcf837b527e4b3f54ba59d1523b25a33fc37b12059163e` | **Auditeur Bilatéral & WORM** (`BoundUETR = 1ba3b8da-...`) |
| **P‑05** | [`05_schnorr_2048_nizk_proof_vector.json`](file:///C:/Users/Group/.gemini/antigravity/scratch/supela-k3-omega/evidence/mystandards_submission_pack/05_schnorr_2048_nizk_proof_vector.json) | `sha256:3b68ee47c83dc75be09dd69ce836158298100068da4756617ff749e94a4dd933` | **Auditeur Cryptographique Tiers** (RFC 3526 Groupe 14) |

### 3. Protocole d'Exécution pour l'Évaluateur Tiers (Zéro Confiance dans le Code Supela)

```powershell
# Étape 1 : Vérifier la signature asymétrique GPG Ed25519 détachée du bundle
gpg --verify evidence/audit_evidence_bundle.json.asc evidence/audit_evidence_bundle.json

# Étape 2 : Exécuter le vérificateur tiers autonome (n'importe aucun module de src.*)
# -> Vérifie GPG, SHA-256, Merkle WORM, l'équation modulaire 2048 bits g^s == R * Y^c mod p,
#    et la validation C libxml2 XSD des fichiers P-01, P-02 et P-04.
python src/verify_third_party_standalone.py

# Étape 3 : Exécuter la suite contradictoire complète (17/17 tests incluant opa.exe)
python tests/test_supela_k3_omega.py
```

### 4. Grille de Décision d'Homologation `Niveau 4` vs Rétrogradation `Niveau 2`

| Gate d'Homologation Externe | Critère d'Acceptation `LEVEL_4_THIRD_PARTY_QUALIFIED` | Réaction Automatique du Runtime si `FAIL` |
| :--- | :--- | :--- |
| **Gate 1 — SWIFT MyStandards** | Rapport officiel `0 Fatal / 0 Error / 0 Warning` sur **P‑01** + **P‑02** (Usage Guidelines CBPR+ en vigueur). | `apply_contradictory_observation()` $\rightarrow$ `LEVEL_2_TESTED_QUARANTINE` + bloc WORM `K3_EPISTEMIC_DEMOTION`. |
| **Gate 2 — SWIFT ITB (FINplus)** | Réception `FINplus ACK` + `pacs.002.001.12` (`ACCP`/`ACSC`) avec `<OrgnlUETR>1ba3b8da-5631-45d4-af6c-893f5d49d29b</OrgnlUETR>`. | `apply_contradictory_observation()` $\rightarrow$ `LEVEL_2_TESTED_QUARANTINE` + bloc WORM `K3_EPISTEMIC_DEMOTION`. |
| **Gate 3 — Audit ZKP 2048 bits** | Validation indépendante de $Y^q \equiv 1, R^q \equiv 1, g^s \equiv R \cdot Y^c \pmod p$ sur **P‑05** (`verify_third_party_standalone.py` = `true`). | `apply_contradictory_observation()` $\rightarrow$ `LEVEL_1_IMPLEMENTED` + mise en quarantaine. |
| **Gate 4 — Audit HSM & WORM** | Attestation matérielle HSM FIPS 140‑3 (`Exportable=False`) + trace CloudTrail `HTTP 403 AccessDenied` sur suppression Root d'un bloc Object Lock `COMPLIANCE`. | `apply_contradictory_observation()` $\rightarrow$ `LEVEL_2_TESTED_QUARANTINE` + bloc WORM `K3_EPISTEMIC_DEMOTION`. |
