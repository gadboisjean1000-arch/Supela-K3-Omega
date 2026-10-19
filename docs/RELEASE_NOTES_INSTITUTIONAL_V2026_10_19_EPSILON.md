# Note de Version Institutionnelle — `Supela-2026-Epsilon` (`v2026.10.19-epsilon-level4-prep`)

**Système** : `Supela-K3-Ω` (*Architecture Épistémique & Rail Interbancaire ISO 20022 CBPR+ Strict*)  
**Branche** : `supela-2026-epsilon-level4-prep`  
**Tag GPG Annoté** : `v2026.10.19-epsilon-level4-prep`  
**Baseline Niveau 3 Gelée** : `supela-2026-delta-level3` / `v2026.10.19-delta-level3` (`be3a4eb3cef8e0fecc7e6dac7161e2e2b79b6e59`)  
**Statut Épistémique Local** : `LEVEL_3_AUDITABLE` (*Pré-Qualifiable Niveau 4 — Zéro Auto-Attribution de N4/N5*)  
**Suite de Tests Unitaires, Contradictoires & Non-Exhaustivité** : `20/20 PASSED`

---

## 1. Objet de la Version Institutionnelle

La version **`v2026.10.19-epsilon-level4-prep`** scelle la transition architecturale entre un moteur localement auditable (**Niveau 3**) et un système prêt pour la qualification externe par des autorités tierces (**Niveau 4** : portails SWIFT MyStandards / Integration Testbed, HSM FIPS 140-3, auditeurs cryptographiques indépendants).

Elle unifie en un continuum exécutable **les 23 piliers formels** — des mathématiques fondamentales et appliquées (Piliers 1 à 15), au noyau cryptographique et épistémique Supela-K3-$\Omega$ (Pilier 16), à la physique du silicium et des trois familles de transistors **BJT, JFET et MOSFET/CMOS** (Pilier 17), aux portes universelles $\mathrm{NAND}$ et additionneurs matériels CLA (Pilier 18), à l'architecture CPU et aux lois d'échelle (Pilier 19), à la calculabilité de Turing et à l'isomorphisme de Curry-Howard (Pilier 20), à la vérification formelle de Hoare/Dijkstra/TLA+ (Pilier 21), au consensus Byzantin BFT (Pilier 22), jusqu'à la **Frontière de l'Inconnu Non Formulé et de la Non-Exhaustivité** (Pilier 23).

---

## 2. Les 6 Nouveautés Majeures Livrées et Vérifiées

### 2.1 Durcissement Cryptographique & Élimination des Secrets Statiques
* **Zéro clé secrète en dur** dans [`src/worm_merkle.py`](../src/worm_merkle.py) : génération CSPRNG éphémère 256 bits (`secrets.token_bytes(32)`) ou injection externe via `SUPELA_ISV_SECRET_KEY`, n'exposant que l'empreinte irréversible `key_fingerprint_sha256`.
* **Preuve à divulgation nulle de connaissance (NIZK) de Schnorr 2048 bits** ([`src/schnorr_zkp.py`](../src/schnorr_zkp.py)) sur le sous-groupe d'ordre premier $q = (p-1)/2$ du groupe MODP IETF RFC 3526 (Groupe 14) :
  $$g^s \equiv R \cdot Y^c \pmod p$$
* **Signature asymétrique détachée GPG Ed25519** ([`evidence/audit_evidence_bundle.json.asc`](../evidence/audit_evidence_bundle.json.asc)) scellant le bundle d'audit.

### 2.2 Conformité ISO 20022 `CBPR_PLUS_STRICT` & Validation C `libxml2`
* **Zéro `<SplmtryData>` sur le fil interbancaire SWIFT** (`01_bah_head_001_001_02_strict.xml` + `02_wire_pacs_008_001_10_strict.xml`).
* **Sidecar de lignage détaché** (`04_detached_supela_lineage_sidecar.xml`) lié cryptographiquement au virement par `<BoundUETR>` et `<BoundWirePackageSha256>`.
* Validation XSD stricte par le moteur C `libxml2` (`lxml.etree.XMLSchema`) contre les schémas formels [`schemas/`](../schemas/).

### 2.3 Exécution Réelle du Binaire CNCF Open Policy Agent (`opa.exe`)
* Pont d'exécution réelle [`src/opa_binary_bridge.py`](../src/opa_binary_bridge.py) invoquant `opa.exe eval --fail-defined` sur [`policies/supela_Eas.rego`](../policies/supela_Eas.rego).

### 2.4 Cinquième Dimension Épistémique : Rétrogradation Monotone sur Contradiction
* Méthode [`apply_contradictory_observation`](../src/supela_k3_engine.py) rétrogradant immédiatement tout composant `LEVEL_3_AUDITABLE` vers `LEVEL_2_TESTED_QUARANTINE` (`RETROACTIVE_QUARANTINE_ON_CONTRADICTION`) dès la réception d'une preuve contradictoire (ex. NACK SWIFT ITB, anomalie matérielle) et scellant un bloc `K3_EPISTEMIC_DEMOTION` dans la chaîne de Merkle WORM (`test_16`).

### 2.5 Invariant Entropique de Visibilité de l'Omission
* Manifeste exécutable `reformulation_and_omission_manifest` dans chaque reçu [`DualPipelineReceipt`](../src/supela_k3_engine.py) (`test_17`), déclarant l'empreinte SHA-256 de l'entrée brute non reformulée et inventoriant toutes les pertes de projection ($H(X \mid Y) > 0$).

### 2.6 Calculateur des 23 Piliers, Déclaration de Non-Exhaustivité & Garde-fou sur l'Inconnu Non Formulé
* **Calculateur exécutable** [`src/universal_continuum_calculator.py`](../src/universal_continuum_calculator.py) générant et vérifiant [`evidence/universal_continuum_23_pillars_receipt.json`](../evidence/universal_continuum_23_pillars_receipt.json) contre le schéma formel [`schemas/supela_continuum_23_pillars.schema.json`](../schemas/supela_continuum_23_pillars.schema.json).
* **Déclaration formelle de non-exhaustivité** (`non_exhaustiveness_and_incompleteness_declaration`) : reconnaît la disproportion cardinale entre le domaine formulé dénombrable ($\aleph_0$) et le réel non dénombrable ($2^{\aleph_0}$, mesure de Lebesgue $\mu(\Sigma^*) = 0.0$), interdit toute prétention d'exhaustivité (`completeness_claim_prohibited: true`) et place toute observation non formulée en quarantaine **Fail-Closed** (`LEVEL_2_TESTED_QUARANTINE`, `test_18`, `test_19`, `test_20`).

---

## 3. Matrice des Tests (`20/20 PASSED`)

| ID Test | Domaine Vérifié | Statut |
| :--- | :--- | :--- |
| `test_01` $\rightarrow$ `test_11` | Invariants N3 : Conservation décimale $\mathbb{D}_2$, XSD ISO 20022, Merkle WORM, HMAC CSPRNG, Quarantaine Fail-Closed, Plafond épistémique $L_3$ | `PASS` |
| `test_12` | Preuve NIZK de Schnorr 2048 bits RFC 3526 Groupe 14 & rejet de falsification | `PASS` |
| `test_13` | Exécution réelle du binaire `opa.exe` sur `policies/supela_Eas.rego` | `PASS` |
| `test_14` | Mode `CBPR_PLUS_STRICT` : zéro `<SplmtryData>` sur le fil SWIFT + liaison Sidecar détaché | `PASS` |
| `test_15` | Rejet par `libxml2` d'une injection `<SplmtryData>` en mode strict | `PASS` |
| `test_16` | 5e Dimension : Rétrogradation épistémique $L_3 \to L_{2Q}$ et bloc `K3_EPISTEMIC_DEMOTION` | `PASS` |
| `test_17` | Invariant de visibilité de l'omission (`reformulation_and_omission_manifest`) | `PASS` |
| `test_18` | Calculateur universel des 23 piliers (Mathématiques, Transistors BJT/JFET/MOSFET, ALU CLA, CS, K3-$\Omega$) | `PASS` |
| `test_19` | Tests contradictoires de non-exhaustivité ($\aleph_0$ vs $2^{\aleph_0}$) et quarantaine Fail-Closed sur l'Inconnu Non Formulé | `PASS` |
| `test_20` | Validation formelle du reçu des 23 piliers contre `schemas/supela_continuum_23_pillars.schema.json` | `PASS` |

---

## 4. Vérification Tiers Autonome (Zéro Dépendance Interne)

Tout auditeur externe peut vérifier l'intégralité du dépôt en une seule commande, sans importer aucun module de `src.*` :

```powershell
python src/verify_third_party_standalone.py
```
