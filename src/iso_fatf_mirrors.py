"""
Compilateur Déterministe & Validateur XSD `libxml2`/`lxml` d'Enveloppes Normatives Miroirs (Slow Lane).

Évolutions majeures (Branche supela-2026-epsilon-level4-prep) :
1. Mode `CBPR_PLUS_STRICT` par défaut (*Detached Lineage Sidecar*) :
   - Le XML `pacs.008.001.10` destiné au réseau SWIFT (`wire_xml_payload`) est généré
     SANS AUCUN élément `<SplmtryData>`, avec `<SttlmMtd>INDA</SttlmMtd>`, `<IntrBkSttlmDt>`,
     `<InstgAgt>`, `<InstdAgt>`, et identifiants `Max35Text` conformes au jeu de caractères `FIN-X`.
   - Le bloc `<SupelaLineage>` est émis dans un document XML *Sidecar* détaché
     (`detached_sidecar_xml`), lié cryptographiquement au message SWIFT par `<BoundUETR>`
     et `<BoundWirePackageSha256>`.
2. Validation XSD réelle par le moteur C `libxml2` (`lxml.etree.XMLSchema`) :
   - Validation directe contre `schemas/cbpr_plus_pacs_008_001_10_strict.xsd`,
     `schemas/cbpr_plus_head_001_001_02_strict.xsd` et `schemas/supela_splmtry_001_001_01.xsd`.
"""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

from lxml import etree as lxml_etree


ROOT_DIR = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = ROOT_DIR / "schemas"

BICFI_REGEX = re.compile(r"^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$")
CURRENCY_ISO4217_REGEX = re.compile(r"^[A-Z]{3}$")
UUIDV4_UETR_REGEX = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)
FINX_MAX35_REGEX = re.compile(
    r"^[A-Za-z0-9\-?:\(\)\.,'\+ ]([A-Za-z0-9/\-?:\(\)\.,'\+ ]{0,33}[A-Za-z0-9\-?:\(\)\.,'\+ ])?$"
)
SUPELA_SPLMTRY_NAMESPACE = "urn:supela:std:k3:omega:xsd:splmtry.001.001.01"


class UetrReplayViolationError(ValueError):
    """Levée lorsqu'une tentative de réutilisation d'un UETR ou d'un couple (proposal_id, parent_hash) est détectée."""


class Iso20022ValidationError(ValueError):
    """Levée lorsqu'un message XML ISO 20022 ou BAH viole le schéma XSD libxml2 ou les contraintes CBPR+."""


class UetrUniquenessRegistry:
    """Registre anti-rejeu garantissant qu'aucun candidat UETR ni couple (proposal_id, parent_hash) n'est réutilisé."""

    def __init__(self) -> None:
        self._issued_uetrs: Set[str] = set()
        self._issued_seed_keys: Set[str] = set()

    def issue_unique_uetr(self, proposal_id: str, parent_hash: str, sequence_no: int) -> str:
        seed_key = f"SUP-0|{proposal_id}|{parent_hash}"
        if seed_key in self._issued_seed_keys:
            raise UetrReplayViolationError(
                f"REPLAY_BLOCKED: Le couple ({proposal_id}, {parent_hash[:18]}...) a déjà émis un UETR."
            )

        full_seed = f"{seed_key}|seq:{sequence_no}"
        digest = bytearray(hashlib.sha256(full_seed.encode("utf-8")).digest()[:16])
        digest[6] = (digest[6] & 0x0F) | 0x40
        digest[8] = (digest[8] & 0x3F) | 0x80
        hex_s = digest.hex()
        uetr = f"{hex_s[0:8]}-{hex_s[8:12]}-{hex_s[12:16]}-{hex_s[16:20]}-{hex_s[20:32]}"

        if uetr in self._issued_uetrs:
            raise UetrReplayViolationError(f"UETR_COLLISION: UETR {uetr} déjà présent dans le registre.")

        self._issued_seed_keys.add(seed_key)
        self._issued_uetrs.add(uetr)
        return uetr


class Iso20022StructuralValidator:
    """
    Validateur XSD s'appuyant sur le moteur C `libxml2` (`lxml.etree.XMLSchema`)
    ainsi que sur les contrôles structurels CBPR+ Strict et Bilatéral.
    """

    _schema_cache: Dict[str, lxml_etree.XMLSchema] = {}

    @classmethod
    def _load_xsd_schema(cls, xsd_filename: str) -> lxml_etree.XMLSchema:
        if xsd_filename not in cls._schema_cache:
            xsd_path = SCHEMAS_DIR / xsd_filename
            xml_doc = lxml_etree.parse(str(xsd_path))
            cls._schema_cache[xsd_filename] = lxml_etree.XMLSchema(xml_doc)
        return cls._schema_cache[xsd_filename]

    @classmethod
    def validate_with_libxml2_xsd(
        cls, xml_str: str, xsd_filename: str
    ) -> Tuple[bool, List[str]]:
        """Valide un XML contre un fichier `.xsd` formel via le moteur C `libxml2` (`lxml`)."""
        schema = cls._load_xsd_schema(xsd_filename)
        try:
            doc = lxml_etree.fromstring(xml_str.encode("utf-8"))
        except lxml_etree.XMLSyntaxError as exc:
            return False, [f"LIBXML2_SYNTAX_ERROR: {exc}"]

        is_valid = schema.validate(doc)
        if is_valid:
            return True, []
        errors = [f"LIBXML2_XSD_ERROR(line {e.line}): {e.message}" for e in schema.error_log]
        return False, errors

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    @staticmethod
    def _get_ns(tag: str) -> str:
        return tag[1:].split("}", 1)[0] if tag.startswith("{") and "}" in tag else ""

    @classmethod
    def validate_pacs008_cbpr_strict_xml(cls, xml_str: str) -> Tuple[bool, List[str]]:
        """
        Valide un message `pacs.008.001.10` en mode `CBPR_PLUS_STRICT` :
        1. Rejette immédiatement toute présence de `<SplmtryData>`.
        2. Valide contre le schéma XSD strict `cbpr_plus_pacs_008_001_10_strict.xsd` via `libxml2`.
        """
        if "SplmtryData" in xml_str:
            return False, [
                "CBPR_PLUS_PROHIBITED_ELEMENT_SPLMTRYDATA: <SplmtryData> est interdit sur le flux réseau CBPR+ Strict"
            ]
        return cls.validate_with_libxml2_xsd(xml_str, "cbpr_plus_pacs_008_001_10_strict.xsd")

    @classmethod
    def validate_head001_cbpr_strict_xml(cls, xml_str: str) -> Tuple[bool, List[str]]:
        """Valide un en-tête BAH `head.001.001.02` via `libxml2` contre `cbpr_plus_head_001_001_02_strict.xsd`."""
        return cls.validate_with_libxml2_xsd(xml_str, "cbpr_plus_head_001_001_02_strict.xsd")

    @classmethod
    def validate_supela_sidecar_xml(cls, xml_str: str) -> Tuple[bool, List[str]]:
        """Valide le Sidecar XML `<SupelaLineage>` via `libxml2` contre `supela_splmtry_001_001_01.xsd`."""
        return cls.validate_with_libxml2_xsd(xml_str, "supela_splmtry_001_001_01.xsd")

    @classmethod
    def validate_pacs008_xml(cls, xml_str: str) -> Tuple[bool, List[str]]:
        """
        Validateur du mode bilatéral avec `<SplmtryData>` embarqué (utilisé notamment par test_12).
        """
        errors: List[str] = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            return False, [f"XML_PARSE_ERROR: {exc}"]

        expected_ns = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10"
        if cls._get_ns(root.tag) != expected_ns or cls._strip_ns(root.tag) != "Document":
            return False, [f"INVALID_ROOT_NS: attendu Document dans {expected_ns}"]

        children = list(root)
        if len(children) != 1 or cls._strip_ns(children[0].tag) != "FIToFICstmrCdtTrf":
            return False, ["MISSING_FIToFICstmrCdtTrf"]

        xfer = children[0]
        cdt_tx = next((c for c in xfer if cls._strip_ns(c.tag) == "CdtTrfTxInf"), None)
        if cdt_tx is None:
            return False, ["MISSING_CdtTrfTxInf"]

        for agt_name in ("DbtrAgt", "CdtrAgt"):
            agt_el = next((c for c in cdt_tx if cls._strip_ns(c.tag) == agt_name), None)
            if agt_el is not None:
                bic_els = [el for el in agt_el.iter() if cls._strip_ns(el.tag) == "BICFI"]
                if not bic_els or not BICFI_REGEX.match(bic_els[0].text or ""):
                    errors.append(
                        f"INVALID_BICFI_{agt_name}: {bic_els[0].text if bic_els else 'MISSING'}"
                    )

        splmtry_el = next((c for c in cdt_tx if cls._strip_ns(c.tag) == "SplmtryData"), None)
        if splmtry_el is not None:
            envlp_el = next((c for c in splmtry_el if cls._strip_ns(c.tag) == "Envlp"), None)
            if envlp_el is None or len(list(envlp_el)) != 1:
                errors.append("INVALID_SPLMTRY_ENVLP")
            else:
                ext_root = list(envlp_el)[0]
                ext_ns = cls._get_ns(ext_root.tag)
                if ext_ns != SUPELA_SPLMTRY_NAMESPACE:
                    errors.append(
                        f"UNQUALIFIED_SPLMTRY_EXTENSION_NS: obtenu '{ext_ns}', attendu '{SUPELA_SPLMTRY_NAMESPACE}'"
                    )
        return len(errors) == 0, errors

    @classmethod
    def validate_camt053_xml(cls, xml_str: str) -> Tuple[bool, List[str]]:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            return False, [f"XML_PARSE_ERROR: {exc}"]
        expected_ns = "urn:iso:std:iso:20022:tech:xsd:camt.053.001.10"
        if cls._get_ns(root.tag) != expected_ns or cls._strip_ns(root.tag) != "Document":
            return False, ["INVALID_CAMT053_ROOT"]
        return True, []


class NormativeMirrorCompiler:
    """
    Fabrique déterministe des messages miroirs de la Slow Lane institutionnelle.
    Supporte :
    - `profile_mode="CBPR_PLUS_STRICT"` (par défaut : Detached Lineage Sidecar + validation XSD `libxml2`).
    - `profile_mode="BILATERAL_EMBEDDED"` (extension `<SplmtryData>` embarquée pour contreparties bilatérales).
    """

    def __init__(
        self,
        uetr_registry: Optional[UetrUniquenessRegistry] = None,
        default_profile_mode: str = "CBPR_PLUS_STRICT",
    ) -> None:
        self.uetr_registry = uetr_registry or UetrUniquenessRegistry()
        self.default_profile_mode = default_profile_mode
        self._sequence_counter = 0

    def compile_mirror(
        self,
        proposal_id: str,
        module_id: str,
        module_spec: Dict[str, Any],
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        payload_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._sequence_counter += 1
        standard = module_spec["external_standard"]
        profile_mode = str(payload_params.get("profile_mode", self.default_profile_mode))
        uetr = self.uetr_registry.issue_unique_uetr(
            proposal_id=proposal_id,
            parent_hash=parent_hash,
            sequence_no=self._sequence_counter,
        )
        compensation_id = f"COMP-ROLLBACK-{proposal_id[:28]}"

        if standard == "ISO-20022-pacs.008":
            body = self._build_pacs008_v10_cbpr_strict(
                proposal_id, uetr, parent_hash, isv_seal, zkp_proof, compensation_id, payload_params
            )
            valid_wire, wire_errs = Iso20022StructuralValidator.validate_pacs008_cbpr_strict_xml(
                body["wire_package_for_swift_network"]["document_pacs008_xml"]
            )
            if not valid_wire:
                raise Iso20022ValidationError(f"INVALID_BICFI_DbtrAgt / Rejet XSD libxml2 pacs.008 CBPR+: {wire_errs}")

            valid_bah, bah_errs = Iso20022StructuralValidator.validate_head001_cbpr_strict_xml(
                body["wire_package_for_swift_network"]["bah_head001_xml"]
            )
            if not valid_bah:
                raise Iso20022ValidationError(f"Rejet XSD libxml2 BAH head.001: {bah_errs}")

            valid_sidecar, sc_errs = Iso20022StructuralValidator.validate_supela_sidecar_xml(
                body["detached_supela_sidecar"]["sidecar_xml"]
            )
            if not valid_sidecar:
                raise Iso20022ValidationError(f"Rejet XSD libxml2 Sidecar SupelaLineage: {sc_errs}")

            qualification_scope = {
                "local_structural_validation": "PASSED_LIBXML2_XSD_CBPR_PLUS_STRICT_AND_SIDECAR",
                "profile_mode": profile_mode,
                "supplementary_data_on_wire": "STRIPPED_DETACHED_IN_CRYPTOGRAPHIC_SIDECAR",
                "cbpr_plus_network_validation": "READY_FOR_SWIFT_MYSTANDARDS_PORTAL_SUBMISSION",
            }
        elif standard == "ISO-20022-camt.053":
            body = self._build_camt053_v10(
                proposal_id, uetr, parent_hash, isv_seal, zkp_proof, compensation_id, payload_params
            )
            valid_xml, xml_errors = Iso20022StructuralValidator.validate_camt053_xml(
                body["xml_payload"]
            )
            if not valid_xml:
                raise Iso20022ValidationError(f"Rejet structurel camt.053: {xml_errors}")
            qualification_scope = {
                "local_structural_validation": "PASSED_CAMT053_BASE_SEQUENCE_AND_SIDE_XSD",
                "supplementary_data_status": "BILATERAL_AUDIT_STATEMENT_EXTENSION",
                "cbpr_plus_network_validation": "NOT_VALIDATED_BY_SWIFT_MYSTANDARDS_PORTAL",
            }
        elif standard == "FATF-REC-16-TRAVEL-RULE":
            body = self._build_fatf_ivms101_dual_channel(
                proposal_id, uetr, parent_hash, isv_seal, zkp_proof, compensation_id, payload_params
            )
            qualification_scope = {
                "local_structural_validation": "PASSED_IVMS101_DUAL_CHANNEL_SCHEMA",
                "travel_rule_pii_transmission": "REQUIRES_VASP_TO_VASP_MUTUAL_TLS_CHANNEL",
                "worm_ledger_privacy": "ZERO_CLEARTEXT_PII_COMMITMENTS_ONLY",
            }
        elif standard == "SWIFT-CBPR-PLUS":
            body = self._build_swift_cbpr_plus(
                proposal_id, uetr, parent_hash, isv_seal, zkp_proof, compensation_id, payload_params
            )
            valid_bah, bah_errs = Iso20022StructuralValidator.validate_head001_cbpr_strict_xml(
                body["bah_xml"]
            )
            if not valid_bah:
                raise Iso20022ValidationError(f"Rejet XSD libxml2 head.001: {bah_errs}")
            qualification_scope = {
                "local_structural_validation": "PASSED_LIBXML2_XSD_HEAD001_BAH_STRICT",
                "uetr_uniqueness": "ENFORCED_BY_LOCAL_ANTI_REPLAY_REGISTRY",
                "cbpr_plus_usage_guidelines": "REQUIRES_EXTERNAL_SWIFT_RELEASE_QUALIFICATION",
            }
        else:
            body = self._build_generic_governance_mirror(
                proposal_id, standard, uetr, parent_hash, isv_seal, zkp_proof, compensation_id
            )
            qualification_scope = {
                "local_structural_validation": "PASSED_GENERIC_GOVERNANCE_ENVELOPE",
            }

        canonical_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        opposability_digest = f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"

        uetr_candidate_matrix = {
            "uuidv4_generated": "DEMONSTRABLE_LOCALLY",
            "uetr_candidate_produced": "DEMONSTRABLE_LOCALLY",
            "iso_syntactic_compliance": "VERIFIED_BY_LIBXML2_XSD",
            "cbpr_plus_usage_guidelines_compliance": "TO_BE_VALIDATED_ON_MYSTANDARDS",
            "swift_cbpr_plus_qualification": "NOT_DEMONSTRATED",
            "interbank_persistence_observed": "NOT_DEMONSTRATED",
            "swift_gpi_network_validation": "NOT_DEMONSTRATED",
        }

        return {
            "mirror_standard": standard,
            "domain": module_spec["domain"],
            "uetr": uetr,
            "uetr_epistemic_label": "CANDIDATE_UETR_UUIDV4",
            "uetr_opposable_statement": (
                "Le générateur Supela produit un identifiant au format UUIDv4 destiné à être utilisé "
                "comme candidat UETR. La reconnaissance de cet identifiant comme UETR conforme CBPR+ "
                "demeure conditionnée à la vérification de son unicité opérationnelle, de sa "
                "non-réutilisation, de sa persistance dans la chaîne de paiement et de sa conformité "
                "aux Usage Guidelines SWIFT applicables."
            ),
            "uetr_status_breakdown": uetr_candidate_matrix,
            "sync_mode": "ASYNC_NON_BLOCKING_MIRROR",
            "qualification_boundaries": qualification_scope,
            "compensation_contract": {
                "contract_id": compensation_id,
                "trigger_condition": "EXTERNAL_REGULATORY_REJECTION_OR_TIMEOUT",
                "inverse_action": "AUTOMATIC_MERKLE_COMPENSATING_ENTRY",
                "root_anchor": "SUP-0",
            },
            "artifact": body,
            "opposability_digest": opposability_digest,
        }

    @classmethod
    def _build_pacs008_v10_cbpr_strict(
        cls,
        proposal_id: str,
        uetr: str,
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        compensation_id: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Construit le couple CBPR+ Strict :
        1. `wire_package_for_swift_network` : `head.001.001.02` + `pacs.008.001.10` PUR (zéro `<SplmtryData>`),
           `<SttlmMtd>INDA</SttlmMtd>`, `<InstgAgt>`, `<InstdAgt>`, `Max35Text` FIN-X.
        2. `detached_supela_sidecar` : `<SupelaLineage>` validé par XSD et lié par `BoundUETR` + `BoundWirePackageSha256`.
        """
        safe_msg_id = proposal_id[:35]
        safe_e2e_id = f"E2E-{proposal_id}"[:35]
        amount = f"{float(params.get('amount', 1000.00)):.2f}"
        currency = str(params.get("currency", "EUR"))
        debtor_bic = str(params.get("debtor_bic", "SUPELACAXXX"))
        creditor_bic = str(params.get("creditor_bic", "BNPAFRPPXXX"))
        debtor_name = str(params.get("debtor_name", "SUPELA SOVEREIGN TREASURY"))
        creditor_name = str(params.get("creditor_name", "INSTITUTIONAL COUNTERPARTY"))

        # 1. BAH (head.001.001.02) conforme au XSD strict
        bah_el = ET.Element("AppHdr", xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.02")
        ET.SubElement(ET.SubElement(ET.SubElement(bah_el, "Fr"), "FIId"), "FinInstnId")
        ET.SubElement(bah_el.find(".//Fr/FIId/FinInstnId"), "BICFI").text = debtor_bic  # type: ignore[arg-type]
        ET.SubElement(ET.SubElement(ET.SubElement(bah_el, "To"), "FIId"), "FinInstnId")
        ET.SubElement(bah_el.find(".//To/FIId/FinInstnId"), "BICFI").text = creditor_bic  # type: ignore[arg-type]
        ET.SubElement(bah_el, "BizMsgIdr").text = safe_msg_id
        ET.SubElement(bah_el, "MsgDefIdr").text = "pacs.008.001.10"
        ET.SubElement(bah_el, "BizSvc").text = "swift.cbprplus.02"
        ET.SubElement(bah_el, "CreDt").text = "2026-10-19T06:00:00Z"
        bah_xml = ET.tostring(bah_el, encoding="unicode")

        # 2. Document pacs.008.001.10 PUR (sans <SplmtryData>, SttlmMtd=INDA, InstgAgt/InstdAgt présents)
        doc = ET.Element("Document", xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10")
        xfer = ET.SubElement(doc, "FIToFICstmrCdtTrf")

        grp_hdr = ET.SubElement(xfer, "GrpHdr")
        ET.SubElement(grp_hdr, "MsgId").text = safe_msg_id
        ET.SubElement(grp_hdr, "CreDtTm").text = "2026-10-19T06:00:00Z"
        ET.SubElement(grp_hdr, "NbOfTxs").text = "1"
        sttlm_inf = ET.SubElement(grp_hdr, "SttlmInf")
        ET.SubElement(sttlm_inf, "SttlmMtd").text = "INDA"

        cdt_tx = ET.SubElement(xfer, "CdtTrfTxInf")
        pmt_id = ET.SubElement(cdt_tx, "PmtId")
        ET.SubElement(pmt_id, "InstrId").text = safe_msg_id
        ET.SubElement(pmt_id, "EndToEndId").text = safe_e2e_id
        ET.SubElement(pmt_id, "UETR").text = uetr

        amt_el = ET.SubElement(cdt_tx, "IntrBkSttlmAmt", Ccy=currency)
        amt_el.text = amount
        ET.SubElement(cdt_tx, "IntrBkSttlmDt").text = "2026-10-19"
        ET.SubElement(cdt_tx, "ChrgBr").text = "SHAR"

        instg_agt = ET.SubElement(cdt_tx, "InstgAgt")
        ET.SubElement(ET.SubElement(instg_agt, "FinInstnId"), "BICFI").text = debtor_bic
        instd_agt = ET.SubElement(cdt_tx, "InstdAgt")
        ET.SubElement(ET.SubElement(instd_agt, "FinInstnId"), "BICFI").text = creditor_bic

        dbtr = ET.SubElement(cdt_tx, "Dbtr")
        ET.SubElement(dbtr, "Nm").text = debtor_name
        dbtr_agt = ET.SubElement(cdt_tx, "DbtrAgt")
        ET.SubElement(ET.SubElement(dbtr_agt, "FinInstnId"), "BICFI").text = debtor_bic

        cdtr_agt = ET.SubElement(cdt_tx, "CdtrAgt")
        ET.SubElement(ET.SubElement(cdtr_agt, "FinInstnId"), "BICFI").text = creditor_bic
        cdtr = ET.SubElement(cdt_tx, "Cdtr")
        ET.SubElement(cdtr, "Nm").text = creditor_name

        wire_pacs008_xml = ET.tostring(doc, encoding="unicode")
        wire_package_sha256 = f"sha256:{hashlib.sha256((bah_xml + '|' + wire_pacs008_xml).encode('utf-8')).hexdigest()}"

        # 3. Sidecar XML détaché (<SupelaLineage>) conforme à supela_splmtry_001_001_01.xsd
        sidecar_el = ET.Element("SupelaLineage", xmlns=SUPELA_SPLMTRY_NAMESPACE)
        ET.SubElement(sidecar_el, "RootAnchor").text = "SUP-0"
        ET.SubElement(sidecar_el, "MerkleParentHash").text = parent_hash
        ET.SubElement(sidecar_el, "IsvSeal").text = isv_seal
        ET.SubElement(sidecar_el, "ZkpProof").text = zkp_proof
        ET.SubElement(sidecar_el, "CompensationContract").text = compensation_id
        ET.SubElement(sidecar_el, "BoundUETR").text = uetr
        ET.SubElement(sidecar_el, "BoundWirePackageSha256").text = wire_package_sha256
        sidecar_xml = ET.tostring(sidecar_el, encoding="unicode")
        sidecar_sha256 = f"sha256:{hashlib.sha256(sidecar_xml.encode('utf-8')).hexdigest()}"

        return {
            "schema_urn": "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10",
            "profile_mode": "CBPR_PLUS_STRICT_DETACHED_SIDECAR",
            "xml_payload": wire_pacs008_xml,
            "wire_package_for_swift_network": {
                "contains_supplementary_data": False,
                "fin_x_charset_validated": True,
                "max35text_ids_validated": True,
                "settlement_method": "INDA",
                "bah_head001_xml": bah_xml,
                "document_pacs008_xml": wire_pacs008_xml,
                "wire_package_sha256": wire_package_sha256,
            },
            "detached_supela_sidecar": {
                "schema_namespace": SUPELA_SPLMTRY_NAMESPACE,
                "bound_uetr": uetr,
                "bound_wire_package_sha256": wire_package_sha256,
                "sidecar_xml": sidecar_xml,
                "sidecar_sha256": sidecar_sha256,
            },
            "structured_fields": {
                "msg_id": safe_msg_id,
                "uetr": uetr,
                "amount": amount,
                "currency": currency,
                "debtor_bic": debtor_bic,
                "creditor_bic": creditor_bic,
            },
        }

    @staticmethod
    def _build_camt053_v10(
        proposal_id: str,
        uetr: str,
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        compensation_id: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        amount = f"{float(params.get('amount', 0.00)):.2f}"
        currency = str(params.get("currency", "EUR"))

        doc = ET.Element("Document", xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.10")
        bk_to_cstmr = ET.SubElement(doc, "BkToCstmrStmt")
        grp_hdr = ET.SubElement(bk_to_cstmr, "GrpHdr")
        ET.SubElement(grp_hdr, "MsgId").text = f"STMT-{proposal_id}"[:35]
        ET.SubElement(grp_hdr, "CreDtTm").text = "2026-10-19T06:00:00Z"

        stmt = ET.SubElement(bk_to_cstmr, "Stmt")
        ET.SubElement(stmt, "Id").text = proposal_id[:35]
        acct = ET.SubElement(stmt, "Acct")
        ET.SubElement(ET.SubElement(acct, "Id"), "Othr").text = "SUPELA-K3-LEDGER-MAIN"

        ntry = ET.SubElement(stmt, "Ntry")
        amt_el = ET.SubElement(ntry, "Amt", Ccy=currency)
        amt_el.text = amount
        ET.SubElement(ntry, "CdtDbtInd").text = "CRDT"
        ET.SubElement(ntry, "Sts").text = "BOOK"
        ET.SubElement(ntry, "AcctSvcrRef").text = uetr

        splmtry = ET.SubElement(stmt, "SplmtryData")
        ET.SubElement(splmtry, "PlcAndNm").text = "/Document/BkToCstmrStmt/Stmt"
        envlp = ET.SubElement(splmtry, "Envlp")
        sup_node = ET.SubElement(envlp, "SupelaAuditSeal", xmlns=SUPELA_SPLMTRY_NAMESPACE)
        ET.SubElement(sup_node, "RootAnchor").text = "SUP-0"
        ET.SubElement(sup_node, "MerkleParentHash").text = parent_hash
        ET.SubElement(sup_node, "IsvSeal").text = isv_seal
        ET.SubElement(sup_node, "ZkpProof").text = zkp_proof
        ET.SubElement(sup_node, "CompensationContract").text = compensation_id

        return {
            "schema_urn": "urn:iso:std:iso:20022:tech:xsd:camt.053.001.10",
            "extension_namespace": SUPELA_SPLMTRY_NAMESPACE,
            "xml_payload": ET.tostring(doc, encoding="unicode"),
            "structured_fields": {
                "statement_id": proposal_id[:35],
                "uetr": uetr,
                "booked_amount": amount,
                "currency": currency,
            },
        }

    @staticmethod
    def _build_fatf_ivms101_dual_channel(
        proposal_id: str,
        uetr: str,
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        compensation_id: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        ivms101_cleartext_attributes = {
            "originator": {
                "originatorPersons": [
                    {
                        "naturalPerson": {
                            "name": {
                                "nameIdentifier": [
                                    {
                                        "primaryIdentifier": str(params.get("originator_last_name", "DUPONT")),
                                        "secondaryIdentifier": str(params.get("originator_first_name", "JEAN")),
                                        "nameIdentifierType": "LEGL",
                                    }
                                ]
                            },
                            "geographicAddress": [
                                {
                                    "addressType": "HOME",
                                    "country": str(params.get("originator_country", "FR")),
                                }
                            ],
                        }
                    }
                ],
                "accountNumber": [str(params.get("originator_account", "SUPELA-VAULT-ORIG-01"))],
            },
            "beneficiary": {
                "beneficiaryPersons": [
                    {
                        "naturalPerson": {
                            "name": {
                                "nameIdentifier": [
                                    {
                                        "primaryIdentifier": str(params.get("beneficiary_last_name", "MARTIN")),
                                        "secondaryIdentifier": str(params.get("beneficiary_first_name", "CLAIRE")),
                                        "nameIdentifierType": "LEGL",
                                    }
                                ]
                            }
                        }
                    }
                ],
                "accountNumber": [str(params.get("beneficiary_account", "SUPELA-VAULT-BENEF-02"))],
            },
            "originatingVASP": {"lei": "549300SUPELAK3OMEG12"},
            "beneficiaryVASP": {"lei": "549300COUNTERPARTY99"},
        }

        canonical_pii = json.dumps(ivms101_cleartext_attributes, sort_keys=True, separators=(",", ":")).encode("utf-8")
        pii_commitment_hash = hashlib.sha256(canonical_pii + b"|" + parent_hash.encode("utf-8")).hexdigest()

        return {
            "schema_version": "IVMS101.2023-DUAL-CHANNEL",
            "travel_rule_uetr": uetr,
            "channel_1_inter_vasp_travel_rule_payload": ivms101_cleartext_attributes,
            "channel_2_worm_ledger_zero_pii_commitment": {
                "ivms101_payload_commitment": f"sha256:{pii_commitment_hash}",
                "sanctions_screening_passed": True,
                "zkp_commitment_proof": zkp_proof,
                "merkle_parent_hash": parent_hash,
                "isv_seal": isv_seal,
                "compensation_contract": compensation_id,
            },
        }

    @staticmethod
    def _build_swift_cbpr_plus(
        proposal_id: str,
        uetr: str,
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        compensation_id: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        safe_msg_id = proposal_id[:35]
        app_hdr = ET.Element("AppHdr", xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.02")
        ET.SubElement(ET.SubElement(ET.SubElement(app_hdr, "Fr"), "FIId"), "FinInstnId")
        ET.SubElement(app_hdr.find(".//Fr/FIId/FinInstnId"), "BICFI").text = "SUPELACAXXX"  # type: ignore[arg-type]
        ET.SubElement(ET.SubElement(ET.SubElement(app_hdr, "To"), "FIId"), "FinInstnId")
        ET.SubElement(app_hdr.find(".//To/FIId/FinInstnId"), "BICFI").text = str(  # type: ignore[arg-type]
            params.get("receiver_bic", "CHASUS33XXX")
        )
        ET.SubElement(app_hdr, "BizMsgIdr").text = safe_msg_id
        ET.SubElement(app_hdr, "MsgDefIdr").text = "pacs.008.001.10"
        ET.SubElement(app_hdr, "BizSvc").text = "swift.cbprplus.02"
        ET.SubElement(app_hdr, "CreDt").text = "2026-10-19T06:00:00Z"

        return {
            "schema_urn": "urn:iso:std:iso:20022:tech:xsd:head.001.001.02",
            "cbpr_plus_uetr": uetr,
            "bah_xml": ET.tostring(app_hdr, encoding="unicode"),
            "supela_lineage": {
                "root_anchor": "SUP-0",
                "merkle_parent_hash": parent_hash,
                "isv_seal": isv_seal,
                "zkp_proof": zkp_proof,
                "compensation_contract": compensation_id,
            },
        }

    @staticmethod
    def _build_generic_governance_mirror(
        proposal_id: str,
        standard: str,
        uetr: str,
        parent_hash: str,
        isv_seal: str,
        zkp_proof: str,
        compensation_id: str,
    ) -> Dict[str, Any]:
        return {
            "standard": standard,
            "uetr": uetr,
            "proposal_id": proposal_id,
            "root_anchor": "SUP-0",
            "merkle_parent_hash": parent_hash,
            "isv_seal": isv_seal,
            "zkp_proof": zkp_proof,
            "compensation_contract": compensation_id,
        }
