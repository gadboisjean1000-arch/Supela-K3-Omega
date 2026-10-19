"""
Passerelle d'aplatissement de schémas JSON (Supela-K3 Schema Flattening Gate).
Neutralise l'erreur HTTP 400 ("Recursive JSON schemas are not currently supported")
renvoyée par les fournisseurs LLM à grammaire stricte (ex: Meta / Llama via OpenRouter)
lorsque des outils MCP ou agents exposent des structures auto-référentielles ($ref, $defs)
ou des objets génériques non bornés.
"""

from __future__ import annotations
import copy
import hashlib
import json
from typing import Any, Dict, List, Tuple


class SchemaSanitizationReport:
    """Rapport scellé d'assainissement de schéma JSON pour le journal WORM."""

    def __init__(
        self,
        original_hash: str,
        sanitized_hash: str,
        recursions_neutralized: int,
        unbounded_objects_sealed: int,
        stripped_defs: List[str],
    ) -> None:
        self.original_hash = original_hash
        self.sanitized_hash = sanitized_hash
        self.recursions_neutralized = recursions_neutralized
        self.unbounded_objects_sealed = unbounded_objects_sealed
        self.stripped_defs = stripped_defs

    @property
    def was_modified(self) -> bool:
        return (
            self.recursions_neutralized > 0
            or self.unbounded_objects_sealed > 0
            or len(self.stripped_defs) > 0
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_schema_sha256": self.original_hash,
            "sanitized_schema_sha256": self.sanitized_hash,
            "was_modified": self.was_modified,
            "recursions_neutralized": self.recursions_neutralized,
            "unbounded_objects_sealed": self.unbounded_objects_sealed,
            "stripped_definitions": self.stripped_defs,
        }


def _compute_schema_hash(schema: Dict[str, Any]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def detect_recursive_or_unbounded_patterns(schema: Any) -> List[str]:
    """
    Analyse statiquement un JSON Schema et retourne la liste des anomalies
    susceptibles de provoquer un HTTP 400 chez Meta / OpenRouter.
    """
    issues: List[str] = []

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if "$ref" in node and str(node["$ref"]).startswith("#"):
                issues.append(f"{path}.$ref -> Référence interne/circulaire ({node['$ref']})")
            for def_key in ("$defs", "definitions"):
                if def_key in node:
                    issues.append(f"{path}.{def_key} -> Bloc de définitions récursives potentielles")
            if node.get("type") == "object" and "properties" not in node and "$ref" not in node:
                issues.append(f"{path} -> Objet ouvert non borné (sans 'properties' explicites)")
            for k, v in node.items():
                _walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]")

    _walk(schema, "$")
    return issues


def flatten_tool_schema(
    schema: Dict[str, Any],
    max_depth: int = 3,
) -> Tuple[Dict[str, Any], SchemaSanitizationReport]:
    """
    Transforme un JSON Schema potentiellement récursif ou ouvert en un schéma
    strictement acyclique et borné, compatible avec tous les moteurs de décodage contraint.
    """
    original_hash = _compute_schema_hash(schema)
    defs_store: Dict[str, Any] = {}
    stripped_defs: List[str] = []
    stats = {"recursions": 0, "unbounded": 0}

    # Extraction préalable des définitions ($defs / definitions) pour résolution de 1er niveau
    for def_key in ("$defs", "definitions"):
        if isinstance(schema.get(def_key), dict):
            for k, v in schema[def_key].items():
                defs_store[k] = copy.deepcopy(v)
                stripped_defs.append(f"{def_key}/{k}")

    def _sanitize_node(node: Any, current_depth: int, seen_refs: Tuple[str, ...]) -> Any:
        if not isinstance(node, dict):
            return copy.deepcopy(node)

        # 1. Résolution ou coupure des pointeurs $ref
        if "$ref" in node:
            ref_val = str(node["$ref"])
            ref_name = ref_val.split("/")[-1]
            if ref_val in seen_refs or current_depth >= max_depth or ref_name not in defs_store:
                stats["recursions"] += 1
                return {
                    "type": "string",
                    "description": (
                        f"[SUPELA-K3-FLATTENED] Payload JSON sérialisé pour '{ref_name}' "
                        f"(récursion coupée à la profondeur {current_depth})."
                    ),
                }
            # Déroulement contrôlé sur 1 niveau
            stats["recursions"] += 1
            resolved_target = copy.deepcopy(defs_store[ref_name])
            return _sanitize_node(resolved_target, current_depth + 1, seen_refs + (ref_val,))

        # 2. Coupure de profondeur maximale sur les objets imbriqués
        if current_depth >= max_depth and node.get("type") in ("object", "array"):
            stats["recursions"] += 1
            return {
                "type": "string",
                "description": f"[SUPELA-K3-FLATTENED] Structure profonde sérialisée en JSON (profondeur >= {max_depth}).",
            }

        cleaned: Dict[str, Any] = {}
        for key, value in node.items():
            if key in ("$defs", "definitions", "additionalProperties"):
                continue
            if key == "properties" and isinstance(value, dict):
                cleaned["properties"] = {
                    prop_name: _sanitize_node(prop_schema, current_depth + 1, seen_refs)
                    for prop_name, prop_schema in value.items()
                }
            elif key == "items" and isinstance(value, dict):
                cleaned["items"] = _sanitize_node(value, current_depth + 1, seen_refs)
            elif isinstance(value, dict):
                cleaned[key] = _sanitize_node(value, current_depth + 1, seen_refs)
            elif isinstance(value, list):
                cleaned[key] = [
                    _sanitize_node(item, current_depth + 1, seen_refs)
                    if isinstance(item, dict)
                    else copy.deepcopy(item)
                    for item in value
                ]
            else:
                cleaned[key] = copy.deepcopy(value)

        # 3. Verrouillage des objets génériques sans propriétés (ex: Arguments dans call_mcp_tool)
        if cleaned.get("type") == "object" and not cleaned.get("properties"):
            stats["unbounded"] += 1
            cleaned["type"] = "string"
            cleaned["description"] = (
                cleaned.get("description", "Objet dynamique")
                + " [SUPELA-K3-SEALED: Fournir sous forme de chaîne JSON valide]"
            )
        elif cleaned.get("type") == "object":
            cleaned["additionalProperties"] = False

        return cleaned

    sanitized_schema = _sanitize_node(schema, current_depth=0, seen_refs=())
    sanitized_hash = _compute_schema_hash(sanitized_schema)

    report = SchemaSanitizationReport(
        original_hash=original_hash,
        sanitized_hash=sanitized_hash,
        recursions_neutralized=stats["recursions"],
        unbounded_objects_sealed=stats["unbounded"],
        stripped_defs=stripped_defs,
    )
    return sanitized_schema, report
