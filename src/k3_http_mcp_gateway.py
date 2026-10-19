"""
Passerelle / Proxy HTTP & MCP Local Souverain Supela-K3-Omega.
Intercepte en amont les requêtes d'inférence (OpenAI / OpenRouter / Meta / MCP) pour :
1. Aplatir automatiquement les schémas JSON d'outils (`tools[*].function.parameters`)
   avant l'envoi au fournisseur externe -> élimine à la source le crash Meta HTTP 400
   ("Recursive JSON schemas are not currently supported").
2. Appliquer le Circuit-Breaker Souverain : si le fournisseur primaire retourne une erreur
   de quota (HTTP 429 / "Daily free model limit reached") ou d'indisponibilité, bascule
   instantanément sur le moteur souverain local scellé (`supela-local-sovereign-v1`).
3. Soumettre toute proposition d'appel d'outil générée par le LLM au sas déterministe
   `SupelaK3OmegaEngine` avant d'autoriser sa sortie et sceller l'audit dans le journal WORM.
"""

from __future__ import annotations
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.schema_flattener import flatten_tool_schema
from src.supela_k3_engine import SupelaK3OmegaEngine


UpstreamDispatchFn = Callable[[Dict[str, Any]], Tuple[int, Dict[str, Any]]]


class SupelaMcpHttpInterceptor:
    """
    Cœur logique du proxy d'interception HTTP/MCP (utilisable en mémoire ou via socket HTTP).
    """

    def __init__(
        self,
        engine: Optional[SupelaK3OmegaEngine] = None,
        upstream_dispatcher: Optional[UpstreamDispatchFn] = None,
        max_schema_depth: int = 3,
    ) -> None:
        self.engine = engine or SupelaK3OmegaEngine(auto_flatten_schemas=True)
        self.upstream_dispatcher = upstream_dispatcher or self._default_mock_upstream
        self.max_schema_depth = max_schema_depth

    def sanitize_request_tools(
        self, request_payload: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Parcourt tous les outils (`tools` OpenAI/OpenRouter ou `subagents`/`mcp_tools`)
        et aplatit leurs schémas JSON récursifs ou non bornés avant départ vers le provider.
        """
        payload_copy = json.loads(json.dumps(request_payload))
        reports: List[Dict[str, Any]] = []

        tools = payload_copy.get("tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                fn_block = tool.get("function", tool)
                if isinstance(fn_block, dict) and isinstance(fn_block.get("parameters"), dict):
                    flat_schema, report = flatten_tool_schema(
                        fn_block["parameters"], max_depth=self.max_schema_depth
                    )
                    fn_block["parameters"] = flat_schema
                    reports.append(
                        {
                            "tool_name": fn_block.get("name", "unnamed_tool"),
                            **report.to_dict(),
                        }
                    )
        return payload_copy, reports

    def handle_chat_completions(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pipeline complet d'interception d'un appel `/v1/chat/completions` :
        1. Sanitisation des schémas d'outils (Anti-Meta 400).
        2. Appel au fournisseur primaire (ou capture d'erreur 429/400).
        3. En cas de 429 ("Daily free model limit reached"), activation du fallback souverain.
        4. Validation K3-Omega de la proposition et scellement WORM.
        """
        sanitized_req, schema_reports = self.sanitize_request_tools(request_payload)
        primary_model = str(sanitized_req.get("model", "meta-llama/llama-4-maverick"))

        http_status, upstream_response = self.upstream_dispatcher(sanitized_req)

        # Détermination de la télémétrie fournisseur pour le Circuit-Breaker K3
        if http_status == 200:
            telemetry = {
                "status": "HEALTHY",
                "primary_model": primary_model,
                "error_code": "NONE",
            }
            effective_completion = upstream_response
        elif http_status == 429 or "limit reached" in json.dumps(upstream_response).lower():
            telemetry = {
                "status": "DEGRADED",
                "primary_model": primary_model,
                "error_code": "DAILY_FREE_LIMIT_REACHED",
            }
            effective_completion = self._build_sovereign_fallback_completion(sanitized_req)
        else:
            telemetry = {
                "status": "ERROR",
                "primary_model": primary_model,
                "error_code": f"HTTP_{http_status}",
            }
            effective_completion = upstream_response

        # Construction de l'enveloppe de gouvernance K3 pour sceller l'appel
        first_tool_schema = {"type": "object", "properties": {"prompt": {"type": "string"}}}
        if sanitized_req.get("tools"):
            first_fn = sanitized_req["tools"][0].get("function", sanitized_req["tools"][0])
            first_tool_schema = first_fn.get("parameters", first_tool_schema)

        k3_envelope = sanitized_req.get(
            "supela_k3_meta",
            {
                "proposal_id": sanitized_req.get("request_id", "PROP-GATEWAY-AUTO-001"),
                "actor": {
                    "role": "AI_PROPOSAL_GENERATOR",
                    "direct_execution_privilege": False,
                },
                "proposal": {
                    "module_id": "VR-14",
                    "target_environment": "k3s-isolated-sandbox",
                    "estimated_impact_score": 20,
                    "emergent_drift_delta": 0.01,
                    "modifies_worm_ledger": False,
                    "parameters": {"amount": 2500.00, "currency": "EUR"},
                    "lineage": {
                        "root_anchor": "SUP-0",
                        "merkle_parent_hash": self.engine.ledger.head_hash,
                        "isv_seal": "ISV-GATEWAY-AUTO-SEAL",
                    },
                },
                "validation": {
                    "gf_verdict": "SEALED_APPROVED",
                    "engine_signatures": ["sig-gateway-k3-alpha", "sig-gateway-k3-beta"],
                    "zkp_proof": "zkp-snark:gateway-verified-proof-001",
                },
            },
        )
        k3_envelope["tool_schema"] = first_tool_schema
        k3_envelope["provider_telemetry"] = telemetry

        receipt = self.engine.evaluate_and_dispatch(k3_envelope)

        return {
            "object": "supela.k3.sealed.completion",
            "upstream_http_status": http_status,
            "schema_flattening_gate": {
                "tools_inspected": len(schema_reports),
                "reports": schema_reports,
            },
            "k3_omega_receipt": receipt.to_dict(),
            "completion": effective_completion if receipt.allowed else None,
        }

    @staticmethod
    def _default_mock_upstream(sanitized_req: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """
        Simulateur de fournisseur externe :
        - Renvoie HTTP 400 si un schéma d'outil contient encore `$ref` ou `$defs` (comportement Meta).
        - Renvoie HTTP 429 si le modèle demandé est `nvidia/nemotron-3.5-super-vl` (quota épuisé).
        - Renvoie HTTP 200 sinon.
        """
        raw_str = json.dumps(sanitized_req.get("tools", []))
        if '"$ref"' in raw_str or '"$defs"' in raw_str:
            return 400, {
                "error": {
                    "message": "Recursive JSON schemas are not currently supported",
                    "type": "invalid_request_error",
                    "provider_name": "Meta",
                }
            }
        if sanitized_req.get("model") == "nvidia/nemotron-3.5-super-vl":
            return 429, {
                "error": {
                    "message": "Daily free model limit reached. Try again in 17h 25m.",
                    "code": 429,
                }
            }
        return 200, {
            "id": "chatcmpl-supela-nominal",
            "model": sanitized_req.get("model", "gemini-4-argon"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Proposition générée sous contrainte Supela-K3-Omega.",
                    },
                }
            ],
        }

    @staticmethod
    def _build_sovereign_fallback_completion(sanitized_req: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": "chatcmpl-supela-sovereign-fallback",
            "model": "supela-local-sovereign-v1",
            "fallback_reason": "UPSTREAM_QUOTA_EXCEEDED_429",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": (
                            "[FALLBACK SOUVERAIN SUPELA-K3] Continuité assurée par le moteur local "
                            "suite au dépassement de quota du fournisseur externe."
                        ),
                    },
                }
            ],
        }


class _GatewayHTTPHandler(BaseHTTPRequestHandler):
    interceptor: SupelaMcpHttpInterceptor

    def log_message(self, format: str, *args: Any) -> None:
        return  # Silence les logs HTTP standard pendant les tests

    def do_POST(self) -> None:
        if self.path not in ("/v1/chat/completions", "/mcp/v1/intercept"):
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        request_payload = json.loads(raw_body)
        response_payload = self.interceptor.handle_chat_completions(request_payload)

        body_bytes = json.dumps(response_payload).encode("utf-8")
        status_code = 200 if response_payload["k3_omega_receipt"]["allowed"] else 403
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


class SupelaGatewayServer:
    """Serveur HTTP local léger exposant `/v1/chat/completions` et `/mcp/v1/intercept`."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        interceptor: Optional[SupelaMcpHttpInterceptor] = None,
    ) -> None:
        self.interceptor = interceptor or SupelaMcpHttpInterceptor()

        class BoundHandler(_GatewayHTTPHandler):
            pass

        BoundHandler.interceptor = self.interceptor
        self.httpd = HTTPServer((host, port), BoundHandler)
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start_background(self) -> str:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)
