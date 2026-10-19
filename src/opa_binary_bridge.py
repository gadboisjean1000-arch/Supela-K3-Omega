"""
Pont d'exécution réelle du binaire officiel Open Policy Agent (`opa.exe`).
Élimine le biais d'auto-évaluation Python en appelant directement le moteur CNCF OPA
sur `policies/guardrails.rego` et `policies/guardrails_test.rego`.
"""

from __future__ import annotations
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Optional, Tuple


ROOT_DIR = Path(__file__).resolve().parent.parent

CANDIDATE_OPA_PATHS = [
    Path(r"C:\Users\Group\Desktop\Supela-Monolithe\opa.exe"),
    Path(r"C:\Users\Group\supela-k3-workspace\.worktrees\gadboisjean1000-arch-friendly-giggle\.tools\opa.exe"),
]


def resolve_opa_binary() -> Optional[Path]:
    """Localise le binaire `opa.exe` officiel sur le poste."""
    which_opa = shutil.which("opa")
    if which_opa:
        return Path(which_opa)
    for candidate in CANDIDATE_OPA_PATHS:
        if candidate.exists():
            return candidate
    return None


def run_opa_policy_tests() -> Dict[str, Any]:
    """Exécute `opa.exe test policies/ -v` et retourne le rapport brut signé par le binaire."""
    opa_bin = resolve_opa_binary()
    if opa_bin is None:
        return {
            "executed": False,
            "error": "OPA_BINARY_NOT_FOUND",
        }

    policies_dir = ROOT_DIR / "policies"
    ver_proc = subprocess.run(
        [str(opa_bin), "version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    test_proc = subprocess.run(
        [str(opa_bin), "test", str(policies_dir), "-v"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return {
        "executed": True,
        "binary_path": str(opa_bin),
        "version_output": ver_proc.stdout.strip(),
        "exit_code": test_proc.returncode,
        "passed": test_proc.returncode == 0,
        "stdout": test_proc.stdout.strip(),
    }


def evaluate_envelope_with_opa_binary(
    envelope: Dict[str, Any], max_drift_delta: float = 0.05
) -> Tuple[bool, Dict[str, Any]]:
    """
    Évalue un payload `envelope` directement via `opa.exe eval` contre `policies/guardrails.rego`
    et retourne `(success, decision_manifest)`.
    """
    opa_bin = resolve_opa_binary()
    if opa_bin is None:
        return False, {"error": "OPA_BINARY_NOT_FOUND"}

    policy_file = ROOT_DIR / "policies" / "guardrails.rego"
    data_payload = {"supela": {"limits": {"max_drift_delta": max_drift_delta}}}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        input_file = tmp_path / "input.json"
        data_file = tmp_path / "data.json"
        input_file.write_text(json.dumps(envelope), encoding="utf-8")
        data_file.write_text(json.dumps(data_payload), encoding="utf-8")

        proc = subprocess.run(
            [
                str(opa_bin),
                "eval",
                "--format",
                "json",
                "--data",
                str(policy_file),
                "--data",
                str(data_file),
                "--input",
                str(input_file),
                "data.supela.k3.omega.guardrails.decision_manifest",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return False, {"error": proc.stderr.strip()}

        parsed = json.loads(proc.stdout)
        expressions = parsed.get("result", [{}])[0].get("expressions", [{}])
        manifest = expressions[0].get("value", {}) if expressions else {}
        return True, manifest
