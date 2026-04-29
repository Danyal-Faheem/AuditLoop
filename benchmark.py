import argparse
import collections
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dive_evaluator import DIVEEvaluator


PAPER_BASELINES = {
    "web3bugs": {
        "precision": 0.571428571,
        "recall": 0.833333333,
        "f1": 0.677966102,
        "accuracy": 0.836206897,
    },
    "defihacks": {
        "precision": 0.909090909,
        "recall": 0.714285714,
        "f1": 0.8,
        "accuracy": 0.852941176,
    },
    "top200": {
        "projects": 303,
        "total_false_positives": 296,
        "projects_with_false_positives": 126,
        "avg_false_positives_per_project": 296 / 303,
    },
}


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def _count_source_projects(source: str) -> int:
    source_path = Path(source)
    if not source_path.exists():
        return 0
    if source_path.is_file():
        return 1

    project_dirs = [
        child
        for child in source_path.iterdir()
        if child.is_dir() and not child.name.startswith(".")
    ]

    if len(project_dirs) == 0:
        return 1
    return len(project_dirs)


def _resolve_dataset_kind(source: str, requested_kind: str) -> str:
    if requested_kind != "auto":
        return requested_kind

    lowered = str(source).lower()
    if "dive" in lowered:
        return "dive"
    if "top200" in lowered:
        return "top200"
    if "defihack" in lowered:
        return "defihacks"
    if "web3bug" in lowered:
        return "web3bugs"
    return "custom"


def _build_derived_metrics(meta: dict, source: str, dataset_kind: str) -> dict:
    files_total = meta.get("files", 0) or meta.get("source_files_total", 0)
    contracts_total = meta.get("contracts", 0)
    loc_total = meta.get("loc", 0)
    used_time = meta.get("used_time", 0)
    vul_before_static = meta.get("vul_before_static", 0)
    vul_after_static = meta.get("vul_after_static", 0)
    vul_after_merge = meta.get("vul_after_merge", 0)
    vul_after_remediation = meta.get("vul_after_remediation", vul_after_merge)
    projects_total = _count_source_projects(source)

    kloc = _safe_div(loc_total, 1000.0)

    derived = {
        "dataset_kind": dataset_kind,
        "source_projects_total": projects_total,
        "seconds_per_kloc": _safe_div(used_time, kloc),
        "loc_per_second": _safe_div(loc_total, used_time),
        "files_per_minute": _safe_div(files_total * 60.0, used_time),
        "contracts_per_minute": _safe_div(contracts_total * 60.0, used_time),
        "findings_per_kloc_before_static": _safe_div(vul_before_static, kloc),
        "findings_per_kloc_after_static": _safe_div(vul_after_static, kloc),
        "findings_per_kloc_after_merge": _safe_div(vul_after_merge, kloc),
        "findings_per_kloc_after_remediation": _safe_div(vul_after_remediation, kloc),
        "findings_per_project_after_merge": _safe_div(vul_after_merge, projects_total),
        "findings_per_project_after_remediation": _safe_div(vul_after_remediation, projects_total),
        "static_reduction_ratio": _safe_div(vul_before_static - vul_after_static, vul_before_static),
        "static_reduction_pct": _safe_div(vul_before_static - vul_after_static, vul_before_static) * 100.0,
        "merge_retention_ratio": _safe_div(vul_after_merge, vul_after_static),
        "merge_retention_pct": _safe_div(vul_after_merge, vul_after_static) * 100.0,
        "remediation_reduction_ratio": _safe_div(vul_after_merge - vul_after_remediation, vul_after_merge),
        "remediation_reduction_pct": _safe_div(vul_after_merge - vul_after_remediation, vul_after_merge) * 100.0,
    }

    if dataset_kind in PAPER_BASELINES:
        derived["paper_baseline"] = PAPER_BASELINES[dataset_kind]

    if dataset_kind == "top200":
        baseline_total_fp = PAPER_BASELINES["top200"]["total_false_positives"]
        derived["assumed_false_positives_after_merge"] = vul_after_merge
        derived["assumed_false_positives_after_remediation"] = vul_after_remediation
        derived["assumed_fp_per_project"] = _safe_div(vul_after_merge, projects_total)
        derived["assumed_fp_per_project_after_remediation"] = _safe_div(vul_after_remediation, projects_total)
        derived["delta_vs_paper_total_fp"] = vul_after_merge - baseline_total_fp
        derived["delta_vs_paper_total_fp_after_remediation"] = vul_after_remediation - baseline_total_fp

    return derived


def _persist_enriched_metadata(metadata_path: Path, source: str, dataset_kind: str) -> dict:
    meta = read_metadata(metadata_path)
    resolved_kind = _resolve_dataset_kind(source, dataset_kind)
    meta["dataset_kind"] = resolved_kind
    meta["derived_metrics"] = _build_derived_metrics(meta, source=source, dataset_kind=resolved_kind)
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta


def run_scan(repo_root: Path, source: str, output_file: Path, provider: str, model: str, openai_key: str = "", ollama_url: str = "http://localhost:11434", ollama_url_second: str = "", ollama_timeout_seconds: int = 60, disable_falcon: bool = False, disable_static: bool = False, enable_remediation: bool = False, remediation_max_rounds: int = 3, remediation_drop_fixed: bool = False, remediation_verify_mode: str = "llm-self-check"):
    cmd = [
        "python3",
        "main.py",
        "-s",
        source,
        "-o",
        str(output_file),
        "--provider",
        provider,
        "--model",
        model,
        "--ollama-url",
        ollama_url,
    ]

    if provider == "openai":
        cmd.extend(["-k", openai_key])

    env = os.environ.copy()
    if provider == "openai" and openai_key:
        env["OPENAI_API_KEY"] = openai_key
    if disable_falcon:
        env["GPTSCAN_DISABLE_FALCON"] = "1"
    if disable_static:
        env["GPTSCAN_DISABLE_STATIC"] = "1"
    if enable_remediation:
        env["GPTSCAN_ENABLE_REMEDIATION"] = "1"
        env["GPTSCAN_REMEDIATION_MAX_ROUNDS"] = str(max(1, int(remediation_max_rounds)))
        if remediation_drop_fixed:
            env["GPTSCAN_REMEDIATION_DROP_FIXED"] = "1"
        env["GPTSCAN_REMEDIATION_VERIFY_MODE"] = str(remediation_verify_mode or "llm-self-check")
    # optional second Ollama URL and timeout
    if (ollama_url_second or os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", "")):
        env["GPTSCAN_OLLAMA_URL_SECOND"] = str(ollama_url_second or os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", ""))
    if ollama_timeout_seconds and int(ollama_timeout_seconds) > 0:
        env["GPTSCAN_OLLAMA_TIMEOUT"] = str(int(ollama_timeout_seconds))

        # propagate optional second Ollama URL and timeout
        if os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", "") != "":
            env["GPTSCAN_OLLAMA_URL_SECOND"] = os.environ.get("GPTSCAN_OLLAMA_URL_SECOND")
        else:
            # preserve passed-in default (if set by caller)
            pass
        if os.environ.get("GPTSCAN_OLLAMA_TIMEOUT", "") != "":
            env["GPTSCAN_OLLAMA_TIMEOUT"] = os.environ.get("GPTSCAN_OLLAMA_TIMEOUT")
    subprocess.run(cmd, cwd=repo_root / "src", env=env, check=True)


def run_scan_with_logs(repo_root: Path, source: str, output_file: Path, provider: str, model: str, openai_key: str = "", ollama_url: str = "http://localhost:11434", disable_falcon: bool = False, disable_static: bool = False, enable_remediation: bool = False, remediation_max_rounds: int = 3, remediation_drop_fixed: bool = False, remediation_verify_mode: str = "llm-self-check"):
    cmd = [
        "python3",
        "main.py",
        "-s",
        source,
        "-o",
        str(output_file),
        "--provider",
        provider,
        "--model",
        model,
        "--ollama-url",
        ollama_url,
    ]

    if provider == "openai":
        cmd.extend(["-k", openai_key])

    env = os.environ.copy()
    if provider == "openai" and openai_key:
        env["OPENAI_API_KEY"] = openai_key
    if disable_falcon:
        env["GPTSCAN_DISABLE_FALCON"] = "1"
    if disable_static:
        env["GPTSCAN_DISABLE_STATIC"] = "1"
    if enable_remediation:
        env["GPTSCAN_ENABLE_REMEDIATION"] = "1"
        env["GPTSCAN_REMEDIATION_MAX_ROUNDS"] = str(max(1, int(remediation_max_rounds)))
        if remediation_drop_fixed:
            env["GPTSCAN_REMEDIATION_DROP_FIXED"] = "1"
        env["GPTSCAN_REMEDIATION_VERIFY_MODE"] = str(remediation_verify_mode or "llm-self-check")
    # propagate optional second Ollama URL and timeout
    if os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", "") != "":
        env["GPTSCAN_OLLAMA_URL_SECOND"] = os.environ.get("GPTSCAN_OLLAMA_URL_SECOND")
    if os.environ.get("GPTSCAN_OLLAMA_TIMEOUT", "") != "":
        env["GPTSCAN_OLLAMA_TIMEOUT"] = os.environ.get("GPTSCAN_OLLAMA_TIMEOUT")

    result = subprocess.run(
        cmd,
        cwd=repo_root / "src",
        env=env,
        capture_output=True,
        text=True,
    )
    return result


def run_scan_with_logs_timeout(
    repo_root: Path,
    source: str,
    output_file: Path,
    provider: str,
    model: str,
    openai_key: str = "",
    ollama_url: str = "http://localhost:11434",
    ollama_url_second: str = "",
    ollama_timeout_seconds: int = 60,
    timeout_seconds: int = 0,
    disable_falcon: bool = False,
    disable_static: bool = False,
    enable_remediation: bool = False,
    remediation_max_rounds: int = 3,
    remediation_drop_fixed: bool = False,
    remediation_verify_mode: str = "llm-self-check",
):
    cmd = [
        "python3",
        "main.py",
        "-s",
        source,
        "-o",
        str(output_file),
        "--provider",
        provider,
        "--model",
        model,
        "--ollama-url",
        ollama_url,
    ]

    if provider == "openai":
        cmd.extend(["-k", openai_key])

    env = os.environ.copy()
    if provider == "openai" and openai_key:
        env["OPENAI_API_KEY"] = openai_key
    if disable_falcon:
        env["GPTSCAN_DISABLE_FALCON"] = "1"
    if disable_static:
        env["GPTSCAN_DISABLE_STATIC"] = "1"
    if enable_remediation:
        env["GPTSCAN_ENABLE_REMEDIATION"] = "1"
        env["GPTSCAN_REMEDIATION_MAX_ROUNDS"] = str(max(1, int(remediation_max_rounds)))
        if remediation_drop_fixed:
            env["GPTSCAN_REMEDIATION_DROP_FIXED"] = "1"
        env["GPTSCAN_REMEDIATION_VERIFY_MODE"] = str(remediation_verify_mode or "llm-self-check")

    if (ollama_url_second or os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", "")):
        env["GPTSCAN_OLLAMA_URL_SECOND"] = str(ollama_url_second or os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", ""))
    if ollama_timeout_seconds and int(ollama_timeout_seconds) > 0:
        env["GPTSCAN_OLLAMA_TIMEOUT"] = str(int(ollama_timeout_seconds))

    timeout_value = None if timeout_seconds <= 0 else timeout_seconds
    return subprocess.run(
        cmd,
        cwd=repo_root / "src",
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_value,
    )


def _list_sol_files(source: str) -> List[Path]:
    source_path = Path(source)
    if source_path.is_file() and source_path.suffix.lower() == ".sol":
        return [source_path]
    if source_path.is_dir():
        sol_files: List[Path] = []
        # Follow symlinked directories (common in benchmark smoke subsets).
        for root, _, files in os.walk(source_path, followlinks=True):
            for file_name in files:
                if file_name.lower().endswith(".sol"):
                    sol_files.append(Path(root) / file_name)
        return sorted(sol_files)
    return []


def _dedupe_results(results: List[dict]) -> List[dict]:
    unique: Dict[str, dict] = {}
    for result in results:
        key = json.dumps(result, sort_keys=True)
        if key not in unique:
            unique[key] = result
    return list(unique.values())


def _extract_solc_version_from_pragma(sol_file: Path) -> str:
    try:
        with open(sol_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(4096)
    except Exception:
        return ""

    # Match common forms:
    # pragma solidity ^0.6.12;
    # pragma solidity =0.8.19;
    # pragma solidity >=0.6.0 <0.9.0;
    pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", content, flags=re.IGNORECASE)
    if pragma_match is None:
        return ""

    expr = pragma_match.group(1)
    version_match = re.search(r"(\d+\.\d+\.\d+)", expr)
    if version_match is None:
        return ""

    return version_match.group(1)


def _try_switch_solc(version: str) -> bool:
    if version == "":
        return False
    try:
        # Best effort: assume version is already installed on the worker.
        subprocess.run(["solc-select", "use", version], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _get_installed_solc_versions() -> List[str]:
    try:
        result = subprocess.run(["solc-select", "versions"], capture_output=True, text=True, check=False)
        lines = (result.stdout or "").splitlines()
        versions = []
        for line in lines:
            clean = line.strip()
            if clean == "":
                continue
            # Example: "0.8.19 (current, set by ...)"
            m = re.match(r"^(\d+\.\d+\.\d+)", clean)
            if m is not None:
                versions.append(m.group(1))
        return sorted(list(set(versions)))
    except Exception:
        return []


def _install_solc_version(version: str) -> bool:
    if version == "":
        return False
    try:
        subprocess.run(["solc-select", "install", version], check=True)
        return True
    except Exception:
        return False


def _collect_required_solc_versions(sol_files: List[Path]) -> List[str]:
    versions = []
    for sol_file in sol_files:
        v = _extract_solc_version_from_pragma(sol_file)
        if v != "":
            versions.append(v)
    return sorted(list(set(versions)))


def _estimate_sol_file_complexity(sol_file: Path) -> Dict[str, int]:
    try:
        with open(sol_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return {"loc": 0, "contracts": 0, "functions": 0}

    loc = len(text.splitlines())
    contracts = len(re.findall(r"\b(contract|library|interface)\b", text))
    functions = len(re.findall(r"\bfunction\b", text))
    return {"loc": loc, "contracts": contracts, "functions": functions}


def _extract_local_sol_imports(sol_file: Path) -> List[str]:
    try:
        text = sol_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    # Supports both forms:
    # import "./A.sol";
    # import {A as B} from "./A.sol";
    pattern = re.compile(r"^\s*import\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']\s*;", re.MULTILINE)
    imports = pattern.findall(text)
    return [item for item in imports if item.endswith(".sol") and item.startswith(".")]


def _determine_project_root(sol_file: Path, source_root: Path) -> Path:
    if source_root.is_file():
        return sol_file.parent

    try:
        rel = sol_file.resolve().relative_to(source_root.resolve())
    except Exception:
        return sol_file.parent

    if len(rel.parts) >= 2:
        return source_root / rel.parts[0]
    return source_root


def _copy_file_into_shard(src_file: Path, project_root: Path, shard_input: Path):
    try:
        rel = src_file.resolve().relative_to(project_root.resolve())
        dst = shard_input / rel
    except Exception:
        dst = shard_input / src_file.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_file, dst)


def _copy_solidity_dependency_closure(sol_file: Path, source_root: Path, shard_input: Path) -> Tuple[int, List[str]]:
    project_root = _determine_project_root(sol_file, source_root)
    queue = [sol_file.resolve()]
    visited = set()
    missing_local_imports = []

    while len(queue) > 0:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        if not current.exists():
            continue

        _copy_file_into_shard(current, project_root, shard_input)

        for rel_import in _extract_local_sol_imports(current):
            target = (current.parent / rel_import).resolve()
            if target.exists() and target.suffix.lower() == ".sol":
                if target not in visited:
                    queue.append(target)
            else:
                missing_local_imports.append(f"{str(current)} -> {rel_import}")

    return len(visited), sorted(list(set(missing_local_imports)))


def _normalize_subprocess_output(output) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="ignore")
    return str(output)


def _probe_falcon_initialization(repo_root: Path, scan_source: str, timeout_seconds: int = 60, excerpt_lines: int = 0) -> dict:
    # If scan_source is a directory, find and use the first .sol file inside (recursively)
    source_path = Path(scan_source)
    if source_path.is_dir():
        # Try to find .sol files at root first, then search recursively
        sol_files = list(source_path.glob("*.sol"))
        if not sol_files:
            # Try recursive search for nested .sol files
            sol_files = list(source_path.glob("**/*.sol"))
        if sol_files:
            scan_source = str(sol_files[0])
        else:
            # No .sol files found, Falcon will fail with appropriate error
            pass
    
    probe_code = (
        "import falcon,sys,json,traceback\n"
        "target=sys.argv[1]\n"
        "try:\n"
        "    falcon.Falcon(target)\n"
        "    print(json.dumps({'ok': True}))\n"
        "except Exception as e:\n"
        "    payload = {\n"
        "        'ok': False,\n"
        "        'type': type(e).__name__,\n"
        "        'message': str(e),\n"
        "        'traceback': traceback.format_exc(),\n"
        "    }\n"
        "    print(json.dumps(payload))\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", probe_code, scan_source],
            cwd=repo_root / "src",
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = (result.stdout or "")
        stderr = (result.stderr or "")
        stdout_lines = stdout.splitlines()
        stderr_lines = stderr.splitlines()

        parsed_probe = {}
        if len(stdout_lines) > 0:
            try:
                parsed_probe = json.loads(stdout_lines[-1])
            except Exception:
                parsed_probe = {}

        if parsed_probe.get("ok") is True:
            reason = "OK"
        elif isinstance(parsed_probe, dict) and parsed_probe.get("type"):
            reason = f"{parsed_probe.get('type')}: {str(parsed_probe.get('message', '')).splitlines()[0]}"
        elif len(stderr_lines) > 0:
            reason = stderr_lines[-1].strip()
        else:
            reason = f"probe_exit_{result.returncode}"

        def _select_tail(lines: List[str]) -> str:
            if excerpt_lines <= 0:
                return "\n".join(lines)
            return "\n".join(lines[-excerpt_lines:])

        excerpt_parts = []
        if len(stdout_lines) > 0:
            excerpt_parts.append("STDOUT:\n" + _select_tail(stdout_lines))
        if len(stderr_lines) > 0:
            excerpt_parts.append("STDERR:\n" + _select_tail(stderr_lines))
        excerpt = "\n\n".join(excerpt_parts)

        return {
            "reason": reason,
            "returncode": result.returncode,
            "excerpt": excerpt,
            "stdout_tail": _select_tail(stdout_lines),
            "stderr_tail": _select_tail(stderr_lines),
            "exception_type": parsed_probe.get("type", ""),
            "exception_message": parsed_probe.get("message", ""),
            "exception_traceback": parsed_probe.get("traceback", ""),
        }
    except subprocess.TimeoutExpired:
        return {
            "reason": f"probe_timeout_{timeout_seconds}s",
            "returncode": None,
            "excerpt": "",
            "stdout_tail": "",
            "stderr_tail": "",
        }
    except Exception as exc:
        return {
            "reason": f"probe_exception: {str(exc)}",
            "returncode": None,
            "excerpt": "",
            "stdout_tail": "",
            "stderr_tail": "",
        }


def _aggregate_metadata(meta_list: List[dict], provider: str, model: str, mode: str) -> dict:
    if len(meta_list) == 0:
        return {
            "llm_provider": provider,
            "llm_model": model,
            "benchmark_mode": mode,
            "source_files_processed": 0,
        }

    sum_keys = [
        "files",
        "contracts",
        "functions",
        "loc",
        "files_after_filter",
        "files_after_step_1",
        "files_after_step_2",
        "files_after_static",
        "contracts_after_filter",
        "contracts_after_step_1",
        "contracts_after_step_2",
        "contracts_after_static",
        "functions_after_filter",
        "functions_after_step_1",
        "functions_after_step_2",
        "functions_after_static",
        "rules_types_for_step_1",
        "rules_types_for_step_2",
        "rules_types_for_static",
        "rules_types_after_static",
        "used_time",
        "vul_before_static",
        "vul_after_static",
        "vul_after_merge",
        "vul_after_remediation",
        "token_sent",
        "token_received",
        "token_sent_gpt4",
        "token_received_gpt4",
        "estimated_cost",
    ]

    aggregated = {}
    for key in sum_keys:
        aggregated[key] = 0
        for meta in meta_list:
            value = meta.get(key, 0)
            if isinstance(value, (int, float)):
                aggregated[key] += value

    aggregated["rules_loaded"] = max(meta.get("rules_loaded", 0) for meta in meta_list)
    aggregated["llm_provider"] = provider
    aggregated["llm_model"] = model
    aggregated["benchmark_mode"] = mode

    falcon_true = 0
    falcon_effective_true = 0
    for meta in meta_list:
        if meta.get("falcon_initialized") is True:
            falcon_true += 1
        if meta.get("falcon_initialized_effective", meta.get("falcon_initialized")) is True:
            falcon_effective_true += 1
    aggregated["falcon_initialized_runs"] = falcon_true
    aggregated["falcon_initialized_effective_runs"] = falcon_effective_true
    aggregated["falcon_total_runs"] = len(meta_list)
    aggregated["falcon_initialized"] = falcon_true == len(meta_list)
    aggregated["falcon_initialized_effective"] = falcon_effective_true == len(meta_list)
    aggregated["falcon_probe_recovered_runs"] = max(0, falcon_effective_true - falcon_true)
    aggregated["source_files_processed"] = len(meta_list)

    if "llm_base_url" in meta_list[0]:
        aggregated["llm_base_url"] = meta_list[0].get("llm_base_url")

    return aggregated


def _write_json_atomic(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp_path, path)


def _parse_shard_id_from_meta_filename(name: str) -> str:
    match = re.match(r"^(\d{4})\.json\.metadata\.json$", name)
    if match is None:
        return ""
    return match.group(1)


def _load_existing_shard_outputs(run_root: Path) -> Dict[str, Tuple[dict, dict]]:
    existing: Dict[str, Tuple[dict, dict]] = {}
    if not run_root.exists():
        return existing

    for meta_path in sorted(run_root.glob("*.json.metadata.json")):
        shard_id = _parse_shard_id_from_meta_filename(meta_path.name)
        if shard_id == "":
            continue

        shard_output = run_root / f"{shard_id}.json"
        if not shard_output.exists():
            continue

        try:
            with open(shard_output, "r", encoding="utf-8") as f:
                shard_json = json.load(f)
            with open(meta_path, "r", encoding="utf-8") as f:
                shard_meta = json.load(f)
            existing[shard_id] = (shard_json, shard_meta)
        except Exception:
            continue

    return existing


def _write_resume_progress(
    progress_path: Path,
    total_shards: int,
    succeeded_shards: int,
    failed_shards: int,
    resumed_shards: int,
    started_at: float,
):
    progress = {
        "total_shards": total_shards,
        "succeeded_shards": succeeded_shards,
        "failed_shards": failed_shards,
        "resumed_shards": resumed_shards,
        "processed_shards": succeeded_shards + failed_shards,
        "remaining_shards": max(0, total_shards - (succeeded_shards + failed_shards)),
        "elapsed_seconds": time.time() - started_at,
        "updated_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _write_json_atomic(progress_path, progress)


def run_scan_per_file(
    repo_root: Path,
    source: str,
    output_file: Path,
    provider: str,
    model: str,
    openai_key: str = "",
    ollama_url: str = "http://localhost:11434",
    ollama_url_second: str = "",
    ollama_timeout_seconds: int = 60,
    show_shard_logs: bool = False,
    failed_log_tail_lines: int = 25,
    shard_timeout_seconds: int = 0,
    auto_install_solc: bool = False,
    disable_falcon: bool = False,
    disable_static: bool = False,
    enable_remediation: bool = False,
    remediation_max_rounds: int = 3,
    remediation_drop_fixed: bool = False,
    remediation_verify_mode: str = "llm-self-check",
    max_files: int = 0,
    resume: bool = True,
) -> Tuple[Path, Path]:
    run_started_at = time.time()
    source_root = Path(source).resolve()
    sol_files = _list_sol_files(source)
    if len(sol_files) == 0:
        raise RuntimeError(f"No Solidity files found under source: {source}")

    discovered_sol_files = len(sol_files)
    if max_files > 0 and discovered_sol_files > max_files:
        sol_files = sol_files[:max_files]
        print(
            f"[subset] limiting per-file benchmark to first {len(sol_files)} Solidity file(s) "
            f"out of {discovered_sol_files} discovered"
        )

    required_versions = _collect_required_solc_versions(sol_files)
    installed_versions = _get_installed_solc_versions()
    missing_versions = sorted(list(set(required_versions) - set(installed_versions)))

    print(f"[preflight] required solc versions: {required_versions}")
    print(f"[preflight] installed solc versions: {installed_versions}")
    if len(missing_versions) > 0:
        print(f"[preflight] missing solc versions: {missing_versions}")
        if auto_install_solc:
            for v in missing_versions:
                ok = _install_solc_version(v)
                print(f"[preflight] install solc {v}: {'ok' if ok else 'failed'}")
            installed_versions = _get_installed_solc_versions()
            missing_versions = sorted(list(set(required_versions) - set(installed_versions)))
            if len(missing_versions) > 0:
                print(f"[preflight] still missing after install attempt: {missing_versions}")
    else:
        print("[preflight] all required solc versions are installed")

    shard_root = output_file.parent / f"_shards_{output_file.stem}"
    input_root = shard_root / "inputs"
    run_root = shard_root / "runs"
    progress_path = shard_root / "resume_progress.json"

    if shard_root.exists() and (not resume):
        shutil.rmtree(shard_root)
    input_root.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True, exist_ok=True)

    existing_shards = _load_existing_shard_outputs(run_root) if resume else {}
    if resume and len(existing_shards) > 0:
        print(f"[resume] found {len(existing_shards)} completed shard(s) under: {run_root}")

    all_results = []
    all_meta = []
    failed = []
    solc_switch_ok = 0
    solc_switch_fail = 0
    solc_switch_skipped = 0
    resumed_shards = 0

    _write_resume_progress(
        progress_path=progress_path,
        total_shards=len(sol_files),
        succeeded_shards=0,
        failed_shards=0,
        resumed_shards=0,
        started_at=run_started_at,
    )

    for index, sol_file in enumerate(sol_files):
        shard_id = f"{index:04d}"
        complexity = _estimate_sol_file_complexity(sol_file)
        print(
            f"  [{index+1}/{len(sol_files)}] running: {sol_file} "
            f"(loc={complexity['loc']}, contracts={complexity['contracts']}, functions={complexity['functions']})"
        )

        requested_version = _extract_solc_version_from_pragma(sol_file)

        existing_entry = existing_shards.get(shard_id)
        if existing_entry is not None:
            shard_json, shard_meta = existing_entry
            recorded_source = str(shard_meta.get("source_file", "")).strip()
            if recorded_source == str(sol_file):
                shard_meta.setdefault("source_file", str(sol_file))
                shard_meta.setdefault("shard_id", shard_id)
                shard_meta.setdefault("requested_solc_version", requested_version)
                shard_meta.setdefault("solc_switch_status", "skipped" if requested_version == "" else "unknown")

                switch_status = str(shard_meta.get("solc_switch_status", "")).strip().lower()
                if switch_status == "ok":
                    solc_switch_ok += 1
                elif switch_status == "fail":
                    solc_switch_fail += 1
                else:
                    solc_switch_skipped += 1

                all_results.extend(shard_json.get("results", []))
                all_meta.append(shard_meta)
                resumed_shards += 1
                print(f"  [{index+1}/{len(sol_files)}] resumed: {sol_file} (shard={shard_id})")

                _write_resume_progress(
                    progress_path=progress_path,
                    total_shards=len(sol_files),
                    succeeded_shards=len(all_meta),
                    failed_shards=len(failed),
                    resumed_shards=resumed_shards,
                    started_at=run_started_at,
                )
                continue

            print(
                f"  [{index+1}/{len(sol_files)}] resume source mismatch for shard {shard_id}, rerunning"
            )

        if requested_version == "":
            solc_switch_status = "skipped"
            solc_switch_skipped += 1
        elif _try_switch_solc(requested_version):
            solc_switch_status = "ok"
            solc_switch_ok += 1
        else:
            solc_switch_status = "fail"
            solc_switch_fail += 1

        shard_input = input_root / shard_id
        shard_input.mkdir(parents=True, exist_ok=True)
        # Keep a pointer to the original file for traceability while preserving
        # the real source path for compilation and import resolution.
        with open(shard_input / "SOURCE_PATH.txt", "w", encoding="utf-8") as f:
            f.write(str(sol_file))
        closure_count, missing_local_imports = _copy_solidity_dependency_closure(
            sol_file=sol_file,
            source_root=source_root,
            shard_input=shard_input,
        )

        shard_output = run_root / f"{shard_id}.json"
        shard_meta_path = Path(str(shard_output) + ".metadata.json")
        shard_started_at = time.time()
        try:
            result = run_scan_with_logs_timeout(
                repo_root=repo_root,
                source=str(shard_input),
                output_file=shard_output,
                provider=provider,
                model=model,
                openai_key=openai_key,
                ollama_url=ollama_url,
                ollama_url_second=ollama_url_second,
                ollama_timeout_seconds=ollama_timeout_seconds,
                timeout_seconds=shard_timeout_seconds,
                disable_falcon=disable_falcon,
                disable_static=disable_static,
                enable_remediation=enable_remediation,
                remediation_max_rounds=remediation_max_rounds,
                remediation_drop_fixed=remediation_drop_fixed,
                remediation_verify_mode=remediation_verify_mode,
            )

            if show_shard_logs:
                if result.stdout.strip() != "":
                    print("----- shard stdout begin -----")
                    print(result.stdout)
                    print("----- shard stdout end -----")
                if result.stderr.strip() != "":
                    print("----- shard stderr begin -----")
                    print(result.stderr)
                    print("----- shard stderr end -----")

            if result.returncode != 0:
                stderr_tail = "\n".join(result.stderr.splitlines()[-failed_log_tail_lines:])
                stdout_tail = "\n".join(result.stdout.splitlines()[-failed_log_tail_lines:])
                failed.append(
                    {
                        "file": str(sol_file),
                        "error": f"exit status {result.returncode}",
                        "elapsed_seconds": time.time() - shard_started_at,
                        "complexity": complexity,
                        "stderr_tail": stderr_tail,
                        "stdout_tail": stdout_tail,
                    }
                )
                print(f"  [{index+1}/{len(sol_files)}] failed: {sol_file}")
                _write_resume_progress(
                    progress_path=progress_path,
                    total_shards=len(sol_files),
                    succeeded_shards=len(all_meta),
                    failed_shards=len(failed),
                    resumed_shards=resumed_shards,
                    started_at=run_started_at,
                )
                continue

            with open(shard_output, "r", encoding="utf-8") as f:
                shard_json = json.load(f)
            with open(shard_meta_path, "r", encoding="utf-8") as f:
                shard_meta = json.load(f)
            shard_meta["source_complexity"] = complexity
            shard_meta["shard_elapsed_seconds"] = time.time() - shard_started_at
            shard_meta["source_file"] = str(sol_file)
            shard_meta["shard_closure_files"] = closure_count
            shard_meta["missing_local_imports"] = missing_local_imports
            shard_meta["shard_id"] = shard_id
            shard_meta["requested_solc_version"] = requested_version
            shard_meta["solc_switch_status"] = solc_switch_status
            shard_meta["falcon_initialized_effective"] = shard_meta.get("falcon_initialized") is True
            if (not disable_falcon) and shard_meta.get("falcon_initialized") is not True:
                probe = _probe_falcon_initialization(
                    repo_root=repo_root,
                    scan_source=str(shard_input),
                )
                shard_meta["falcon_init_probe"] = probe.get("reason", "unknown")
                shard_meta["falcon_init_probe_returncode"] = probe.get("returncode")
                shard_meta["falcon_init_probe_excerpt"] = probe.get("excerpt", "")
                shard_meta["falcon_init_probe_stdout_tail"] = probe.get("stdout_tail", "")
                shard_meta["falcon_init_probe_stderr_tail"] = probe.get("stderr_tail", "")
                shard_meta["falcon_init_probe_exception_type"] = probe.get("exception_type", "")
                shard_meta["falcon_init_probe_exception_message"] = probe.get("exception_message", "")
                shard_meta["falcon_init_probe_exception_traceback"] = probe.get("exception_traceback", "")
                if probe.get("reason") == "OK":
                    shard_meta["falcon_initialized_effective"] = True
            elif disable_falcon:
                shard_meta["falcon_init_probe"] = "disabled_by_flag"

            with open(shard_meta_path, "w", encoding="utf-8") as f:
                json.dump(shard_meta, f, indent=2)

            all_results.extend(shard_json.get("results", []))
            all_meta.append(shard_meta)
            print(f"  [{index+1}/{len(sol_files)}] ok: {sol_file} (pragma={requested_version or 'unknown'})")
        except subprocess.TimeoutExpired as timeout_exc:
            timeout_stderr = _normalize_subprocess_output(timeout_exc.stderr)
            timeout_stdout = _normalize_subprocess_output(timeout_exc.stdout)
            failed.append(
                {
                    "file": str(sol_file),
                    "error": f"timeout after {shard_timeout_seconds} seconds",
                    "elapsed_seconds": time.time() - shard_started_at,
                    "complexity": complexity,
                    "stderr_tail": "\n".join(timeout_stderr.splitlines()[-failed_log_tail_lines:]),
                    "stdout_tail": "\n".join(timeout_stdout.splitlines()[-failed_log_tail_lines:]),
                }
            )
            print(f"  [{index+1}/{len(sol_files)}] timeout: {sol_file}")
        except Exception as e:
            failed.append({"file": str(sol_file), "error": str(e), "elapsed_seconds": time.time() - shard_started_at, "complexity": complexity})
            print(f"  [{index+1}/{len(sol_files)}] failed: {sol_file}")

        _write_resume_progress(
            progress_path=progress_path,
            total_shards=len(sol_files),
            succeeded_shards=len(all_meta),
            failed_shards=len(failed),
            resumed_shards=resumed_shards,
            started_at=run_started_at,
        )

    merged = {
        "version": "1.1.0",
        "success": len(failed) == 0,
        "message": None if len(failed) == 0 else f"{len(failed)} shard(s) failed",
        "results": _dedupe_results(all_results),
    }
    merged_meta = _aggregate_metadata(all_meta, provider, model, mode="per-file")
    merged_meta["vul_after_merge"] = len(merged["results"])
    merged_meta["vul_after_remediation"] = len(merged["results"])
    merged_meta["solc_switch_ok"] = solc_switch_ok
    merged_meta["solc_switch_fail"] = solc_switch_fail
    merged_meta["solc_switch_skipped"] = solc_switch_skipped
    merged_meta["source_files_total"] = len(sol_files)
    merged_meta["source_files_discovered"] = discovered_sol_files
    merged_meta["source_files_limit"] = int(max_files) if max_files > 0 else 0
    merged_meta["source_files_succeeded"] = len(all_meta)
    merged_meta["source_files_failed"] = len(failed)
    merged_meta["source_files_resumed"] = resumed_shards
    merged_meta["resume_enabled"] = resume
    merged_meta["resume_progress_file"] = str(progress_path)
    merged_meta["required_solc_versions"] = required_versions
    merged_meta["installed_solc_versions"] = installed_versions
    merged_meta["missing_solc_versions"] = missing_versions

    remediation_attempted = 0
    remediation_fixed = 0
    remediation_unresolved = 0
    remediation_skipped_missing_source = 0
    remediation_used_time = 0.0
    remediation_rounds_weighted = 0.0
    remediation_total_rounds_used = 0
    remediation_max_rounds_used = 0
    remediation_rounds_histogram = collections.Counter()
    remediation_verify_modes = collections.Counter()
    remediation_verify_engines = collections.Counter()
    remediation_enabled_any = False
    remediation_max_rounds_observed = 0
    for shard_meta in all_meta:
        if shard_meta.get("remediation_enabled") is True:
            remediation_enabled_any = True
            remediation_max_rounds_observed = max(remediation_max_rounds_observed, int(shard_meta.get("remediation_max_rounds", 0) or 0))
            stats = shard_meta.get("remediation_stats", {})
            attempted = int(stats.get("attempted", 0) or 0)
            fixed = int(stats.get("fixed", 0) or 0)
            unresolved = int(stats.get("unresolved", 0) or 0)
            skipped_missing_source = int(stats.get("skipped_missing_source", 0) or 0)
            avg_rounds = float(stats.get("avg_rounds", 0.0) or 0.0)
            used_time_seconds = float(stats.get("used_time_seconds", 0.0) or 0.0)
            total_rounds_used = int(stats.get("total_rounds_used", 0) or 0)
            max_rounds_used = int(stats.get("max_rounds_used", 0) or 0)
            verify_mode = str(stats.get("verify_mode", shard_meta.get("remediation_verify_mode", "")) or "").strip()
            rounds_histogram = stats.get("rounds_histogram", {})
            verify_engines = stats.get("verify_engines", {})

            remediation_attempted += attempted
            remediation_fixed += fixed
            remediation_unresolved += unresolved
            remediation_skipped_missing_source += skipped_missing_source
            remediation_used_time += used_time_seconds
            remediation_rounds_weighted += (avg_rounds * attempted)
            remediation_total_rounds_used += total_rounds_used
            remediation_max_rounds_used = max(remediation_max_rounds_used, max_rounds_used)
            if verify_mode != "":
                remediation_verify_modes[verify_mode] += 1
            if isinstance(rounds_histogram, dict):
                for rounds_key, rounds_count in rounds_histogram.items():
                    try:
                        remediation_rounds_histogram[str(rounds_key)] += int(rounds_count)
                    except Exception:
                        continue
            if isinstance(verify_engines, dict):
                for engine_name, engine_count in verify_engines.items():
                    try:
                        remediation_verify_engines[str(engine_name)] += int(engine_count)
                    except Exception:
                        continue

    if remediation_enabled_any:
        merged_meta["remediation_enabled"] = True
        merged_meta["remediation_max_rounds"] = remediation_max_rounds_observed
        merged_meta["remediation_drop_fixed"] = remediation_drop_fixed
        merged_meta["remediation_verify_mode"] = remediation_verify_mode
        merged_meta["remediation_stats"] = {
            "attempted": remediation_attempted,
            "fixed": remediation_fixed,
            "unresolved": remediation_unresolved,
            "skipped_missing_source": remediation_skipped_missing_source,
            "avg_rounds": _safe_div(remediation_rounds_weighted, remediation_attempted),
            "total_rounds_used": remediation_total_rounds_used,
            "max_rounds_used": remediation_max_rounds_used,
            "rounds_histogram": dict(remediation_rounds_histogram),
            "fixed_rate": _safe_div(remediation_fixed, remediation_attempted),
            "unresolved_rate": _safe_div(remediation_unresolved, remediation_attempted),
            "verify_modes_seen": dict(remediation_verify_modes),
            "verify_engines": dict(remediation_verify_engines),
            "used_time_seconds": remediation_used_time,
        }

    if disable_falcon:
        merged_meta["falcon_disabled"] = True
        merged_meta["falcon_initialized_runs"] = 0
        merged_meta["falcon_initialized_effective_runs"] = 0
        merged_meta["falcon_total_runs"] = 0
        merged_meta["falcon_initialized"] = False
        merged_meta["falcon_initialized_effective"] = False
        merged_meta["falcon_probe_recovered_runs"] = 0
    falcon_reason_counter = collections.Counter()
    falcon_failure_samples = []
    if not disable_falcon:
        for shard_meta in all_meta:
            if shard_meta.get("falcon_initialized") is not True:
                reason = shard_meta.get("falcon_init_probe", "unknown")
                if reason != "OK":
                    falcon_reason_counter[reason] += 1
                    falcon_failure_samples.append(
                        {
                            "shard_id": shard_meta.get("shard_id"),
                            "source_path": shard_meta.get("source_file"),
                            "reason": reason,
                            "probe_returncode": shard_meta.get("falcon_init_probe_returncode"),
                            "probe_excerpt": shard_meta.get("falcon_init_probe_excerpt", ""),
                            "probe_exception_type": shard_meta.get("falcon_init_probe_exception_type", ""),
                            "probe_exception_message": shard_meta.get("falcon_init_probe_exception_message", ""),
                            "probe_exception_traceback": shard_meta.get("falcon_init_probe_exception_traceback", ""),
                            "missing_local_imports": shard_meta.get("missing_local_imports", []),
                            "shard_closure_files": shard_meta.get("shard_closure_files"),
                        }
                    )
    if len(falcon_reason_counter) > 0:
        merged_meta["falcon_init_failure_reasons"] = dict(falcon_reason_counter)
        merged_meta["falcon_init_failure_samples"] = falcon_failure_samples
    if len(failed) > 0:
        merged_meta["failed_files"] = failed

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    with open(Path(str(output_file) + ".metadata.json"), "w", encoding="utf-8") as f:
        json.dump(merged_meta, f, indent=2)

    _write_resume_progress(
        progress_path=progress_path,
        total_shards=len(sol_files),
        succeeded_shards=len(all_meta),
        failed_shards=len(failed),
        resumed_shards=resumed_shards,
        started_at=run_started_at,
    )

    return output_file, Path(str(output_file) + ".metadata.json")


def read_metadata(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_metrics(openai_meta, ollama_meta):
    return {
        "openai": {
            "provider": openai_meta.get("llm_provider"),
            "model": openai_meta.get("llm_model"),
            "vul_after_merge": openai_meta.get("vul_after_merge"),
            "vul_after_remediation": openai_meta.get("vul_after_remediation"),
            "vul_after_static": openai_meta.get("vul_after_static"),
            "used_time": openai_meta.get("used_time"),
            "token_sent": openai_meta.get("token_sent"),
            "token_received": openai_meta.get("token_received"),
            "estimated_cost": openai_meta.get("estimated_cost"),
        },
        "ollama": {
            "provider": ollama_meta.get("llm_provider"),
            "model": ollama_meta.get("llm_model"),
            "vul_after_merge": ollama_meta.get("vul_after_merge"),
            "vul_after_remediation": ollama_meta.get("vul_after_remediation"),
            "vul_after_static": ollama_meta.get("vul_after_static"),
            "used_time": ollama_meta.get("used_time"),
            "token_sent": ollama_meta.get("token_sent"),
            "token_received": ollama_meta.get("token_received"),
            "estimated_cost": ollama_meta.get("estimated_cost"),
        },
    }


def _load_shard_source_map_for_output(output_file: Path) -> Dict[str, str]:
    shard_source_map: Dict[str, str] = {}
    shard_root = output_file.parent / f"_shards_{output_file.stem}"
    run_root = shard_root / "runs"
    if not run_root.exists():
        return shard_source_map

    for meta_path in sorted(run_root.glob("*.json.metadata.json")):
        shard_id = _parse_shard_id_from_meta_filename(meta_path.name)
        if shard_id == "":
            continue
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                shard_meta = json.load(f)
            source_file = str(shard_meta.get("source_file", "")).strip()
            if source_file != "":
                shard_source_map[shard_id] = source_file
        except Exception:
            continue

    return shard_source_map


def _run_dive_evaluation_for_output(
    output_file: Path,
    metadata_path: Path,
    source: str,
    dive_labels_csv: str,
    dive_eval_mode: str,
):
    labels_path = Path(dive_labels_csv).expanduser().resolve()
    if not labels_path.exists():
        raise FileNotFoundError(f"DIVE labels CSV not found: {labels_path}")

    with open(output_file, "r", encoding="utf-8") as f:
        output_json = json.load(f)
    findings = output_json.get("results", [])

    source_files = _list_sol_files(source)
    shard_source_map = _load_shard_source_map_for_output(output_file)
    evaluator = DIVEEvaluator(labels_csv_path=labels_path, mapping_mode=dive_eval_mode)
    report = evaluator.evaluate(
        findings=findings,
        source_files=source_files,
        shard_source_map=shard_source_map,
    )

    report_path = output_file.parent / f"{output_file.stem}.dive_eval.json"
    _write_json_atomic(report_path, report)

    meta = read_metadata(metadata_path)
    meta["dive_evaluation_file"] = str(report_path)
    meta["dive_labels_csv"] = str(labels_path)
    meta["dive_eval_mode"] = dive_eval_mode
    meta["dive_evaluation_summary"] = {
        "mapped_dive_labels": report.get("mapped_dive_labels", []),
        "unsupported_dive_labels": report.get("unsupported_dive_labels", []),
        "evaluated_contracts": report.get("dataset", {}).get("evaluated_contracts", 0),
        "contracts_with_predictions": report.get("prediction_summary", {}).get("contracts_with_predictions", 0),
        "micro": report.get("metrics", {}).get("micro", {}),
        "macro": report.get("metrics", {}).get("macro", {}),
        "exact_contract_match_accuracy": report.get("metrics", {}).get("exact_contract_match_accuracy", 0.0),
    }
    _write_json_atomic(metadata_path, meta)

    return report_path


def _ensure_run_manifest(run_dir: Path, manifest: dict, resume: bool, force_resume: bool):
    manifest_path = run_dir / "run_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            existing = json.load(f)

        existing_core = dict(existing)
        requested_core = dict(manifest)
        existing_core.pop("created_at_utc", None)
        requested_core.pop("created_at_utc", None)

        if existing_core != requested_core:
            if resume and (not force_resume):
                raise RuntimeError(
                    "Run manifest mismatch for requested run-id. "
                    "Use --force-resume to continue anyway, or choose a new --run-id."
                )
        return manifest_path

    _write_json_atomic(manifest_path, manifest)
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description="Benchmark GPTScan with OpenAI vs Ollama on the same source path")
    parser.add_argument("-s", "--source", required=True, help="Source directory for GPTScan")
    parser.add_argument("-o", "--output-dir", default="benchmark_results", help="Directory where benchmark outputs are stored")
    parser.add_argument("--mode", choices=["compare", "ollama-only"], default="ollama-only", help="Run both providers or Ollama only")
    parser.add_argument("--falcon-mode", choices=["auto", "per-file"], default="auto", help="Use per-file runs to preserve Falcon static coverage on plain multi-file directories")
    parser.add_argument("--max-files", type=int, default=0, help="Process at most N Solidity files in per-file mode (0 processes all files)")
    parser.add_argument("--dataset-kind", choices=["auto", "top200", "defihacks", "web3bugs", "dive", "custom"], default="auto", help="Annotate outputs with dataset-aware derived metrics and paper baselines")
    parser.add_argument("--dive-labels-csv", default="", help="Path to DIVE labels CSV for labeled evaluation")
    parser.add_argument("--dive-eval-mode", choices=["high-confidence"], default="high-confidence", help="DIVE evaluator mapping strategy")
    parser.add_argument("--openai-key", default="", help="OpenAI API key used for baseline")
    parser.add_argument("--openai-model", default="gpt-3.5-turbo", help="OpenAI model for baseline")
    parser.add_argument("--ollama-model", default="qwen2.5-coder:7b", help="Ollama model to benchmark")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama base URL")
    parser.add_argument("--ollama-url-second", default="", help="Optional second Ollama base URL for verification")
    parser.add_argument("--ollama-timeout-seconds", type=int, default=60, help="Per-LLM call timeout (seconds) for Ollama requests")
    parser.add_argument("--run-id", default="", help="Stable run identifier used for resume (defaults to timestamp)")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True, help="Reuse completed provider outputs and per-file shards when available")
    parser.add_argument("--force-resume", action="store_true", help="Allow resume even if run manifest settings changed")
    parser.add_argument("--show-shard-logs", action="store_true", help="Print full stdout/stderr from each per-file shard run")
    parser.add_argument("--failed-log-tail-lines", type=int, default=25, help="How many stdout/stderr lines to keep per failed shard")
    parser.add_argument("--shard-timeout-seconds", type=int, default=0, help="Kill a per-file shard if runtime exceeds this timeout (0 disables timeout)")
    parser.add_argument("--auto-install-solc", action="store_true", help="Attempt to install missing solc versions found in pragma directives")
    parser.add_argument("--disable-falcon", action="store_true", help="Disable Falcon initialization for this benchmark run")
    parser.add_argument("--disable-static", action="store_true", help="Disable static analysis stage for this benchmark run")
    parser.add_argument("--enable-remediation", action="store_true", help="Enable post-scan LLM remediation loop")
    parser.add_argument("--remediation-max-rounds", type=int, default=3, help="Maximum remediation fix/verify rounds per finding")
    parser.add_argument("--drop-fixed-findings", action="store_true", help="Drop findings marked fixed by remediation from final output")
    parser.add_argument("--remediation-verify-mode", choices=["llm-self-check", "llm-rule-recheck", "slither-rule-recheck", "falcon-rule-recheck"], default="llm-self-check", help="Verification strategy for remediation rounds")
    args = parser.parse_args()

    if args.mode == "compare" and args.openai_key.strip() == "":
        parser.error("--openai-key is required when --mode compare")
    if args.max_files < 0:
        parser.error("--max-files must be >= 0")
    if args.max_files > 0 and args.falcon_mode != "per-file":
        parser.error("--max-files is currently supported only with --falcon-mode per-file")

    resolved_dataset_kind = _resolve_dataset_kind(args.source, args.dataset_kind)
    should_run_dive_eval = resolved_dataset_kind == "dive" or args.dive_labels_csv.strip() != ""
    if resolved_dataset_kind == "dive" and args.dive_labels_csv.strip() == "":
        parser.error("--dive-labels-csv is required when dataset kind resolves to 'dive'")

    repo_root = Path(__file__).resolve().parent
    run_id = args.run_id.strip() if args.run_id.strip() != "" else datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = repo_root / args.output_dir / run_id

    if run_dir.exists() and (not args.resume) and args.run_id.strip() != "":
        raise RuntimeError(
            f"Run directory already exists: {run_dir}. Use --resume or choose a different --run-id."
        )
    run_dir.mkdir(parents=True, exist_ok=True)

    run_manifest = {
        "source": str(Path(args.source).resolve()),
        "mode": args.mode,
        "falcon_mode": args.falcon_mode,
        "max_files": int(args.max_files),
        "dataset_kind": resolved_dataset_kind,
        "dive_labels_csv": str(Path(args.dive_labels_csv).expanduser().resolve()) if args.dive_labels_csv.strip() != "" else "",
        "dive_eval_mode": args.dive_eval_mode,
        "disable_falcon": bool(args.disable_falcon),
        "disable_static": bool(args.disable_static),
        "enable_remediation": bool(args.enable_remediation),
        "remediation_max_rounds": int(args.remediation_max_rounds),
        "remediation_drop_fixed": bool(args.drop_fixed_findings),
        "remediation_verify_mode": args.remediation_verify_mode,
        "shard_timeout_seconds": int(args.shard_timeout_seconds),
        "auto_install_solc": bool(args.auto_install_solc),
        "created_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
    }
    manifest_path = _ensure_run_manifest(
        run_dir=run_dir,
        manifest=run_manifest,
        resume=bool(args.resume),
        force_resume=bool(args.force_resume),
    )
    print(f"[run] manifest: {manifest_path}")

    ollama_output = run_dir / "ollama_output.json"

    def execute_scan(provider: str, model: str, output_path: Path, key: str = ""):
        if args.falcon_mode == "per-file":
            return run_scan_per_file(
                repo_root=repo_root,
                source=args.source,
                output_file=output_path,
                provider=provider,
                model=model,
                openai_key=key,
                ollama_url=args.ollama_url,
                ollama_url_second=args.ollama_url_second,
                ollama_timeout_seconds=args.ollama_timeout_seconds,
                show_shard_logs=args.show_shard_logs,
                failed_log_tail_lines=args.failed_log_tail_lines,
                shard_timeout_seconds=args.shard_timeout_seconds,
                auto_install_solc=args.auto_install_solc,
                disable_falcon=args.disable_falcon,
                disable_static=args.disable_static,
                enable_remediation=args.enable_remediation,
                remediation_max_rounds=args.remediation_max_rounds,
                remediation_drop_fixed=args.drop_fixed_findings,
                remediation_verify_mode=args.remediation_verify_mode,
                max_files=args.max_files,
                resume=args.resume,
            )
        run_scan(
            repo_root=repo_root,
            source=args.source,
            output_file=output_path,
            provider=provider,
            model=model,
            openai_key=key,
            ollama_url=args.ollama_url,
            ollama_url_second=args.ollama_url_second,
            ollama_timeout_seconds=args.ollama_timeout_seconds,
            disable_falcon=args.disable_falcon,
            disable_static=args.disable_static,
            enable_remediation=args.enable_remediation,
            remediation_max_rounds=args.remediation_max_rounds,
            remediation_drop_fixed=args.drop_fixed_findings,
            remediation_verify_mode=args.remediation_verify_mode,
        )
        return output_path, Path(str(output_path) + ".metadata.json")

    openai_output = run_dir / "openai_output.json"

    if args.mode == "compare":
        openai_meta_path = Path(str(openai_output) + ".metadata.json")
        if args.resume and openai_output.exists() and openai_meta_path.exists():
            print("[1/3] Reusing existing OpenAI output (resume mode)...")
        else:
            print("[1/3] Running OpenAI baseline...")
            execute_scan("openai", args.openai_model, openai_output, key=args.openai_key)

        ollama_meta_path = Path(str(ollama_output) + ".metadata.json")
        if args.resume and ollama_output.exists() and ollama_meta_path.exists():
            print("[2/3] Reusing existing Ollama output (resume mode)...")
        else:
            print("[2/3] Running Ollama benchmark...")
            execute_scan("ollama", args.ollama_model, ollama_output, key="")
    else:
        ollama_meta_path = Path(str(ollama_output) + ".metadata.json")
        if args.resume and ollama_output.exists() and ollama_meta_path.exists():
            print("[1/2] Reusing existing Ollama output (resume mode)...")
        else:
            print("[1/2] Running Ollama benchmark...")
            execute_scan("ollama", args.ollama_model, ollama_output, key="")

    ollama_meta_path = Path(str(ollama_output) + ".metadata.json")
    ollama_meta = _persist_enriched_metadata(
        metadata_path=ollama_meta_path,
        source=args.source,
        dataset_kind=args.dataset_kind,
    )
    if should_run_dive_eval:
        dive_report_path = _run_dive_evaluation_for_output(
            output_file=ollama_output,
            metadata_path=ollama_meta_path,
            source=args.source,
            dive_labels_csv=args.dive_labels_csv,
            dive_eval_mode=args.dive_eval_mode,
        )
        print(f"[eval] Ollama DIVE evaluation: {dive_report_path}")
        ollama_meta = read_metadata(ollama_meta_path)

    if args.mode == "compare":
        openai_meta_path = Path(str(openai_output) + ".metadata.json")
        openai_meta = _persist_enriched_metadata(
            metadata_path=openai_meta_path,
            source=args.source,
            dataset_kind=args.dataset_kind,
        )
        if should_run_dive_eval:
            dive_report_path_openai = _run_dive_evaluation_for_output(
                output_file=openai_output,
                metadata_path=openai_meta_path,
                source=args.source,
                dive_labels_csv=args.dive_labels_csv,
                dive_eval_mode=args.dive_eval_mode,
            )
            print(f"[eval] OpenAI DIVE evaluation: {dive_report_path_openai}")
            openai_meta = read_metadata(openai_meta_path)

        comparison = compare_metrics(openai_meta, ollama_meta)
        comparison["dataset_kind"] = _resolve_dataset_kind(args.source, args.dataset_kind)
        comparison["ollama_derived_metrics"] = ollama_meta.get("derived_metrics", {})
        comparison["openai_derived_metrics"] = openai_meta.get("derived_metrics", {})
        if "dive_evaluation_summary" in ollama_meta:
            comparison["ollama_dive_evaluation"] = ollama_meta.get("dive_evaluation_summary", {})
        if "dive_evaluation_summary" in openai_meta:
            comparison["openai_dive_evaluation"] = openai_meta.get("dive_evaluation_summary", {})
        comparison["run_id"] = run_id
        comparison["resume_enabled"] = bool(args.resume)
        comparison_path = run_dir / "comparison.json"
        with open(comparison_path, "w", encoding="utf-8") as f:
            json.dump(comparison, f, indent=2)

        print("[3/3] Benchmark complete")
        print(f"OpenAI output: {openai_output}")
        print(f"Ollama output: {ollama_output}")
        print(f"Comparison: {comparison_path}")
    else:
        summary = {
            "ollama": {
                "provider": ollama_meta.get("llm_provider"),
                "model": ollama_meta.get("llm_model"),
                "vul_after_merge": ollama_meta.get("vul_after_merge"),
                "vul_after_remediation": ollama_meta.get("vul_after_remediation"),
                "vul_after_static": ollama_meta.get("vul_after_static"),
                "used_time": ollama_meta.get("used_time"),
                "token_sent": ollama_meta.get("token_sent"),
                "token_received": ollama_meta.get("token_received"),
                "estimated_cost": ollama_meta.get("estimated_cost"),
                "derived_metrics": ollama_meta.get("derived_metrics", {}),
                "dive_evaluation_summary": ollama_meta.get("dive_evaluation_summary", {}),
            }
        }
        summary_path = run_dir / "summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print("[2/2] Benchmark complete")
        print(f"Ollama output: {ollama_output}")
        print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
