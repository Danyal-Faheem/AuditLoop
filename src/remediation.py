import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from antlr4helper.callgraph import CallGraph
from chatgpt_api import Chat
from remediation_verifier import FalconVerifier, SlitherVerifier


def _extract_code_block(text: str) -> str:
    fenced = re.findall(r"```(?:solidity)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        return fenced[0].strip()
    return text.strip()


def _extract_contract_block(file_text: str, contract_name: str) -> str:
    # Best-effort extraction of one contract/library/interface block by name.
    pattern = re.compile(rf"\b(contract|library|interface)\s+{re.escape(contract_name)}\b")
    match = pattern.search(file_text)
    if not match:
        return file_text

    brace_start = file_text.find("{", match.end())
    if brace_start == -1:
        return file_text

    depth = 0
    end_idx = None
    for idx in range(brace_start, len(file_text)):
        ch = file_text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end_idx = idx + 1
                break

    if end_idx is None:
        return file_text

    return file_text[match.start():end_idx]


def _response_still_vulnerable(answer: str) -> bool:
    normalized = answer.strip().lower()
    if normalized.startswith("yes"):
        return True
    if normalized.startswith("no"):
        return False

    m = re.search(r"\b(yes|no)\b", normalized)
    if m is None:
        # Conservative fallback when the model is ambiguous.
        return True
    return m.group(1) == "yes"


class RemediationEngine:
    def __init__(self, max_rounds: int, patches_root: Path, verify_mode: str = "llm-self-check", llm_timeout_seconds: int = 60, second_ollama_url: str = ""):
        self.max_rounds = max(1, int(max_rounds))
        self.patches_root = patches_root
        self.verify_mode = (verify_mode or "llm-self-check").strip().lower()
        if self.verify_mode not in {"llm-self-check", "llm-rule-recheck", "slither-rule-recheck", "falcon-rule-recheck"}:
            self.verify_mode = "llm-self-check"
        self.chat = Chat()
        self.slither_verifier = SlitherVerifier() if self.verify_mode == "slither-rule-recheck" else None
        self.falcon_verifier = FalconVerifier() if self.verify_mode == "falcon-rule-recheck" else None
        self.llm_timeout_seconds = max(1, int(llm_timeout_seconds or int(os.environ.get("GPTSCAN_OLLAMA_TIMEOUT", "60"))))
        self.second_ollama_url = (second_ollama_url or os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", "")).strip() or None
        self.patches_root.mkdir(parents=True, exist_ok=True)

    def _resolve_finding_location(self, cg: CallGraph, finding: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], int, int]:
        affected = finding.get("affectedFiles", [])
        if len(affected) == 0:
            return None, None, None, 0, 0

        file_path = affected[0].get("filePath")
        line_start = int(affected[0].get("range", {}).get("start", {}).get("line", 0) or 0)
        line_end = int(affected[0].get("range", {}).get("end", {}).get("line", 0) or 0)
        if not file_path:
            return None, None, None, line_start, line_end

        file_abs = os.path.abspath(file_path)
        if file_abs not in cg.files:
            return file_abs, None, None, line_start, line_end

        subcontracts = cg.files[file_abs].get("subcontracts", [])
        for contract in subcontracts:
            contract_name = contract.get("name")
            for func in contract.get("functions", []):
                loc = func.get("loc", {})
                try:
                    f_start = int(str(loc.get("start", "0:0")).split(":")[0])
                    f_end = int(str(loc.get("end", "0:0")).split(":")[0])
                except Exception:
                    continue
                if f_start <= line_start <= f_end:
                    return file_abs, contract_name, func.get("name"), line_start, line_end

        return file_abs, None, None, line_start, line_end

    def _build_fix_prompt(
        self,
        vulnerability_code: str,
        vulnerability_title: str,
        vulnerability_description: str,
        contract_code: str,
        function_name: Optional[str],
    ) -> str:
        target_hint = f"Target function: {function_name}" if function_name else "Target function: unknown"
        return (
            "You are a senior Solidity security engineer.\n"
            "Fix the vulnerability in the provided contract while preserving intended behavior and public interfaces whenever possible.\n"
            "Return ONLY patched Solidity code in a single markdown solidity code block.\n\n"
            f"Vulnerability code: {vulnerability_code}\n"
            f"Vulnerability title: {vulnerability_title}\n"
            f"Vulnerability description: {vulnerability_description}\n"
            f"{target_hint}\n\n"
            "Contract code:\n"
            "```solidity\n"
            f"{contract_code}\n"
            "```\n"
        )

    def _build_verify_prompt(self, vulnerability_code: str, vulnerability_title: str, patched_contract_code: str) -> str:
        return (
            "You are a Solidity vulnerability verifier.\n"
            "Determine whether the patched code is STILL vulnerable to the specified issue.\n"
            "Answer strictly with one word: YES or NO.\n"
            "YES means the vulnerability still exists. NO means it has been fixed.\n\n"
            f"Vulnerability code: {vulnerability_code}\n"
            f"Vulnerability title: {vulnerability_title}\n\n"
            "Patched contract:\n"
            "```solidity\n"
            f"{patched_contract_code}\n"
            "```\n"
        )

    def _build_rule_recheck_prompt(
        self,
        vulnerability_code: str,
        vulnerability_title: str,
        vulnerability_description: str,
        recommendation: str,
        patched_contract_code: str,
    ) -> str:
        return (
            "You are a strict smart-contract security reviewer.\n"
            "Re-evaluate the patched contract against the vulnerability rule details below.\n"
            "Answer strictly with one word: YES or NO.\n"
            "YES means the vulnerability still exists. NO means the vulnerability is fixed.\n\n"
            f"Vulnerability code: {vulnerability_code}\n"
            f"Vulnerability title: {vulnerability_title}\n"
            f"Rule description: {vulnerability_description}\n"
            f"Rule recommendation: {recommendation}\n\n"
            "Patched contract:\n"
            "```solidity\n"
            f"{patched_contract_code}\n"
            "```\n"
        )

    def remediate_findings(self, findings: List[Dict[str, Any]], cg: CallGraph) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        start = time.time()
        attempted = 0
        fixed = 0
        unresolved = 0
        skipped_missing_source = 0
        rounds_sum = 0
        rounds_histogram: Dict[str, int] = {}
        verify_engines: Dict[str, int] = {}

        updated = []
        for idx, finding in enumerate(findings):
            attempted += 1
            code = finding.get("code", "")
            title = finding.get("title", "")
            description = finding.get("description", "")

            file_path, contract_name, function_name, _, _ = self._resolve_finding_location(cg, finding)
            if file_path is None or (not os.path.exists(file_path)):
                finding["remediation"] = {
                    "attempted": True,
                    "status": "skipped_missing_source",
                    "rounds_used": 0,
                    "final_vulnerability_remains": True,
                    "artifact_path": "",
                    "rounds": [],
                }
                unresolved += 1
                skipped_missing_source += 1
                updated.append(finding)
                continue

            file_text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            contract_context = _extract_contract_block(file_text, contract_name) if contract_name else file_text

            finding_dir = self.patches_root / f"finding_{idx:04d}"
            finding_dir.mkdir(parents=True, exist_ok=True)

            round_records: List[Dict[str, Any]] = []
            final_artifact = ""
            is_fixed = False
            patched_code = ""

            for round_idx in range(1, self.max_rounds + 1):
                fix_prompt = self._build_fix_prompt(
                    vulnerability_code=code,
                    vulnerability_title=title,
                    vulnerability_description=description,
                    contract_code=contract_context,
                    function_name=function_name,
                )
                try:
                    fix_response = self.chat.sendMessages(fix_prompt, GPT4=False, timeout_seconds=self.llm_timeout_seconds)
                except Exception as exc:
                    # LLM failure — mark this finding as unresolved and skip further rounds
                    round_records.append({
                        "round": round_idx,
                        "artifact_path": "",
                        "verify_mode": self.verify_mode,
                        "verify_engine": "llm-failure",
                        "verify_response": f"llm-error: {str(exc)}",
                        "still_vulnerable": True,
                        "verifier_details": {"status": "llm-error", "message": str(exc)},
                    })
                    # stop further remediation rounds for this finding
                    break
                
                patched_code = _extract_code_block(fix_response)

                patch_file = finding_dir / f"round_{round_idx:02d}.sol"
                patch_file.write_text(patched_code, encoding="utf-8")
                final_artifact = str(patch_file)

                verify_engine = self.verify_mode
                verifier_details: Dict[str, Any] = {}

                if self.verify_mode == "slither-rule-recheck" and self.slither_verifier is not None:
                    verifier_details = self.slither_verifier.verify_patch(
                        patched_contract_path=patch_file,
                        finding_code=code,
                    )
                    if verifier_details.get("status") == "verified":
                        verify_response = str(verifier_details.get("summary", "")).strip()
                        still_vulnerable = bool(verifier_details.get("still_vulnerable", True))
                        verify_engine = "slither"
                    else:
                        verify_prompt = self._build_rule_recheck_prompt(
                            vulnerability_code=code,
                            vulnerability_title=title,
                            vulnerability_description=description,
                            recommendation=str(finding.get("recommendation", "")),
                            patched_contract_code=patched_code,
                        )
                        try:
                            # allow using a second Ollama instance for verification if configured
                            verify_response = self.chat.sendMessages(
                                verify_prompt,
                                GPT4=False,
                                timeout_seconds=self.llm_timeout_seconds,
                                override_ollama_base_url=self.second_ollama_url,
                            )
                        except Exception as exc:
                            verify_response = f"llm-error: {str(exc)}"
                            still_vulnerable = True
                            verify_engine = "llm-rule-recheck-fallback-llm-error"
                            verifier_details = {"status": "llm-error", "message": str(exc)}
                        else:
                            still_vulnerable = _response_still_vulnerable(verify_response)
                            verify_engine = "llm-rule-recheck-fallback"
                        still_vulnerable = _response_still_vulnerable(verify_response)
                        verify_engine = "llm-rule-recheck-fallback"
                elif self.verify_mode == "falcon-rule-recheck" and self.falcon_verifier is not None:
                    verifier_details = self.falcon_verifier.verify_patch(
                        patched_contract_path=patch_file,
                        finding_code=code,
                    )
                    verify_response = str(verifier_details.get("summary", verifier_details.get("message", "")).strip())
                    still_vulnerable = bool(verifier_details.get("still_vulnerable", True))
                    verify_engine = "falcon"
                elif self.verify_mode == "llm-rule-recheck":
                    verify_prompt = self._build_rule_recheck_prompt(
                        vulnerability_code=code,
                        vulnerability_title=title,
                        vulnerability_description=description,
                        recommendation=str(finding.get("recommendation", "")),
                        patched_contract_code=patched_code,
                    )
                    try:
                        verify_response = self.chat.sendMessages(verify_prompt, GPT4=False, timeout_seconds=self.llm_timeout_seconds, override_ollama_base_url=self.second_ollama_url)
                        still_vulnerable = _response_still_vulnerable(verify_response)
                    except Exception as exc:
                        verify_response = f"llm-error: {str(exc)}"
                        still_vulnerable = True
                        verify_engine = "llm-rule-recheck-llm-error"
                else:
                    verify_prompt = self._build_verify_prompt(
                        vulnerability_code=code,
                        vulnerability_title=title,
                        patched_contract_code=patched_code,
                    )
                    try:
                        verify_response = self.chat.sendMessages(verify_prompt, GPT4=False, timeout_seconds=self.llm_timeout_seconds, override_ollama_base_url=self.second_ollama_url)
                        still_vulnerable = _response_still_vulnerable(verify_response)
                    except Exception as exc:
                        verify_response = f"llm-error: {str(exc)}"
                        still_vulnerable = True
                        verify_engine = "llm-self-check-llm-error"

                verify_engines[verify_engine] = verify_engines.get(verify_engine, 0) + 1

                round_records.append(
                    {
                        "round": round_idx,
                        "artifact_path": str(patch_file),
                        "verify_mode": self.verify_mode,
                        "verify_engine": verify_engine,
                        "verify_response": verify_response.strip(),
                        "still_vulnerable": still_vulnerable,
                        "verifier_details": verifier_details,
                    }
                )

                if not still_vulnerable:
                    is_fixed = True
                    rounds_sum += round_idx
                    break

            if not is_fixed:
                rounds_sum += self.max_rounds
            rounds_used = len(round_records)
            rounds_histogram[str(rounds_used)] = rounds_histogram.get(str(rounds_used), 0) + 1

            if is_fixed:
                fixed += 1
            else:
                unresolved += 1

            finding["remediation"] = {
                "attempted": True,
                "status": "fixed" if is_fixed else "unresolved",
                "rounds_used": len(round_records),
                "max_rounds": self.max_rounds,
                "verify_mode": self.verify_mode,
                "final_vulnerability_remains": (not is_fixed),
                "artifact_path": final_artifact,
                "rounds": round_records,
            }
            updated.append(finding)

        avg_rounds = (rounds_sum / attempted) if attempted > 0 else 0.0
        fixed_rate = (fixed / attempted) if attempted > 0 else 0.0
        unresolved_rate = (unresolved / attempted) if attempted > 0 else 0.0
        max_rounds_used = 0
        for rounds_key in rounds_histogram.keys():
            try:
                max_rounds_used = max(max_rounds_used, int(rounds_key))
            except Exception:
                pass
        stats = {
            "attempted": attempted,
            "fixed": fixed,
            "unresolved": unresolved,
            "skipped_missing_source": skipped_missing_source,
            "avg_rounds": avg_rounds,
            "total_rounds_used": rounds_sum,
            "max_rounds_used": max_rounds_used,
            "rounds_histogram": rounds_histogram,
            "fixed_rate": fixed_rate,
            "unresolved_rate": unresolved_rate,
            "verify_mode": self.verify_mode,
            "verify_engines": verify_engines,
            "used_time_seconds": time.time() - start,
        }
        return updated, stats
