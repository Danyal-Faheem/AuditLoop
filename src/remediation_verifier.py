import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional


FINDING_TO_SLITHER_DETECTOR = {
    # High-confidence mapping for current medium-effort integration.
    "unauthorized-transfer": "arbitrary-send-erc20",
}

FINDING_TO_FALCON_DETECTOR = {
    # Keep this mapping conservative; unsupported finding codes are handled safely.
    "unauthorized-transfer": "arbitrary-send-erc20",
}


class SlitherVerifier:
    def __init__(self, timeout_seconds: int = 120):
        self.timeout_seconds = max(1, int(timeout_seconds))

    def _is_slither_available(self) -> bool:
        return shutil.which("slither") is not None

    def _parse_slither_json(self, json_path: Path) -> Optional[dict]:
        if not json_path.exists():
            return None
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def verify_patch(self, patched_contract_path: Path, finding_code: str) -> Dict[str, object]:
        if not self._is_slither_available():
            return {
                "status": "tool-unavailable",
                "tool": "slither",
                "message": "slither binary not found in PATH",
                "still_vulnerable": True,
            }

        detector = FINDING_TO_SLITHER_DETECTOR.get(str(finding_code).strip(), "")
        if detector == "":
            return {
                "status": "unsupported-finding",
                "tool": "slither",
                "message": f"no slither detector mapping for finding code '{finding_code}'",
                "still_vulnerable": True,
            }

        json_out = patched_contract_path.with_suffix(patched_contract_path.suffix + ".slither.json")
        cmd = [
            "slither",
            str(patched_contract_path),
            "--detect",
            detector,
            "--json",
            str(json_out),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "tool": "slither",
                "detector": detector,
                "message": f"slither timed out after {self.timeout_seconds} seconds",
                "still_vulnerable": True,
            }
        except Exception as exc:
            return {
                "status": "execution-error",
                "tool": "slither",
                "detector": detector,
                "message": str(exc),
                "still_vulnerable": True,
            }

        parsed = self._parse_slither_json(json_out)
        detectors = []
        if isinstance(parsed, dict):
            detectors = parsed.get("results", {}).get("detectors", []) or []

        if result.returncode != 0 and len(detectors) == 0:
            stderr_tail = "\n".join((result.stderr or "").splitlines()[-10:])
            stdout_tail = "\n".join((result.stdout or "").splitlines()[-10:])
            return {
                "status": "analysis-error",
                "tool": "slither",
                "detector": detector,
                "returncode": result.returncode,
                "stderr_tail": stderr_tail,
                "stdout_tail": stdout_tail,
                "still_vulnerable": True,
            }

        still_vulnerable = len(detectors) > 0
        return {
            "status": "verified",
            "tool": "slither",
            "detector": detector,
            "detectors_found": len(detectors),
            "still_vulnerable": still_vulnerable,
            "summary": (
                f"slither detector '{detector}' found {len(detectors)} issue(s)"
            ),
        }


class FalconVerifier:
    def __init__(self, timeout_seconds: int = 120):
        self.timeout_seconds = max(1, int(timeout_seconds))

    def _is_falcon_available(self) -> bool:
        return shutil.which("falcon") is not None

    def _parse_falcon_json(self, json_path: Path) -> Optional[dict]:
        if not json_path.exists():
            return None
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def verify_patch(self, patched_contract_path: Path, finding_code: str) -> Dict[str, object]:
        if not self._is_falcon_available():
            return {
                "status": "tool-unavailable",
                "tool": "falcon",
                "message": "falcon binary not found in PATH",
                "still_vulnerable": True,
            }

        detector = FINDING_TO_FALCON_DETECTOR.get(str(finding_code).strip(), "")
        if detector == "":
            return {
                "status": "unsupported-finding",
                "tool": "falcon",
                "message": f"no falcon detector mapping for finding code '{finding_code}'",
                "still_vulnerable": True,
            }

        json_out = patched_contract_path.with_suffix(patched_contract_path.suffix + ".falcon.json")
        cmd = [
            "falcon",
            str(patched_contract_path),
            "--detect",
            detector,
            "--json",
            str(json_out),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "tool": "falcon",
                "detector": detector,
                "message": f"falcon timed out after {self.timeout_seconds} seconds",
                "still_vulnerable": True,
            }
        except Exception as exc:
            return {
                "status": "execution-error",
                "tool": "falcon",
                "detector": detector,
                "message": str(exc),
                "still_vulnerable": True,
            }

        parsed = self._parse_falcon_json(json_out)
        detectors = []
        if isinstance(parsed, dict):
            detectors = parsed.get("results", {}).get("detectors", []) or []

        if result.returncode != 0 and len(detectors) == 0:
            stderr_tail = "\n".join((result.stderr or "").splitlines()[-10:])
            stdout_tail = "\n".join((result.stdout or "").splitlines()[-10:])
            return {
                "status": "analysis-error",
                "tool": "falcon",
                "detector": detector,
                "returncode": result.returncode,
                "stderr_tail": stderr_tail,
                "stdout_tail": stdout_tail,
                "still_vulnerable": True,
            }

        still_vulnerable = len(detectors) > 0
        return {
            "status": "verified",
            "tool": "falcon",
            "detector": detector,
            "detectors_found": len(detectors),
            "still_vulnerable": still_vulnerable,
            "summary": (
                f"falcon detector '{detector}' found {len(detectors)} issue(s)"
            ),
        }
