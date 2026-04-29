import csv
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


DIVE_LABEL_COLUMNS = [
    "Reentrancy",
    "Access Control",
    "Arithmetic",
    "Unchecked Return Values",
    "DoS",
    "Bad Randomness",
    "Front Running",
    "Time manipulation",
]


HIGH_CONFIDENCE_MAPPING = {
    "front-running": {"Front Running"},
    "unauthorized-transfer": {"Access Control"},
}


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


class DIVEEvaluator:
    def __init__(self, labels_csv_path: Path, mapping_mode: str = "high-confidence"):
        self.labels_csv_path = Path(labels_csv_path)
        self.mapping_mode = (mapping_mode or "high-confidence").strip().lower()
        if self.mapping_mode != "high-confidence":
            raise ValueError(f"Unsupported DIVE mapping mode: {self.mapping_mode}")

        if not self.labels_csv_path.exists():
            raise FileNotFoundError(f"DIVE labels CSV not found: {self.labels_csv_path}")

        self.labels_by_contract = self._load_labels()
        self.finding_to_labels = HIGH_CONFIDENCE_MAPPING

    def _load_labels(self) -> Dict[int, Dict[str, int]]:
        labels_by_contract: Dict[int, Dict[str, int]] = {}
        with open(self.labels_csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                contract_raw = str(row.get("contractID", "")).strip()
                if not contract_raw.isdigit():
                    continue
                contract_id = int(contract_raw)

                contract_labels: Dict[str, int] = {}
                for label in DIVE_LABEL_COLUMNS:
                    val = str(row.get(label, "0")).strip()
                    contract_labels[label] = 1 if val == "1" else 0
                labels_by_contract[contract_id] = contract_labels
        return labels_by_contract

    def _extract_contract_id_from_source_path(self, source_path: str) -> Optional[int]:
        stem = Path(source_path).stem
        if stem.isdigit():
            return int(stem)
        return None

    def _extract_shard_id(self, finding_path: str) -> str:
        # Typical path: .../_shards_.../inputs/0048/<file>.sol
        match = re.search(r"/inputs/(\d{4})/", finding_path)
        if match is None:
            return ""
        return match.group(1)

    def _resolve_contract_id(
        self,
        finding_path: str,
        shard_source_map: Dict[str, str],
    ) -> Optional[int]:
        # First try the path directly (works for non-sharded or already rewritten paths).
        direct = self._extract_contract_id_from_source_path(finding_path)
        if direct is not None:
            return direct

        # Then try shard lookup if findings point to _shards inputs.
        shard_id = self._extract_shard_id(finding_path)
        if shard_id == "":
            return None
        source_path = shard_source_map.get(shard_id, "")
        if source_path == "":
            return None
        return self._extract_contract_id_from_source_path(source_path)

    def evaluate(
        self,
        findings: List[dict],
        source_files: List[Path],
        shard_source_map: Dict[str, str],
    ) -> Dict[str, Any]:
        mapped_labels = sorted(
            list(
                {
                    label
                    for labels in self.finding_to_labels.values()
                    for label in labels
                }
            )
        )
        unsupported_labels = [label for label in DIVE_LABEL_COLUMNS if label not in mapped_labels]

        scanned_contract_ids: Set[int] = set()
        for sol_file in source_files:
            stem = sol_file.stem
            if stem.isdigit():
                scanned_contract_ids.add(int(stem))

        evaluable_contract_ids = sorted(
            list(scanned_contract_ids.intersection(set(self.labels_by_contract.keys())))
        )

        predicted_labels: Dict[int, Set[str]] = {}
        findings_total = len(findings)
        findings_with_mapped_code = 0
        findings_with_unmapped_code = 0
        resolved_paths = 0
        unresolved_paths = 0

        for finding in findings:
            finding_code = str(finding.get("code", "")).strip()
            mapped_for_finding = self.finding_to_labels.get(finding_code, set())
            if len(mapped_for_finding) == 0:
                findings_with_unmapped_code += 1
                continue
            findings_with_mapped_code += 1

            for affected in finding.get("affectedFiles", []):
                file_path = str(affected.get("filePath", ""))
                if file_path == "":
                    unresolved_paths += 1
                    continue

                contract_id = self._resolve_contract_id(file_path, shard_source_map=shard_source_map)
                if contract_id is None:
                    unresolved_paths += 1
                    continue

                resolved_paths += 1
                if contract_id not in predicted_labels:
                    predicted_labels[contract_id] = set()
                predicted_labels[contract_id].update(mapped_for_finding)

        per_label_metrics: Dict[str, Dict[str, Any]] = {}
        micro_tp = 0
        micro_fp = 0
        micro_fn = 0
        macro_f1_sum = 0.0
        macro_precision_sum = 0.0
        macro_recall_sum = 0.0

        for label in mapped_labels:
            tp = 0
            fp = 0
            fn = 0
            tn = 0

            for contract_id in evaluable_contract_ids:
                truth_positive = self.labels_by_contract[contract_id].get(label, 0) == 1
                predicted_positive = label in predicted_labels.get(contract_id, set())

                if truth_positive and predicted_positive:
                    tp += 1
                elif (not truth_positive) and predicted_positive:
                    fp += 1
                elif truth_positive and (not predicted_positive):
                    fn += 1
                else:
                    tn += 1

            precision = _safe_div(tp, tp + fp)
            recall = _safe_div(tp, tp + fn)
            f1 = _safe_div(2.0 * precision * recall, precision + recall)

            per_label_metrics[label] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            }

            micro_tp += tp
            micro_fp += fp
            micro_fn += fn
            macro_precision_sum += precision
            macro_recall_sum += recall
            macro_f1_sum += f1

        micro_precision = _safe_div(micro_tp, micro_tp + micro_fp)
        micro_recall = _safe_div(micro_tp, micro_tp + micro_fn)
        micro_f1 = _safe_div(2.0 * micro_precision * micro_recall, micro_precision + micro_recall)

        macro_denominator = max(1, len(mapped_labels))
        macro_precision = macro_precision_sum / float(macro_denominator)
        macro_recall = macro_recall_sum / float(macro_denominator)
        macro_f1 = macro_f1_sum / float(macro_denominator)

        exact_match_hits = 0
        for contract_id in evaluable_contract_ids:
            truth_set = {
                label
                for label in mapped_labels
                if self.labels_by_contract[contract_id].get(label, 0) == 1
            }
            pred_set = predicted_labels.get(contract_id, set()).intersection(set(mapped_labels))
            if truth_set == pred_set:
                exact_match_hits += 1

        report = {
            "evaluator": "dive-high-confidence-v1",
            "mapping_mode": self.mapping_mode,
            "labels_csv": str(self.labels_csv_path),
            "mapped_dive_labels": mapped_labels,
            "unsupported_dive_labels": unsupported_labels,
            "finding_code_to_dive_labels": {
                key: sorted(list(value)) for key, value in self.finding_to_labels.items()
            },
            "dataset": {
                "dive_contracts_total": len(self.labels_by_contract),
                "scanned_contracts_with_numeric_id": len(scanned_contract_ids),
                "evaluated_contracts": len(evaluable_contract_ids),
                "evaluated_contract_ids_sample": evaluable_contract_ids[:20],
            },
            "prediction_summary": {
                "findings_total": findings_total,
                "findings_with_mapped_code": findings_with_mapped_code,
                "findings_with_unmapped_code": findings_with_unmapped_code,
                "resolved_affected_paths": resolved_paths,
                "unresolved_affected_paths": unresolved_paths,
                "contracts_with_predictions": len(predicted_labels),
            },
            "metrics": {
                "micro": {
                    "precision": micro_precision,
                    "recall": micro_recall,
                    "f1": micro_f1,
                    "tp": micro_tp,
                    "fp": micro_fp,
                    "fn": micro_fn,
                },
                "macro": {
                    "precision": macro_precision,
                    "recall": macro_recall,
                    "f1": macro_f1,
                },
                "exact_contract_match_accuracy": _safe_div(exact_match_hits, len(evaluable_contract_ids)),
                "per_label": per_label_metrics,
            },
        }

        return report
