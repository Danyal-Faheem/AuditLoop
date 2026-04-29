#!/usr/bin/env python3
"""Analyze Falcon failure samples and categorize by error type."""
import json
import re
from collections import defaultdict
from pathlib import Path

metadata_file = Path("/home/danyal.faheem/CNSEC/GPTScan/benchmark_results/20260323_012918/ollama_output.json.metadata.json")

with open(metadata_file) as f:
    metadata = json.load(f)

samples = metadata.get("falcon_init_failure_samples", [])
print(f"\n📊 Analyzing {len(samples)} Falcon Failures\n{'='*70}")

categories = defaultdict(list)

for sample in samples:
    msg = sample.get("probe_exception_message", "")
    shard_id = sample.get("shard_id", "?")
    source = sample.get("source_path", "?").split("/")[-1]
    missing_imports = sample.get("missing_local_imports", [])
    
    # Categorize
    if "different compiler version" in msg:
        cat = "SOLC_VERSION_MISMATCH"
    elif "not found: File not found" in msg and missing_imports:
        cat = "BROKEN_IMPORT_DETECTED"
    elif "not found: File not found" in msg:
        cat = "BROKEN_IMPORT_UNDETECTED"
    elif "not found" in msg.lower():
        cat = "FILE_NOT_FOUND_OTHER"
    elif "requires different" in msg:
        cat = "COMPILER_REQUIREMENT_MISMATCH"
    else:
        cat = "OTHER"
    
    categories[cat].append({
        "shard": shard_id,
        "file": source,
        "missing": missing_imports,
        "error_snippet": msg.split("\n")[0][:120]
    })

print("\n📋 FAILURE BREAKDOWN:\n")
for cat in sorted(categories.keys()):
    items = categories[cat]
    print(f"  {cat}: {len(items)}")
    for item in items[:3]:  # Show first 3 of each
        print(f"    - [{item['shard']}] {item['file']}")
        print(f"      Error: {item['error_snippet']}")
        if item['missing']:
            print(f"      Missing: {item['missing'][0]}")
    if len(items) > 3:
        print(f"    ... and {len(items)-3} more")
    print()

print(f"{'='*70}\n")
print("💡 RECOMMENDATIONS:\n")

counts = {cat: len(items) for cat, items in categories.items()}
print(f"Summary: {counts}\n")

if counts.get("SOLC_VERSION_MISMATCH", 0) > 0:
    print(f"1. SOLC_VERSION_MISMATCH ({counts['SOLC_VERSION_MISMATCH']} failures):")
    print("   → Pragma extraction or version selection is wrong")
    print("   → Check if extracted pragma matches actual version needed\n")

if counts.get("BROKEN_IMPORT_DETECTED", 0) > 0:
    print(f"2. BROKEN_IMPORT_DETECTED ({counts['BROKEN_IMPORT_DETECTED']} failures):")
    print("   → Dataset files are corrupted/renamed (e.g., Container.sol → ontainer.sol)")
    print("   → Implement fuzzy-match fallback for near-match filenames\n")

if counts.get("BROKEN_IMPORT_UNDETECTED", 0) > 0:
    print(f"3. BROKEN_IMPORT_UNDETECTED ({counts['BROKEN_IMPORT_UNDETECTED']} failures):")
    print("   → Imports not in missing_local_imports (regex miss or different syntax)")
    print("   → Improve import regex or expand parsing logic\n")

if counts.get("OTHER", 0) > 0:
    print(f"4. OTHER ({counts['OTHER']} failures):")
    print("   → Unknown error categories, needs investigation\n")

if counts.get("FILE_NOT_FOUND_OTHER", 0) > 0:
    print(f"5. FILE_NOT_FOUND_OTHER ({counts['FILE_NOT_FOUND_OTHER']} failures):")
    print("   → Files not found but different error pattern\n")
