# AuditLoop

## Description

An enhanced smart contract vulnerability scanner that combines LLM-based detection with **automated remediation and multi-stage verification**. The codebase extends the original GPTScan framework with:

1. **LLM-driven remediation**: Automatically fixes detected vulnerabilities and verifies the patches
2. **Multiple verification modes**: Uses LLM self-check, rule-based re-evaluation, or static analysis (Slither/Falcon) as a secondary verification layer
3. **Timeout and retry resilience**: Robust handling of LLM timeouts and errors (important for local Ollama instances)
4. **Optional dual-LLM setup**: Run detection with one LLM and verification with another
5. **DIVE benchmark integration**: High-confidence evaluation against the DIVE dataset for systematic assessment

### Key Differences from Original GPTScan

- **Remediation pipeline**: Original GPTScan stops after detection; this version attempts to fix each vulnerability and verifies the fix
- **Verification strategies**: Choice of 4 verification modes (llm-self-check, llm-rule-recheck, slither-rule-recheck, falcon-rule-recheck)
- **Timeout handling**: Configurable per-LLM-call timeout with automatic retry and fallback behavior
- **Dual-LLM support**: Separate Ollama instances for detection and verification phases
- **Benchmark framework**: Enhanced benchmarking with per-file sharding, resume capability, and structured metrics

## Installation & Setup

1. **Prerequisites**:
   - Python 3.10+
   - Java 17+ (for Falcon static analysis)
   - SOLC compiler versions matching your smart contracts (use `solc-select` to manage multiple versions)
   - Ollama (for local LLM inference) or OpenAI API key

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Prepare your Solidity compiler**:

```bash
solc-select install 0.8.19  # Install specific version (example)
solc-select use 0.8.19      # Activate it
```

4. **Start Ollama server** (if using local LLM):

```bash
ollama serve
# In another terminal, pull a model:
ollama pull qwen3-coder:latest
```

## Benchmark Execution

Use the `benchmark.py` script to run systematic evaluations across multiple files or datasets.

### Basic Benchmark Setup

From the repository root:

```bash
python3 benchmark.py \
  -s /path/to/source \
  --mode ollama-only \
  --falcon-mode per-file \
  --ollama-model qwen3-coder:latest
```

### Benchmark Flags Reference

**Input & Output**:
- `-s, --source` (required): Source directory or file to scan
- `-o, --output-dir`: Directory for benchmark results (default: `benchmark_results`)
- `--run-id`: Stable identifier for this run; used for resume (default: timestamp)
- `--resume`: Enable resume from checkpoint (default: true)
- `--force-resume`: Allow resume even if run manifest changed

**Scan Mode**:
- `--mode`: `compare` (OpenAI vs Ollama) or `ollama-only` (default: `ollama-only`)
- `--falcon-mode`: `auto` (default) or `per-file` (run one file per GPTScan invocation; preserves Falcon coverage in multi-file directories)

**LLM Configuration**:
- `--ollama-model`: Ollama model name (default: `qwen2.5-coder:7b`)
- `--ollama-url`: Ollama server URL (default: `http://localhost:11434`)
- `--ollama-url-second`: Optional second Ollama instance for remediation verification
- `--ollama-timeout-seconds`: Per-call timeout for Ollama (default: 60 seconds)
- `--openai-model`: OpenAI model for compare mode (default: `gpt-3.5-turbo`)
- `--openai-key`: OpenAI API key (required for `--mode compare`)

**Static Analysis**:
- `--disable-falcon`: Skip Falcon static analysis (useful for multi-file directories where Falcon may fail)
- `--disable-static`: Completely disable static filtering stage; all LLM candidates bypass Falcon checks

**Remediation (Vulnerability Fixing)**:
- `--enable-remediation`: Enable LLM-driven remediation loop (off by default)
- `--remediation-max-rounds`: Maximum fix/verify iterations per vulnerability (default: 3)
- `--remediation-verify-mode`: Verification strategy (default: `llm-self-check`)
  - `llm-self-check`: Pure LLM verification (fast, no external tools needed)
  - `llm-rule-recheck`: LLM re-evaluation against vulnerability rules (medium cost)
  - `slither-rule-recheck`: Slither static check first, fallback to LLM rule-recheck (slower, more precise)
  - `falcon-rule-recheck`: Falcon static check first, fallback to LLM (slowest, highest precision)
- `--drop-fixed-findings`: Remove fixed vulnerabilities from final output JSON (default: keep all)

**Solidity Compiler Management**:
- `--auto-install-solc`: Automatically install missing pragma versions using `solc-select` (useful for diverse contracts)

**Evaluation**:
- `--dataset-kind`: Dataset type for metrics (default: `auto`)
  - `auto`: Infer from source path
  - `dive`, `top200`, `defihacks`, `web3bugs`, `custom`
- `--dive-labels-csv`: Path to DIVE labels CSV (required when dataset-kind is `dive`)
- `--dive-eval-mode`: DIVE evaluation mapping mode (default: `high-confidence`)

**Per-File Benchmarking** (when `--falcon-mode per-file`):
- `--max-files`: Limit to first N Solidity files (0 = all; default: 0)
- `--shard-timeout-seconds`: Kill per-file shard if exceeds timeout (0 = no timeout; default: 0)
- `--show-shard-logs`: Print full stdout/stderr from each file shard
- `--failed-log-tail-lines`: Number of lines to keep from failed shard logs (default: 25)

### Example Benchmark Commands

**Basic Ollama-only smoke test (100 files)**:

```bash
python3 benchmark.py \
  -s /path/to/source \
  --mode ollama-only \
  --falcon-mode per-file \
  --max-files 100 \
  --ollama-model qwen3-coder:latest \
  --run-id smoke_100_files
```

**Full benchmark with remediation**:

```bash
python3 benchmark.py \
  -s /path/to/source \
  --mode ollama-only \
  --falcon-mode per-file \
  --ollama-model qwen3-coder:latest \
  --enable-remediation \
  --remediation-max-rounds 3 \
  --remediation-verify-mode llm-rule-recheck \
  --run-id full_run_with_remediation
```

**Benchmark with dual Ollama (different model for verification)**:

```bash
python3 benchmark.py \
  -s /path/to/source \
  --mode ollama-only \
  --falcon-mode per-file \
  --ollama-model qwen3-coder:latest \
  --ollama-url-second http://localhost:11435 \
  --ollama-timeout-seconds 120 \
  --enable-remediation \
  --remediation-verify-mode llm-rule-recheck \
  --run-id dual_ollama_run
```

**Benchmark on dataset with static + remediation**:

```bash
python3 benchmark.py \
  -s /path/to/dataset \
  --mode ollama-only \
  --falcon-mode per-file \
  --dataset-kind dive \
  --dive-labels-csv /path/to/DIVE_Labels.csv \
  --dive-eval-mode high-confidence \
  --enable-remediation \
  --remediation-max-rounds 3 \
  --remediation-verify-mode slither-rule-recheck \
  --run-id dataset_eval_slither_verify
```

**Resume a stopped benchmark**:

```bash
python3 benchmark.py \
  -s /path/to/source \
  --mode ollama-only \
  --falcon-mode per-file \
  --run-id full_run_with_remediation \
  --resume
```

### Output Artifacts

Benchmarks produce outputs in `benchmark_results/<run_id>/`:

- `ollama_output.json`: Raw detected findings
- `ollama_output.json.metadata.json`: Scan metadata (counts, timings, remediation stats)
- `ollama_output.dive_eval.json`: DIVE evaluation report (if `--dive-labels-csv` provided)
- `summary.json`: High-level summary (ollama-only mode)
- `comparison.json`: Side-by-side metrics (compare mode)
- `_shards_ollama_output/`: Per-file shard results and resume checkpoint

### Dataset Requirements

The benchmark expects a dataset with these attributes:

- **Source files**: Smart contract source code files (`.sol`)
- **Labeling** (optional, for evaluation):
  - CSV format mapping contract IDs to vulnerability class labels
  - Required columns: contractID, and labels for each vulnerability class
- **File naming**: Contracts should be identifiable by filename (e.g., `123.sol` → contract ID 123) for evaluation linkage

If you have labeling, provide via `--dive-labels-csv` to enable automated evaluation metrics (precision, recall, F1).


