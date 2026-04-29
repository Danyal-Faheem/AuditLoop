# GPTScan

## Description

Using ChatGPT for logic vulnerability detection.

## How to Use

1. Install dependencies,

- Requires Python 3.10+
- Install Python dependencies: `pip install -r requirements.txt`
- Requires Java 17+

2. Run GPTScan

Before start, please select the correct SOLC version, by running the commands:

```shell
solc-select install 0.8.19 # just an example of 0.8.19
solc-select use 0.8.19
```

For example, if the source code is stored in the `/source` directory, run the command from the `src` folder:

```shell
cd src
```

OpenAI mode (default provider):

```shell
python3.10 main.py -s /sourcecode -o /sourcecode/output.json -k OPEN_AI_API_KEY_xxxxxxxxxxxxx
```

Ollama mode (local LLM):

```shell
python3.10 main.py -s /sourcecode -o /sourcecode/output.json --provider ollama --model qwen2.5-coder:7b --ollama-url http://localhost:11434
```

Provider flags:
- `--provider`: `openai` or `ollama` (default: `openai`)
- `--model`: override model name for selected provider
- `--model-gpt4`: override GPT4 model used by GPT4 code paths
- `--ollama-url`: Ollama endpoint URL (default: `http://localhost:11434`)

For `openai` provider, `-k/--gptkey` is required.

3. Check the output

The output results are located at the location specified by the `-o` parameter, in the example above, it is located at `/sourcecode/output.json`.

The metadata file `<output>.metadata.json` now also records `llm_provider` and `llm_model` for traceability.

## Quick Benchmark

Ollama-only (no OpenAI key):

```shell
python3 benchmark.py \
    -s /sourcecode \
    --mode ollama-only \
    --falcon-mode per-file \
    --ollama-model qwen2.5-coder:7b \
    --ollama-url http://localhost:11434
```

OpenAI vs Ollama compare mode:

Use the benchmark helper at repository root to compare a local Ollama model against OpenAI on the same source path.

```shell
python3 benchmark.py \
    -s /sourcecode \
    --mode compare \
    --falcon-mode per-file \
    --openai-key OPEN_AI_API_KEY_xxxxxxxxxxxxx \
    --openai-model gpt-3.5-turbo \
    --ollama-model qwen2.5-coder:7b \
    --ollama-url http://localhost:11434
```

`--falcon-mode per-file` runs one Solidity file per GPTScan invocation and merges outputs. This keeps Falcon-backed static checks enabled for benchmark corpora that are plain multi-file directories.

In `per-file` mode, the benchmark helper also tries `solc-select use <pragma-version>` per Solidity file (best effort) to reduce Falcon compile failures caused by mixed pragma versions.

Checkpoint/resume is enabled by default. Use a stable run id to continue long runs safely:

```shell
python3 benchmark.py \
    -s /sourcecode \
    --mode ollama-only \
    --falcon-mode per-file \
    --run-id top200_qwen_run1 \
    --resume
```

The run directory stores `run_manifest.json` and per-shard progress in `_shards_<output_stem>/resume_progress.json`.

Use `--max-files N` to run a deterministic smoke subset in per-file mode (first N sorted Solidity files):

```shell
python3 benchmark.py \
    -s /sourcecode \
    --mode ollama-only \
    --falcon-mode per-file \
    --max-files 100 \
    --run-id smoke100 \
    --resume
```

If per-file runs appear "stuck", use:
- `--show-shard-logs` to print each shard's stdout/stderr
- `--failed-log-tail-lines 50` (or larger) to keep longer failure tails in metadata
- `--shard-timeout-seconds 1800` to skip unusually long shards and continue benchmark progress
- `--auto-install-solc` to install missing pragma versions detected in preflight (`solc-select install <version>`)

Per-file runs also print simple complexity stats for each file (`loc`, contract count, function count) so you can see which shard is heavy.

Outputs are written to `benchmark_results/<timestamp>/` with:
- `openai_output.json` and `openai_output.json.metadata.json`
- `ollama_output.json` and `ollama_output.json.metadata.json`
- `comparison.json` (compare mode) or `summary.json` (ollama-only mode)

If DIVE evaluation is enabled, additional artifacts are written:
- `<provider>_output.dive_eval.json`
- `<provider>_output.json.metadata.json` includes `dive_evaluation_summary`

### DIVE Labeled Evaluation (Medium-Effort)

Create a vulnerable-only DIVE subset (example: first 2000 vulnerable contracts):

```shell
python3 scripts/create_dive_vuln_subset.py \
    --labels-csv /path/to/DIVE/Labels/DIVE_Labels.csv \
    --source-dir /path/to/DIVE/Raw/PRE/Source\ codes \
    --output-dir /path/to/DIVE/subsets/vuln2000 \
    --limit 2000 \
    --overwrite
```

Run benchmark with DIVE labels (high-confidence mapping mode):

```shell
python3 benchmark.py \
    -s /path/to/DIVE/Raw/PRE/Source\ codes \
    --mode ollama-only \
    --falcon-mode per-file \
    --dataset-kind dive \
    --dive-labels-csv /path/to/DIVE/Labels/DIVE_Labels.csv \
    --dive-eval-mode high-confidence
```

DIVE smoke run (about 100 files) with LLM detection + LLM remediation + LLM verification:

```shell
python3 benchmark.py \
    -s /path/to/DIVE/Raw/PRE/Source\ codes \
    --mode ollama-only \
    --falcon-mode per-file \
    --max-files 100 \
    --dataset-kind dive \
    --dive-labels-csv /path/to/DIVE/Labels/DIVE_Labels.csv \
    --dive-eval-mode high-confidence \
    --enable-remediation \
    --remediation-max-rounds 3 \
    --remediation-verify-mode llm-rule-recheck \
    --run-id dive_smoke100_rule_recheck
```

Add `--drop-fixed-findings` if you want final output JSON to keep unresolved findings only.

High-confidence mapping currently reports metrics for mapped classes and explicitly reports unsupported DIVE classes in the evaluation artifact.

### Remediation Verification Modes

Benchmark supports these remediation verification modes:
- `llm-self-check`
- `llm-rule-recheck`
- `slither-rule-recheck` (new): uses Slither first, then falls back to `llm-rule-recheck` if static verification is unavailable/inconclusive.
- `falcon-rule-recheck` (new): runs Falcon detector checks on patched artifacts when detector mapping is available.

## Supported Project Types

Currently supported project types include:
- Single file in a folder, i.e., `contract` folder with a single `example.sol` file. Use the path of folder as source (**NOT THE FILE, WHICH MAY CAUSE ERRORS.**)
- ~~Multi-file, i.e., a directory with multiple `.sol` files, without any other external dependencies~~
- Common framework projects, such as Truffle, Hardhat, Brownie, etc.

Tested frameworks include:
- Hardhad
- Truffle
- Brownie

Note that this project does not include the compilation environment, such as Node.js, which needs to be installed separately.

**NOTE**: Please also make sure that you path do not contain keywords like `external`, `openzeppelin`, `uniswap`, `pancakeswap`, `legacy`, since we are using a naive way to match the path. Find more in `src/antlr4helper/callgraph.py:__parse_all_files`. It will not have explict error messages, but will cause empty output.

## Dataset

Dataset used to evaluate GPTScan in the paper, are the following:
1. Web3Bugs: [https://github.com/MetaTrustLabs/GPTScan-Web3Bugs](https://github.com/MetaTrustLabs/GPTScan-Web3Bugs)
2. DefiHacks: [https://github.com/MetaTrustLabs/GPTScan-DefiHacks](https://github.com/MetaTrustLabs/GPTScan-DefiHacks)
3. Top200: [https://github.com/MetaTrustLabs/GPTScan-Top200](https://github.com/MetaTrustLabs/GPTScan-Top200)

## How to Cite this project

```bibtex
@inproceedings{sun2024gptscan,
    author = {Sun, Yuqiang and Wu, Daoyuan and Xue, Yue and Liu, Han and Wang, Haijun and Xu, Zhengzi and Xie, Xiaofei and Liu, Yang},
    title = {{GPTScan}: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis},
    year = {2024},
    isbn = {9798400702174},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    url = {https://doi.org/10.1145/3597503.3639117},
    doi = {10.1145/3597503.3639117},
    booktitle = {Proceedings of the IEEE/ACM 46th International Conference on Software Engineering},
    articleno = {166},
    numpages = {13},
    series = {ICSE '24}
}
```
