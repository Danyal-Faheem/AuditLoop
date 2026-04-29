import yaml
import os
import logging
from typing import Dict, List, Tuple
import config as global_config
import datetime
import json
import falcon_adapter
import traceback
import static_check
import utils
import remediation
import sys
import time
import argparse
import subprocess
from pathlib import Path
import rich
from rich.progress import Progress
from rich.table import Table
from rich_utils import *
import falcon

logger = logging.getLogger(__name__)

console = rich.get_console()


def _flatten_to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        parts = []
        for k, v in value.items():
            parts.append(_flatten_to_text(k))
            parts.append(_flatten_to_text(v))
        return " ".join(list(filter(lambda x: x != "", parts)))
    if isinstance(value, (list, tuple, set)):
        return " ".join(list(filter(lambda x: x != "", map(_flatten_to_text, value))))
    return str(value)


def _collect_candidate_descriptions(raw_value, selected_value) -> List[str]:
    candidates = []

    if isinstance(raw_value, dict):
        if isinstance(selected_value, str) and selected_value in raw_value:
            candidates.append(_flatten_to_text(raw_value[selected_value]))
        elif isinstance(selected_value, dict):
            for selected_key, selected_val in selected_value.items():
                if selected_key in raw_value:
                    candidates.append(_flatten_to_text(raw_value[selected_key]))
                candidates.append(_flatten_to_text(selected_val))
        elif isinstance(selected_value, (list, tuple, set)):
            for item in selected_value:
                if isinstance(item, str) and item in raw_value:
                    candidates.append(_flatten_to_text(raw_value[item]))
                else:
                    candidates.append(_flatten_to_text(item))
        else:
            selected_key = _flatten_to_text(selected_value)
            if selected_key in raw_value:
                candidates.append(_flatten_to_text(raw_value[selected_key]))
            candidates.append(_flatten_to_text(selected_value))
    else:
        candidates.append(_flatten_to_text(raw_value))
        candidates.append(_flatten_to_text(selected_value))

    return list(filter(lambda x: x != "", candidates))

def _do_load_config(config_path: str):
    with open(os.path.join("tasks", config_path), "r") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    return config


def load_config(config_name: str):
    if os.path.exists(os.path.join("tasks", config_name+".yml")):
        path = os.path.join("tasks", config_name+".yml")
    elif os.path.exists(os.path.join("tasks", config_name+".yaml")):
        path = os.path.join("tasks", config_name+".yaml")
    else:
        raise FileNotFoundError("No such file: {}".format(config_name))
    return _do_load_config(os.path.basename(path))


def load_configs(config_names: list):
    configs = []
    for config_name in config_names:
        configs.append(load_config(config_name))
    return configs


def load_all_configs():
    configs = []
    for file in os.listdir("tasks"):
        if file.endswith(".yml") or file.endswith(".yaml"):
            configs.append(_do_load_config(file))
    return configs


def load_rule(rule_indexs: List[int]):
    result = []
    for rule in rule_indexs:
        if os.path.exists(os.path.join("rules", rule+".yml")):
            result.append(yaml.load(
                open(os.path.join("rules", rule+".yml"), "r"), Loader=yaml.FullLoader))
        else:
            raise FileNotFoundError("No such file: {}".format(rule))
    return result


def load_all_rules():
    result = []
    for file in os.listdir("rules"):
        if file.endswith(".yml"):
            result.append(
                yaml.load(open(os.path.join("rules", file), "r"), Loader=yaml.FullLoader))
    return result


def compile_project(abs_path:str):
    disable_falcon = os.environ.get("GPTSCAN_DISABLE_FALCON", "").strip().lower() in {"1", "true", "yes", "on"}
    if disable_falcon:
        logger.warning("Falcon disabled by GPTSCAN_DISABLE_FALCON; continuing without Falcon-backed static checks")
        return None

    # with Progress(transient=True) as progress:
    #     task = progress.add_task("Compiling", total=None, start=False)
    #     data = {
    #         "version": "0.0.1",
    #         "user": {
    #             "project": {
    #                 "workspace": f"{abs_path}"
    #             },
    #             "operation": ["detection", "dependency", "compile"],
    #             "output_format": ["standard", "compatible-ast"],
    #             "output_path": f"{os.path.join(abs_path, 'ast')}"
    #         }
    #     }
    #     json.dump(data, open(os.path.join(abs_path, 'parse-config.json'), "w"))
    #     output = subprocess.check_output(['mt-parsing', 'parse-config.json'], cwd=os.path.abspath(abs_path))
    #     if len(os.listdir(os.path.join(abs_path, "ast", "standard"))) > 0:
    #         return True
    #     else:
    #         logger.error(output)
    #         return False
    try:
        if os.path.isfile(abs_path):
            return falcon.Falcon(abs_path)

        files = os.listdir(abs_path)
        sol_files = list(filter(lambda x: x.endswith(".sol") and os.path.isfile(os.path.join(abs_path, x)), files))

        if len(sol_files) == 1:
            return falcon.Falcon(os.path.join(abs_path, sol_files[0]))

        # Falcon/crytic-compile expects either a framework project or a single target file.
        # For plain directories containing many standalone .sol files (common in benchmarks),
        # skip Falcon so the rest of GPTScan can continue with reduced static precision.
        framework_markers = {
            "hardhat.config.js",
            "hardhat.config.ts",
            "truffle-config.js",
            "brownie-config.yaml",
            "brownie-config.yml",
            "foundry.toml",
        }
        is_framework_project = any(os.path.exists(os.path.join(abs_path, marker)) for marker in framework_markers)

        if len(sol_files) > 1 and not is_framework_project:
            logger.warning("Falcon disabled for plain multi-file directory input; continuing without Falcon-backed static checks")
            return None

        return falcon.Falcon(abs_path)
    except Exception as e:
        logger.warning("Falcon initialization failed: %s", str(e))
        return None


def simple_cli():
    start_time = time.time()

    parser = argparse.ArgumentParser(
                    prog='GPTScan',
                    description='GPTScan is an AI based smart contract vulnerability scanner.')
    parser.add_argument("-s", "--source", help="The source code directory", required=True)
    # not need ast, compile first
    # parser.add_argument("-a", "--ast", help="The AST directory", required=True)
    parser.add_argument("-o", "--output", help="The output file", required=True)
    parser.add_argument("-k", "--gptkey", help="The OpenAI API key", required=False, default="")
    parser.add_argument("--provider", choices=["openai", "ollama"], default=global_config.LLM_PROVIDER, help="LLM provider")
    parser.add_argument("--model", default="", help="Override model name for selected provider")
    parser.add_argument("--model-gpt4", default="", help="Override GPT4 model for GPT4 calls")
    parser.add_argument("--ollama-url", default=global_config.OLLAMA_BASE_URL, help="Ollama base URL")
    parser.add_argument("--ollama-url-second", default="", help="Optional second Ollama base URL for verification")
    parser.add_argument("--ollama-timeout-seconds", type=int, default=60, help="Per-LLM call timeout (seconds) for Ollama requests")

    cli_args = parser.parse_args()
    
    
    scan_rules = load_all_rules()
    console.log(f"Loaded [bold green]{len(scan_rules)}[/bold green] rules")
    
    source_dir = cli_args.source

    disable_static = os.environ.get("GPTSCAN_DISABLE_STATIC", "").strip().lower() in {"1", "true", "yes", "on"}
    enable_remediation = os.environ.get("GPTSCAN_ENABLE_REMEDIATION", "").strip().lower() in {"1", "true", "yes", "on"}
    remediation_drop_fixed = os.environ.get("GPTSCAN_REMEDIATION_DROP_FIXED", "").strip().lower() in {"1", "true", "yes", "on"}
    remediation_verify_mode = os.environ.get("GPTSCAN_REMEDIATION_VERIFY_MODE", "llm-self-check").strip().lower() or "llm-self-check"
    remediation_max_rounds = int(os.environ.get("GPTSCAN_REMEDIATION_MAX_ROUNDS", "3") or "3")

    falcon_instance = compile_project(source_dir)
    if falcon_instance is None:
        console.log("Compile [bold yellow]degraded[/bold yellow].")
        console.log("[yellow]Falcon-backed static checks are disabled for this input; scan will continue with reduced static precision and recall.[/yellow]")
    if disable_static:
        console.log("[yellow]Static analysis stage disabled by GPTSCAN_DISABLE_STATIC; all candidates bypass static gating.[/yellow]")
    output_file = cli_args.output
    gptkey = cli_args.gptkey

    if cli_args.provider == "openai" and gptkey == "":
        parser.error("-k/--gptkey is required when provider is openai")

    os.environ["GPTSCAN_LLM_PROVIDER"] = cli_args.provider
    os.environ["GPTSCAN_OLLAMA_URL"] = cli_args.ollama_url
    if cli_args.ollama_url_second.strip() != "":
        os.environ["GPTSCAN_OLLAMA_URL_SECOND"] = cli_args.ollama_url_second.strip()
    if int(cli_args.ollama_timeout_seconds) > 0:
        os.environ["GPTSCAN_OLLAMA_TIMEOUT"] = str(int(cli_args.ollama_timeout_seconds))
    if cli_args.model.strip() != "":
        os.environ["GPTSCAN_LLM_MODEL"] = cli_args.model.strip()
    if cli_args.model_gpt4.strip() != "":
        os.environ["GPTSCAN_LLM_MODEL_GPT4"] = cli_args.model_gpt4.strip()

    if gptkey != "":
        os.environ["OPENAI_API_KEY"] = gptkey

    import analyze_pipeline
    import chatgpt_api

    res, cg, meta_data = analyze_pipeline.ask_whether_has_vul_with_scenario_v9(
        source_dir, scan_rules)
    final_result = {}
    # logger.info(res)
    for file in res:
        with open(file) as f:
            source = f.read().splitlines()
            for contract in res[file]:
                for function1 in res[file][contract]:
                    
                    # I think should first ask for function 1
                    # this is a key value map for vul -> result
                    function1_tmp_result = {}

                    for function2 in res[file][contract][function1]:
                        confirmed_vuls = {}
                        for vul in res[file][contract][function1][function2]["data"]:
                            meta_data["rules_types_for_static"].add(vul["name"])
                            if disable_static:
                                confirmed_vuls[vul["name"]] = {"StaticAnalysis": "Disabled"}
                            # if the rule need static check
                            elif "static" in vul:
                                # if need static check

                                # if function1 is not asked yet, ask for function1 first
                                if vul["name"] not in function1_tmp_result:
                                    function1_detail = cg.get_function_detail(file, contract, function1)
                                    function1_text = "\n".join(open(file).read().splitlines()[int(function1_detail['loc']['start'].split(":")[0])-1:int(function1_detail['loc']['end'].split(":")[0])])
                                    try:
                                        args = []
                                        checker = vul["static"]["rule"]["name"]
                                        if "multisteps" in vul["static"] and vul["static"]["multisteps"] == True:
                                            answer = analyze_pipeline.ask_for_static_multistep(vul["static"]["prompt"], function1_text, vul["static"]["output_keys"])
                                            if "filter" in vul["static"]:
                                                for filter_variable in vul["static"]["filter"]:
                                                    if filter_variable in answer:
                                                        for var in answer[filter_variable].copy():
                                                            var_remove_flag = True
                                                            for target_feature in vul["static"]["filter"][filter_variable]:
                                                                if target_feature.lower() in var.lower():
                                                                    var_remove_flag = False
                                                                    break
                                                            if var_remove_flag == True:
                                                                answer[filter_variable].remove(var)
                                                                
                                                    else:
                                                        raise Exception("Filter variable not found")
                                        else:
                                            if "format" in vul["static"] and vul["static"]["format"] == "json":
                                                answer, raw = analyze_pipeline.ask_for_static_json(vul["static"]["prompt"], function1_text, vul["static"]["output_keys"])
                                                if "validate_description" in vul["static"]:
                                                    for to_validate_key, to_validate_values in vul["static"]["validate_description"].items():
                                                        validate_flag = True
                                                        selected_value = answer.get(to_validate_key)
                                                        raw_value = raw.get(to_validate_key)
                                                        candidate_descriptions = _collect_candidate_descriptions(raw_value, selected_value)
                                                        for v_line in to_validate_values:
                                                            v_line_flag = False
                                                            for v in v_line:
                                                                for description in candidate_descriptions:
                                                                    if v.lower() in description.lower():
                                                                        v_line_flag = True
                                                                        break
                                                                if v_line_flag:
                                                                    break
                                                            validate_flag = validate_flag and v_line_flag
                                                        if validate_flag == False:
                                                            raise Exception("The description of variable did not pass the `validate_description` validation")
                                                if "exclude_variable" in vul["static"]:
                                                    for to_exclude_key, to_exclude_values in vul["static"]["exclude_variable"].items():
                                                        validate_flag = True
                                                        answer_text = _flatten_to_text(answer.get(to_exclude_key, ""))
                                                        for var in to_exclude_values:
                                                            if var.lower() in answer_text.lower():
                                                                validate_flag = False
                                                                break
                                                        if validate_flag == False:
                                                            raise Exception("The description of variable did not pass the `exclude_variable` validation")
                                            elif "format" in vul["static"] and vul["static"]["format"] == "json_single":
                                                answer = analyze_pipeline.ask_for_static_json_single(vul["static"]["prompt"], function1_text, vul["static"]["output_keys"][0])
                                            elif "format" in vul["static"] and vul["static"]["format"] == "not_need":
                                                pass
                                            else:
                                                answer = analyze_pipeline.ask_for_static(vul["static"]["prompt"], function1_text, vul["static"]["output_keys"])

                                        if "multisteps" not in vul["static"] or vul["static"]["multisteps"] == False:
                                            for arg in vul["static"]["rule"]["args"]:
                                                if "CONSTANT" in arg:
                                                    args.append(arg["CONSTANT"])
                                                else:
                                                    if "format" in vul["static"] and vul["static"]["format"] == "json" or vul["static"]["format"] == "json_single":
                                                        args.append(answer[arg])
                                                    elif "format" in vul["static"] and vul["static"]["format"] == "not_need":
                                                        args = list(map(lambda x: x["constant"], vul["static"]["args"]))
                                                    else:
                                                        args.append(
                                                            answer[arg].split(" ")[0])
                                        else:
                                            for arg in vul["static"]["rule"]["args"]:
                                                if "CONSTANT" in arg:
                                                    args.append(arg["CONSTANT"])
                                                else:
                                                    args.append(answer[arg])

                                        res_1 = static_check.run_static_check(checker, args, function1, falcon_instance, function1_text)
                                        function1_tmp_result[vul["name"]] = res_1
                                    except:
                                        logger.error(
                                            "Static analysis failed: Invalid args")
                                        logger.error(f"Current File: {file}, current function: {function1}, current vul: {vul['name']}")
                                        logger.error(traceback.format_exc())
                                        # raise Exception(
                                        #     "Static analysis failed: Invalid args")
                                        function1_tmp_result[vul["name"]] = False


                                # if function1 is asked, use the result directly
                                # and ask for function2
                                res_2 = None
                                if function2 == "__ONLY_FUNCTION__":
                                    res_2 = False
                                else:
                                    try:
                                        args = []
                                        checker = vul["static"]["rule"]["name"]
                                        function2_splitted = function2.split("!!!")
                                        function2_file = function2_splitted[0]
                                        function2_contract = function2_splitted[1]
                                        function2_func = function2_splitted[2]
                                        function2_detail = cg.get_function_detail(function2_file, function2_contract, function2_func)
                                        function2_text = "\n".join(open(function2_file).read().splitlines()[int(function2_detail['loc']['start'].split(":")[0])-1:int(function2_detail['loc']['end'].split(":")[0])])
                                        if "multisteps" in vul["static"] and vul["static"]["multisteps"] == True:
                                            answer = analyze_pipeline.ask_for_static_multistep(vul["static"]["prompt"], function2_text, vul["static"]["output_keys"])
                                        else:
                                            if "format" in vul["static"] and vul["static"]["format"] == "json":
                                                answer, raw = analyze_pipeline.ask_for_static_json(vul["static"]["prompt"], function2_text, vul["static"]["output_keys"])
                                                if "validate_description" in vul["static"]:
                                                    for to_validate_key, to_validate_values in vul["static"]["validate_description"].items():
                                                        validate_flag = True
                                                        selected_value = answer.get(to_validate_key)
                                                        raw_value = raw.get(to_validate_key)
                                                        candidate_descriptions = _collect_candidate_descriptions(raw_value, selected_value)
                                                        for v_line in to_validate_values:
                                                            v_line_flag = False
                                                            for v in v_line:
                                                                for description in candidate_descriptions:
                                                                    if v.lower() in description.lower():
                                                                        v_line_flag = True
                                                                        break
                                                                if v_line_flag:
                                                                    break
                                                            validate_flag = validate_flag and v_line_flag
                                                        if validate_flag == False:
                                                            raise Exception("The description of variable did not pass the validation")
                                                if "exclude_variable" in vul["static"]:
                                                    for to_exclude_key, to_exclude_values in vul["static"]["exclude_variable"].items():
                                                        validate_flag = True
                                                        answer_text = _flatten_to_text(answer.get(to_exclude_key, ""))
                                                        for var in to_exclude_values:
                                                            if var.lower() in answer_text.lower():
                                                                validate_flag = False
                                                                break
                                                        if validate_flag == False:
                                                            raise Exception("The description of variable did not pass the `exclude_variable` validation")
                                            elif "format" in vul["static"] and vul["static"]["format"] == "json_single":
                                                answer = analyze_pipeline.ask_for_static_json_single(vul["static"]["prompt"], function2_text, vul["static"]["output_keys"][0])
                                            elif "format" in vul["static"] and vul["static"]["format"] == "not_need":
                                                pass
                                            else:
                                                answer = analyze_pipeline.ask_for_static(vul["static"]["prompt"], function2_text, vul["static"]["output_keys"])

                                        if "multisteps" not in vul["static"] or vul["static"]["multisteps"] == False:
                                            for arg in vul["static"]["rule"]["args"]:
                                                if "CONSTANT" in arg:
                                                    args.append(arg["CONSTANT"])
                                                else:
                                                    if "format" in vul["static"] and vul["static"]["format"] == "json" or vul["static"]["format"] == "json_single":
                                                        args.append(answer[arg])
                                                    elif "format" in vul["static"] and vul["static"]["format"] == "not_need":
                                                        args = list(map(lambda x: x["constant"], vul["static"]["args"]))
                                                    else:
                                                        args.append(
                                                            answer[arg].split(" ")[0])
                                        else:
                                            for arg in vul["static"]["rule"]["args"]:
                                                if "CONSTANT" in arg:
                                                    args.append(arg["CONSTANT"])
                                                else:
                                                    args.append(answer[arg])
                                        res_2 = static_check.run_static_check(checker, args, function2_func, falcon_instance, function2_text)
                                    except:
                                        logger.error(
                                            "Static analysis failed: Invalid args")
                                        logger.error(f"Current File: {file}, current function: {function1}, current vul: {vul['name']}")
                                        logger.error(traceback.format_exc())
                                        res_2 = False
                                

                                # if function1 and function2 are both asked, merge the result
                                confirmed_vuls[vul["name"]]={"StaticAnalysis": function1_tmp_result[vul["name"]] or res_2}

                            else:
                                confirmed_vuls[vul["name"]]={"StaticAnalysis": "Not Needed"}
                        if len(confirmed_vuls)>0:
                            if file not in final_result:
                                final_result[file] = {}
                            if contract not in final_result[file]:
                                final_result[file][contract] = {}
                            if function1 not in final_result[file][contract]:
                                final_result[file][contract][function1] = {}
                            final_result[file][contract][function1][function2] = confirmed_vuls

    num_true = 0
    num_false = 0
    for file_, file_data_ in final_result.items():
        for contract_, contract_data_ in file_data_.items():
            for function1_, function1_data_ in contract_data_.items():
                for function2_, function2_data_ in function1_data_.items():
                    for vul_, vul_data_ in function2_data_.items():
                        if "StaticAnalysis" in vul_data_:
                            if vul_data_["StaticAnalysis"] == False:
                                num_false += 1
                            else:
                                meta_data["files_after_static"].add(file_)
                                meta_data["contracts_after_static"].add(file_+"!!!"+contract_)
                                meta_data["functions_after_static"].add(file_+"!!!"+contract_+"!!!"+function1_)
                                if function2_ != "__ONLY_FUNCTION__":
                                    meta_data["files_after_static"].add(function2_.split("!!!")[0])
                                    meta_data["contracts_after_static"].add(function2_.split("!!!")[0]+"!!!"+function2_.split("!!!")[1])
                                    meta_data["functions_after_static"].add(function2_)
                                meta_data["rules_types_after_static"].add(vul_)
                                num_true += 1

    # json.dump(res, open(output_file, "w"), indent=4)
    output_json = utils.convert_output(final_result, scan_rules, cg, source_dir)

    remediation_stats = None
    vul_after_merge = len(output_json.get("results", []))
    vul_after_remediation = vul_after_merge
    if enable_remediation:
        patches_root = os.path.abspath(output_file + ".patches")
        console.log(f"[cyan]Remediation enabled[/cyan]. Writing patched artifacts to: {patches_root}")
        engine = remediation.RemediationEngine(
            max_rounds=remediation_max_rounds,
            patches_root=Path(patches_root),
            verify_mode=remediation_verify_mode,
            llm_timeout_seconds=int(os.environ.get("GPTSCAN_OLLAMA_TIMEOUT", "60")),
            second_ollama_url=os.environ.get("GPTSCAN_OLLAMA_URL_SECOND", ""),
        )
        patched_results, remediation_stats = engine.remediate_findings(output_json.get("results", []), cg)
        if remediation_drop_fixed:
            patched_results = [
                result
                for result in patched_results
                if (result.get("remediation", {}).get("status") != "fixed")
            ]
        output_json["results"] = patched_results
        vul_after_remediation = len(output_json["results"])

    meta_data["used_time"]= time.time()-start_time  # 花费时间，单位为秒
    meta_data["vul_before_static"] = num_true + num_false   # 静态分析前，第二次交互为yes的数量，可能有重复（A和A+B）
    meta_data["vul_after_static"] = num_true    # 静态分析后，结果不为False的数量（之前有不需要静态分析的，现在没了）
    meta_data["vul_after_merge"] = vul_after_merge  # 去重后的结果数量（修复前）
    meta_data["vul_after_remediation"] = vul_after_remediation
    if disable_static:
        meta_data["static_analysis_disabled"] = True
    if enable_remediation:
        meta_data["remediation_enabled"] = True
        meta_data["remediation_max_rounds"] = remediation_max_rounds
        meta_data["remediation_drop_fixed"] = remediation_drop_fixed
        meta_data["remediation_verify_mode"] = remediation_verify_mode
        meta_data["remediation_stats"] = remediation_stats or {}

    meta_data["token_sent"] = chatgpt_api.tokens_sent.value # 发送的Token数量
    meta_data["token_received"] = chatgpt_api.tokens_received.value # 接收的Token数量
    meta_data["token_sent_gpt4"] = chatgpt_api.tokens_sent_gpt4.value # 发送的Token数量
    meta_data["token_received_gpt4"] = chatgpt_api.tokens_received_gpt4.value # 接收的Token数量
    meta_data["falcon_initialized"] = falcon_instance is not None
    if cli_args.provider == "openai":
        meta_data["estimated_cost"] = (meta_data["token_sent"] * global_config.SEND_PRICE) + (meta_data["token_received"] * global_config.RECEIVE_PRICE) + (meta_data["token_sent_gpt4"] * global_config.GPT4_SEND_PRICE) + (meta_data["token_received_gpt4"] * global_config.GPT4_RECEIVE_PRICE)
    else:
        meta_data["estimated_cost"] = global_config.LOCAL_LLM_ESTIMATED_COST

    meta_data["llm_provider"] = cli_args.provider
    if cli_args.model.strip() != "":
        meta_data["llm_model"] = cli_args.model.strip()
    elif cli_args.provider == "openai":
        meta_data["llm_model"] = global_config.OPENAI_MODEL
    else:
        meta_data["llm_model"] = global_config.OLLAMA_MODEL

    if cli_args.provider == "ollama":
        meta_data["llm_base_url"] = cli_args.ollama_url

    for metadata_key, metadata_value in meta_data.copy().items():
        if isinstance(metadata_value, set):
            meta_data[metadata_key] = len(metadata_value)

    # logger.info("============= Summary ===============")
    # logger.info(json.dumps(meta_data))

    summary_table = Table(title="Summary")
    summary_table.add_column("Key")
    summary_table.add_column("Value")
    summary_table.add_row("Files", str(meta_data["files"]))
    summary_table.add_row("Contracts", str(meta_data["contracts"]))
    summary_table.add_row("Functions", str(meta_data["functions"]))
    summary_table.add_row("Lines of Code", str(meta_data["loc"]))
    summary_table.add_row("LLM Provider", str(meta_data["llm_provider"]))
    summary_table.add_row("LLM Model", str(meta_data["llm_model"]))
    summary_table.add_row("Falcon Initialized", str(meta_data["falcon_initialized"]))
    summary_table.add_row("Used Time", str(meta_data["used_time"]))
    summary_table.add_row("Estimated Cost (USD)", str(meta_data["estimated_cost"]))

    console.print(summary_table)


    json.dump(output_json, open(output_file, "w"), indent=4)
    json.dump(meta_data, open(output_file+".metadata.json", "w"), indent=4)
