import logging
logger = logging.getLogger(__name__)
import falcon_adapter
from falcon import Falcon
from typing import List
import re
import rich
import rich_utils

console = rich.get_console()


def _coerce_symbol(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        if len(value) == 0:
            return ""
        # Most LLM outputs for variable extraction are {"varName": "description"}.
        # Prefer the key as the symbol name used in source code checks.
        return str(next(iter(value.keys())))
    if isinstance(value, (list, tuple, set)):
        if len(value) == 0:
            return ""
        return _coerce_symbol(next(iter(value)))
    return str(value)

# Could return None
def __has_check(var:str, text):
    if var in text:
        return f"{var}<" in text or f"{var} <" in text or f"{var} >" in text or f"{var}>" in text or f"{var}<=" in text or f"{var} <=" in text or f"{var} >=" in text or f"{var}>=" in text or f"<{var}" in text or f"< {var}" in text or f">{var}" in text or f"> {var}" in text or f"<={var}" in text or f"<= {var}" in text or f">={var}" in text or f">= {var}" in text
    return None

def __has_noneq_check(var1:str, var2:str, text):
    var1 = _coerce_symbol(var1)
    var2 = _coerce_symbol(var2)
    if var1 in text and var2 in text:
        return f"{var1} != {var2}" in text or f"{var1}!={var2}" in text or f"{var1} !={var2}" in text or f"{var1}!= {var2}" in text or f"{var2} != {var1}" in text or f"{var2}!={var1}" in text or f"{var2}!= {var1}" in text or f"{var2} !={var1}" in text
    return False

def __has_eq_check(var1:str, var2:str, text):
    var1 = _coerce_symbol(var1)
    var2 = _coerce_symbol(var2)
    if var1 in text and var2 in text:
        return f"{var1} == {var2}" in text or f"{var1}=={var2}" in text or f"{var1} =={var2}" in text or f"{var1}== {var2}" in text or f"{var2} == {var1}" in text or f"{var2}=={var1}" in text or f"{var2}== {var1}" in text or f"{var2} =={var1}" in text
    return False

# only var1 > var2, since var2 is 0
def __has_larger_check(var1:str, var2:str, text):
    var1 = _coerce_symbol(var1)
    var2 = _coerce_symbol(var2)
    if var1 in text and var2 in text:
        return f"{var1} > {var2}" in text or f"{var2}>{var1}" in text or f"{var1}> {var2}" in text or f"{var1} >{var2}" in text
    return False

def __order_first_b(a:List[str], b:List[str], text):
    # make sure that all a happens after b in text
    # a: change balance
    # b: change interest, a should happen after b

    # if any is empty, return false
    if len(a) == 0 or len(b) == 0:
        return False

    # if a and b point to the same statement, return false
    if len(a) == 1 and len(b) == 1:
        stmt_a = a[0]
        stmt_b = b[0]
        if stmt_a in stmt_b or stmt_b in stmt_a:
            return False
    
    # if a or b are not in the text, return false
    text_has_a_flag = False
    text_has_b_flag = False

    for a_var in a:
        if a_var in text:
            text_has_a_flag = True
            break
    for b_var in b:
        if b_var in text:
            text_has_b_flag = True
            break
    if not text_has_a_flag or not text_has_b_flag:
        return False

    # if exist a happens before b, return false
    for a_var in a:
        for b_var in b:
            if a_var in text and b_var in text:
                try:
                    if text.index(a_var) < text.index(b_var):
                        return True
                except:
                    continue
    
    # if all a happens after b, return true
    return False

def __call_arg_check(function:str, arg:str, text:str):
    function = _coerce_symbol(function)
    arg = _coerce_symbol(arg)
    if function not in text:
        return True
    else:
        return False
    
def __emit_at_end(function:str, text:str):
    function = _coerce_symbol(function)
    if f"emit {function}" not in text:
        return True
    # the length is 5 means that there are 4 commas, and there are 3 statements after emit.
    return len(re.split(f'emit\\s*{function}', text)[-1].split[","]) > 5

def __in_code(pattern:str, text:str):
    pattern = _coerce_symbol(pattern)
    return pattern.lower() in text.lower()

def run_static_check(checker:str, args, function_name:str, falcon:Falcon, text:str) -> bool:
    # if there is a vulnerability, return true
    match checker:
        case "find_data_dependency":
            var_a = _coerce_symbol(args[0])
            var_b = _coerce_symbol(args[1])

            if var_a is None or var_a == '' or var_a == 'N/A':
                return False
            if var_b is None or var_b == '' or var_b == 'N/A':  # TODO 'N/A' for the case of return value
                return False
            if var_b == var_a:
                return True

            console.print(rich_utils.make_args_table([var_a, var_b], "find_data_dependency"))

            lines = text.splitlines()
            for line in lines:
                 # if these two variable are in the same line, they have dependency
                if var_a in line and var_b in line and '=' in line:
                    return True
                # if first parameter is in the return statement
                if var_a in line and 'return ' in line:
                    return True
                    
            if falcon is None:
                logger.warning("Falcon is not initialized, skipping data dependency check")
                return False
            
            return falcon_adapter.find_data_dependency(var_a, var_b, function_name, falcon)
        
        case "first_deposit_check":
            if falcon is None:
                logger.warning("Falcon is not initialized, skipping first deposit check")
                return False
            varB = _coerce_symbol(args[0])
            varC = _coerce_symbol(args[1])
            varA = _coerce_symbol(args[2])
            logger.info(f"first_deposit_check: VariableA: {varA}; VariableB: {varB}; VariableC: {varC}")
            # check Variable C
            if varC == "" or varC == "N/A":
                return False
            
            console.print(rich_utils.make_args_table([varB, varC, varA], "first_deposit_check"))

            # check if (VariableB == 0) or in the else branch via __has_larger_check(varB, "0", text)) but need if
            checkB = __has_eq_check(varB, "0", text)
            # check VariableA = VariableC  or  mint(VariableC)
            return checkB and falcon_adapter.first_deposit_check(varB, varC, varA, function_name, falcon)
        
        case "has_check":
            init_value = None
            for arg in args:
                if arg is None:
                    continue
                new_value = __has_check(arg, text)
                if new_value is None:
                    continue
                if init_value == None:
                    init_value = not new_value
                else:
                    init_value |= not new_value
            return True if init_value is None else init_value
        
        case "has_min_check":
            init_value = None
            for arg in args:
                if arg is None:
                    continue
                new_value = __has_check(arg, text)
                if new_value is None:
                    continue
                if "min" in arg.lower() or "limit" in arg.lower() or "slip" in arg.lower() or "desire" in arg.lower():
                    new_value = True
                if init_value == None:
                    init_value = not new_value
                else:
                    init_value |= not new_value
            return True if init_value is None else init_value
        
        case "has_eq_check":
            if args[0] == args[1]:
                return False
            console.print(rich_utils.make_args_table(args, "has_eq_check"))
            checkA = (__has_eq_check(args[0], args[1], text) or __has_noneq_check(args[0], args[1], text))
            return not checkA

        case "order_first_b":
            console.print(rich_utils.make_args_table(args, "order_first_b"))
            check = __order_first_b(args[0], args[1], text)
            return check
    
        case "call_arg_check":
            function = _coerce_symbol(args[0])
            arg = _coerce_symbol(args[1])
            console.print(rich_utils.make_args_table([function, arg], "call_arg_check"))
            if falcon is None:
                logger.warning("Falcon is not initialized, skipping call arg check")
                return False
            check = __call_arg_check(function, arg, text)
            check |= falcon_adapter.is_arg_taint(function, 0, function_name, falcon)
            return check
        
        case "emit_at_end":
            check = __emit_at_end(_coerce_symbol(args[0]), text)
            return check

        case "in_code":
            check = __in_code(_coerce_symbol(args[0]), text)
            return check
        
        case "check_require":
            codes = args[0]
            console.print(rich_utils.make_args_table(args, "check_require"))
            for code in codes:
                if "require" in code or "if " in code or "if(" in code or "assert" in code:
                    return True
            return False

