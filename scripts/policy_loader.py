"""
SkillGuard Policy Loader (Zero Dependencies - Python stdlib only)
Loads YAML policies, manifests, and rules into native Python dictionaries and lists.
"""

import os
import re
import json
from pathlib import Path
from typing import Any, Dict, List, Union


def _parse_scalar(val_str: str) -> Any:
    val = val_str.strip()
    if not val:
        return ""
    if val.startswith('"') and val.endswith('"'):
        inner = val[1:-1]
        # In YAML double quotes, unescape \" \n \t and \\
        return inner.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')
    if val.startswith("'") and val.endswith("'"):
        inner = val[1:-1]
        return inner.replace("''", "'")
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.lower() == "null" or val == "~":
        return None
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


def parse_simple_yaml(text: str) -> Any:
    """
    Lightweight, robust YAML subset parser written strictly in Python standard library.
    Handles dictionaries, lists, scalar types, nested blocks, and comments.
    """
    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        stripped = line.rstrip()
        comment_idx = -1
        in_double = False
        in_single = False
        escaped = False
        for i, char in enumerate(stripped):
            if escaped:
                escaped = False
                continue
            if char == '\\':
                escaped = True
                continue
            if char == '"' and not in_single:
                in_double = not in_double
            elif char == "'" and not in_double:
                in_single = not in_single
            elif char == '#' and not in_double and not in_single:
                comment_idx = i
                break
        if comment_idx != -1:
            stripped = stripped[:comment_idx].rstrip()
        if stripped.strip():
            indent = len(stripped) - len(stripped.lstrip())
            cleaned_lines.append((indent, stripped.strip()))

    def parse_block(idx: int, current_indent: int) -> tuple[Any, int]:
        if idx >= len(cleaned_lines):
            return None, idx

        # Determine if this block is a list or a dict
        first_indent, first_content = cleaned_lines[idx]
        is_list = first_content.startswith("- ")

        if is_list:
            result_list = []
            while idx < len(cleaned_lines):
                indent, content = cleaned_lines[idx]
                if indent < current_indent:
                    break
                if not content.startswith("- "):
                    break
                item_content = content[2:].strip()
                if not item_content:
                    # Item has children
                    child_val, idx = parse_block(idx + 1, indent + 2)
                    result_list.append(child_val)
                elif ":" in item_content and not item_content.startswith(('"', "'")):
                    # Dict inside list: "- id: 'foo'"
                    colon_pos = item_content.index(":")
                    k = item_content[:colon_pos].strip()
                    v = item_content[colon_pos + 1:].strip()
                    elem_dict = {}
                    if v:
                        elem_dict[k] = _parse_scalar(v)
                    else:
                        child_val, idx = parse_block(idx + 1, indent + 2)
                        elem_dict[k] = child_val
                    idx += 1
                    # Parse subsequent keys under the same list item
                    while idx < len(cleaned_lines):
                        sub_indent, sub_content = cleaned_lines[idx]
                        if sub_indent <= indent or sub_content.startswith("- "):
                            break
                        if ":" in sub_content:
                            c_pos = sub_content.index(":")
                            sub_k = sub_content[:c_pos].strip()
                            sub_v = sub_content[c_pos + 1:].strip()
                            if sub_v:
                                elem_dict[sub_k] = _parse_scalar(sub_v)
                                idx += 1
                            else:
                                sub_child, idx = parse_block(idx + 1, sub_indent + 2)
                                elem_dict[sub_k] = sub_child
                        else:
                            idx += 1
                    result_list.append(elem_dict)
                    continue
                else:
                    result_list.append(_parse_scalar(item_content))
                    idx += 1
            return result_list, idx

        # Otherwise parse dict
        result_dict = {}
        while idx < len(cleaned_lines):
            indent, content = cleaned_lines[idx]
            if indent < current_indent:
                break
            if ":" not in content:
                idx += 1
                continue
            colon_pos = content.index(":")
            key = content[:colon_pos].strip()
            val = content[colon_pos + 1:].strip()

            if val:
                result_dict[key] = _parse_scalar(val)
                idx += 1
            else:
                # Value is on subsequent lines
                if idx + 1 < len(cleaned_lines):
                    next_indent, _ = cleaned_lines[idx + 1]
                    if next_indent > indent:
                        child_val, idx = parse_block(idx + 1, next_indent)
                        result_dict[key] = child_val
                    else:
                        result_dict[key] = None
                        idx += 1
                else:
                    result_dict[key] = None
                    idx += 1
        return result_dict, idx

    parsed, _ = parse_block(0, 0)
    return parsed or {}


def load_policy(policy_path: Union[str, Path] = None) -> Dict[str, Any]:
    if policy_path is None:
        root = Path(__file__).resolve().parent.parent
        policy_path = root / "policy" / "policy.default.yaml"
    with open(policy_path, "r", encoding="utf-8") as f:
        return parse_simple_yaml(f.read())


def load_trust(trust_path: Union[str, Path] = None) -> Dict[str, Any]:
    if trust_path is None:
        root = Path(__file__).resolve().parent.parent
        trust_path = root / "policy" / "trust.yaml"
    with open(trust_path, "r", encoding="utf-8") as f:
        return parse_simple_yaml(f.read())


def load_network_allowlist(allowlist_path: Union[str, Path] = None) -> List[str]:
    if allowlist_path is None:
        root = Path(__file__).resolve().parent.parent
        allowlist_path = root / "policy" / "network-allowlist.txt"
    domains = []
    with open(allowlist_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def load_all_rules(rules_dir: Union[str, Path] = None) -> List[Dict[str, Any]]:
    if rules_dir is None:
        root = Path(__file__).resolve().parent.parent
        rules_dir = root / "policy" / "rules"
    rules_dir = Path(rules_dir)
    all_rules = []
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_file, "r", encoding="utf-8") as f:
            data = parse_simple_yaml(f.read())
            cat_name = data.get("category", yaml_file.stem)
            for rule in data.get("rules", []):
                rule["source_file"] = yaml_file.name
                rule["category"] = cat_name
                all_rules.append(rule)
    return all_rules
