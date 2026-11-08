"""
SkillGuard Module 1: Static Skill Scanner
Analyzes skill directories, zip files, git repositories, and prompt files.
Performs strictly read-only, non-executing static security analysis.
"""

import argparse
import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add current scripts directory to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy, load_all_rules, load_network_allowlist
from prompt_guard import sanitize_evidence, format_deterministic_alert


def calculate_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences: Dict[str, int] = {}
    for char in data:
        occurrences[char] = occurrences.get(char, 0) + 1
    for count in occurrences.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy


def extract_frontmatter(content: str) -> Tuple[Dict[str, str], str]:
    """Extracts frontmatter metadata from markdown."""
    frontmatter = {}
    body = content
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1]
            body = parts[2]
            for line in fm_text.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    frontmatter[k.strip().lower()] = v.strip().strip('"\'')
    return frontmatter, body


def safe_extract_zip(zip_path: Path, target_dir: Path, max_size_bytes: int = 20971520, max_files: int = 500):
    """
    Safely extracts zip file protecting against Zip Slip (path traversal) and decompression bombs.
    """
    total_size = 0
    total_files = 0
    target_dir = target_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > max_files:
            raise ValueError(f"Zip bomb protection: archive contains {len(infolist)} files (max {max_files}).")

        for member in infolist:
            total_files += 1
            total_size += member.file_size
            if total_size > max_size_bytes:
                raise ValueError(f"Zip bomb protection: uncompressed size exceeds {max_size_bytes} bytes.")

            # Path traversal check
            dest_path = (target_dir / member.filename).resolve()
            if not str(dest_path).startswith(str(target_dir)):
                raise ValueError(f"Zip slip detected: path traversal attempt via '{member.filename}'.")

            # Symlink check (Unix mode symlink)
            if (member.external_attr >> 16) & 0o120000 == 0o120000:
                raise ValueError(f"Symlink escape detected: '{member.filename}' is a symlink.")

            zf.extract(member, target_dir)


def clone_git_repo_safely(git_url: str, target_dir: Path) -> None:
    """
    Clones a git repo with security flags: depth 1, hooks disabled, submodules disabled.
    """
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "clone",
        "--depth", "1",
        "--no-recurse-submodules",
        git_url,
        str(target_dir)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(f"Git clone failed: {res.stderr.strip()}")


class SkillScanner:
    def __init__(self, policy: Optional[Dict[str, Any]] = None, rules: Optional[List[Dict[str, Any]]] = None):
        self.policy = policy or load_policy(ROOT_DIR / "policy" / "policy.default.yaml")
        self.rules = rules if rules is not None else load_all_rules(ROOT_DIR / "policy" / "rules")
        self.allowlist = load_network_allowlist(ROOT_DIR / "policy" / "network-allowlist.txt")

        # Compile rule patterns
        self.compiled_rules = []
        for r in self.rules:
            patterns = r.get("patterns", [])
            compiled = []
            for pat in patterns:
                try:
                    compiled.append(re.compile(pat))
                except re.error:
                    pass
            self.compiled_rules.append({
                "id": r.get("id"),
                "name": r.get("name"),
                "severity": r.get("severity", "MEDIUM"),
                "category": r.get("category", "General"),
                "description": r.get("description", ""),
                "why_dangerous": r.get("why_dangerous", ""),
                "remediation": r.get("remediation", ""),
                "compiled_patterns": compiled,
            })

    def scan_content(self, content: str, file_name: str = "SKILL.md") -> List[Dict[str, Any]]:
        """Scans in-memory text against all security rules."""
        findings: List[Dict[str, Any]] = []
        lines = content.splitlines()

        # Check for inline suppression comments: # skillguard: ignore <RULE-ID> reason="..."
        suppressed_rules: Dict[str, str] = {}
        for line in lines:
            m = re.search(r"#\s*skillguard:\s*ignore\s+([A-Z0-9_-]+)\s*(?:reason=[\"']([^\"']+)[\"'])?", line, re.IGNORECASE)
            if m:
                rule_id = m.group(1).upper()
                reason = m.group(2) or "Unspecified reason"
                suppressed_rules[rule_id] = reason

        for rule in self.compiled_rules:
            rule_id = rule["id"]
            severity = rule["severity"]

            for line_no, line in enumerate(lines, start=1):
                # Check for comment suppression
                if rule_id in suppressed_rules:
                    # CRITICAL rules can NEVER be suppressed!
                    if severity == "CRITICAL":
                        findings.append({
                            "id": "SEC-OVERRIDE-DENIED",
                            "name": "Unauthorized Critical Rule Suppression",
                            "severity": "CRITICAL",
                            "category": "Policy Violation",
                            "file": file_name,
                            "line": line_no,
                            "evidence": f"Attempted to ignore critical rule {rule_id}",
                            "why_dangerous": f"Critical security findings cannot be suppressed via code comments.",
                            "remediation": f"Remove '# skillguard: ignore {rule_id}' comment and fix the underlying risk.",
                        })
                    else:
                        continue

                for pat in rule["compiled_patterns"]:
                    match = pat.search(line)
                    if match:
                        findings.append({
                            "id": rule_id,
                            "name": rule["name"],
                            "severity": severity,
                            "category": rule["category"],
                            "file": file_name,
                            "line": line_no,
                            "evidence": match.group(0),
                            "why_dangerous": rule["why_dangerous"],
                            "remediation": rule["remediation"],
                        })
                        break  # One match per rule per line is sufficient

        # High Entropy / Obfuscation check
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            # If line is unusually long, continuous without spaces, and high entropy
            if len(stripped) > 80 and " " not in stripped and calculate_entropy(stripped) > 4.8:
                if not any(f["id"] == "OBF-003" and f["line"] == line_no for f in findings):
                    findings.append({
                        "id": "OBF-003",
                        "name": "High Entropy Obfuscated String",
                        "severity": "HIGH",
                        "category": "Obfuscation",
                        "file": file_name,
                        "line": line_no,
                        "evidence": stripped[:60] + "...",
                        "why_dangerous": "High Shannon entropy indicates an encrypted, compressed, or packed payload.",
                        "remediation": "Audit constant string and decode before deploying.",
                    })

        return findings

    def scan_directory(self, dir_path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Scans an entire directory tree of a skill."""
        dir_path = Path(dir_path).resolve()
        all_findings: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {
            "name": dir_path.name,
            "description": "",
            "files_scanned": 0,
            "scope_mismatch": False,
        }

        max_file_size = self.policy.get("limits", {}).get("max_file_size_bytes", 5242880)

        # First inspect SKILL.md if present
        skill_md = dir_path / "SKILL.md"
        skill_text = ""
        if skill_md.is_file():
            try:
                skill_text = skill_md.read_text(encoding="utf-8", errors="replace")
                fm, _ = extract_frontmatter(skill_text)
                if "name" in fm:
                    metadata["name"] = fm["name"]
                if "description" in fm:
                    metadata["description"] = fm["description"]
            except Exception:
                pass

        for root, dirs, files in os.walk(dir_path):
            # Skip .git directory
            if ".git" in dirs:
                dirs.remove(".git")
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(dir_path)

                if file_path.stat().st_size > max_file_size:
                    all_findings.append({
                        "id": "SCAN-LIMIT-EXCEEDED",
                        "name": "File Size Limit Exceeded",
                        "severity": "MEDIUM",
                        "category": "Limits",
                        "file": str(rel_path),
                        "line": 0,
                        "evidence": f"File size {file_path.stat().st_size} bytes exceeds limit {max_file_size}",
                        "why_dangerous": "Oversized files can cause DoS during agent parsing.",
                        "remediation": "Reduce file size or store assets externally.",
                    })
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    file_findings = self.scan_content(content, str(rel_path))
                    all_findings.extend(file_findings)
                    metadata["files_scanned"] += 1
                except Exception as e:
                    all_findings.append({
                        "id": "SCAN-READ-ERROR",
                        "name": "Unreadable File Error",
                        "severity": "LOW",
                        "category": "Scanner",
                        "file": str(rel_path),
                        "line": 0,
                        "evidence": str(e),
                        "why_dangerous": "Failed to inspect file statically.",
                        "remediation": "Check file encoding and permissions.",
                    })

        # Scope compatibility analysis
        desc = metadata.get("description", "").lower()
        has_network_findings = any(f.get("category") == "Data Exfiltration & Unauthorized Network Sinks" for f in all_findings)
        has_persistence_findings = any(f.get("category") == "Persistence & System Tampering" for f in all_findings)
        is_declared_pure_tool = any(kw in desc for kw in ["format", "linter", "read-only", "calculator", "color", "parser"])

        if is_declared_pure_tool and (has_network_findings or has_persistence_findings):
            metadata["scope_mismatch"] = True
            all_findings.append({
                "id": "SCP-001",
                "name": "Capability Scope Exceeded",
                "severity": "HIGH",
                "category": "Scope Violation",
                "file": "SKILL.md",
                "line": 1,
                "evidence": f"Description states '{desc[:60]}' but attempts persistence/network actions.",
                "why_dangerous": "Skill claims benign formatting/reading utility while requesting privileged sinks.",
                "remediation": "Restrict skill scope or declare network/system requirements transparently.",
            })

        # Combination rule: agent directive + concealment + sensitive sink => CRITICAL
        has_agent_directive = any(f["id"].startswith("PI-") for f in all_findings)
        has_concealment = any(f["id"] == "PI-002" for f in all_findings)
        has_sink = any(f["id"].startswith(("EX-", "PER-")) for f in all_findings)

        if has_agent_directive and has_concealment and has_sink:
            all_findings.append({
                "id": "COMBO-CRITICAL-001",
                "name": "Lethal Combination: Concealed Agent Hijack & Sensitive Sink",
                "severity": "CRITICAL",
                "category": "Composite Threat",
                "file": "SKILL.md",
                "line": 1,
                "evidence": "Simultaneous prompt injection, user concealment, and sensitive sink detected.",
                "why_dangerous": "Confirms intentional multi-stage malicious agent compromise.",
                "remediation": "Block skill permanently and quarantine.",
            })

        return all_findings, metadata

    def evaluate_verdict(self, findings: List[Dict[str, Any]]) -> str:
        """Determines the overarching verdict according to the decision matrix."""
        if any(f.get("severity") == "CRITICAL" for f in findings):
            return "BLOCK"
        if any(f.get("severity") == "HIGH" for f in findings):
            return "CONFIRM"
        if any(f.get("severity") == "MEDIUM" for f in findings):
            return "WARN"
        if any(f.get("severity") == "LOW" for f in findings):
            return "ALLOW_WITH_NOTE"
        return "ALLOW"


def scan_target(target: str, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scans target path (file, directory, zip, or git URL) and returns structured analysis."""
    scanner = SkillScanner(policy=policy)
    temp_dir = None

    try:
        target_path = Path(target)
        if target.startswith("http://") or target.startswith("https://") or target.endswith(".git"):
            temp_dir = tempfile.mkdtemp(prefix="skillguard_git_")
            clone_git_repo_safely(target, Path(temp_dir))
            findings, metadata = scanner.scan_directory(Path(temp_dir))
        elif target_path.is_file() and target_path.suffix.lower() == ".zip":
            temp_dir = tempfile.mkdtemp(prefix="skillguard_zip_")
            safe_extract_zip(target_path, Path(temp_dir))
            findings, metadata = scanner.scan_directory(Path(temp_dir))
        elif target_path.is_file():
            content = target_path.read_text(encoding="utf-8", errors="replace")
            findings = scanner.scan_content(content, target_path.name)
            metadata = {
                "name": target_path.stem,
                "description": "",
                "files_scanned": 1,
                "scope_mismatch": False,
            }
        elif target_path.is_dir():
            findings, metadata = scanner.scan_directory(target_path)
        else:
            # Treat target as raw text snippet
            findings = scanner.scan_content(target, "inline_snippet.md")
            metadata = {
                "name": "inline_snippet",
                "description": "",
                "files_scanned": 1,
                "scope_mismatch": False,
            }

        verdict = scanner.evaluate_verdict(findings)
        alert_tr = format_deterministic_alert(findings, metadata.get("name", "skill"), language="tr")
        alert_en = format_deterministic_alert(findings, metadata.get("name", "skill"), language="en")

        return {
            "target": target,
            "name": metadata.get("name", "skill"),
            "files_scanned": metadata.get("files_scanned", 1),
            "verdict": verdict,
            "findings_count": len(findings),
            "findings": findings,
            "alert_tr": alert_tr,
            "alert_en": alert_en,
        }
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="SkillGuard Static Skill Scanner")
    parser.add_argument("target", help="Skill directory, zip file, git URL, or file path to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--lang", default="tr", choices=["tr", "en"], help="Alert message language (tr/en)")
    args = parser.parse_args()

    result = scan_target(args.target)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        alert_msg = result["alert_tr"] if args.lang == "tr" else result["alert_en"]
        print(alert_msg)

    if result["verdict"] == "BLOCK":
        sys.exit(2)
    elif result["verdict"] in ["CONFIRM", "WARN"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
