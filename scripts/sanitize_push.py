"""
SkillGuard Module 3: Pre-Commit & Pre-Push Automatic Sanitizer
Inspects staged git changes, repository files, and directories for leaked secrets,
forbidden credential files, high-entropy tokens, internal IPs, and sensitive comments.
Provides zero-dependency vault backups, automated code replacements, and single-command undo.
"""

import argparse
import difflib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy


# ==============================================================================
# PATTERNS & FORBIDDEN FILES
# ==============================================================================

FORBIDDEN_FILE_PATTERNS = [
    r"^\.env(\.[a-zA-Z0-9_-]+)?$",
    r".*\.(pem|key|p12|keystore|pfx|pkcs12)$",
    r".*\b(id_rsa|id_ecdsa|id_ed25519|id_dsa)$",
    r".*\.tfstate(\.backup)?$",
    r".*\.(sql|sqlite|sqlite3|db|bak|dump)$",
    r".*\.har$",
    r"^\.npmrc$",
]

EXEMPT_IP_PREFIXES = (
    "192.0.2.",    # TEST-NET-1 (RFC 5737)
    "198.51.100.",  # TEST-NET-2
    "203.0.113.",   # TEST-NET-3
    "127.0.0.1",    # Localhost
    "0.0.0.0",      # Bind all
)

KNOWN_PLACEHOLDER_SUBSTRINGS = [
    "AKIAIOSFODNN7EXAMPLE",
    "EXAMPLE",
    "DUMMY",
    "PLACEHOLDER",
    "YOUR_API_KEY",
    "YOUR_SECRET",
    "CHANGE_ME",
    "TEST_KEY",
    "FAKE",
]

SECRET_RULES = [
    {
        "id": "SEC-AWS-KEY",
        "name": "AWS Access Key",
        "severity": "CRITICAL",
        "pattern": r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        "env_var_prefix": "AWS_ACCESS_KEY_ID",
    },
    {
        "id": "SEC-GITHUB-TOKEN",
        "name": "GitHub Access Token",
        "severity": "CRITICAL",
        "pattern": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|gho_[a-zA-Z0-9]{36})\b",
        "env_var_prefix": "GITHUB_TOKEN",
    },
    {
        "id": "SEC-OPENAI-KEY",
        "name": "OpenAI / Anthropic API Key",
        "severity": "CRITICAL",
        "pattern": r"\b(sk-[a-zA-Z0-9]{20,48}|sk-ant-api[a-zA-Z0-9_\-]{30,80})\b",
        "env_var_prefix": "AI_API_KEY",
    },
    {
        "id": "SEC-STRIPE-KEY",
        "name": "Stripe Live Secret Key",
        "severity": "CRITICAL",
        "pattern": r"\b[sr]k_live_[0-9a-zA-Z]{24,99}\b",
        "env_var_prefix": "STRIPE_SECRET_KEY",
    },
    {
        "id": "SEC-PRIVATE-KEY",
        "name": "Private Cryptographic Key",
        "severity": "CRITICAL",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "env_var_prefix": "PRIVATE_KEY",
    },
    {
        "id": "SEC-JWT-TOKEN",
        "name": "JSON Web Token (JWT)",
        "severity": "HIGH",
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{20,}\b",
        "env_var_prefix": "AUTH_JWT_TOKEN",
    },
    {
        "id": "SEC-DB-URI",
        "name": "Database URI with Credentials",
        "severity": "CRITICAL",
        "pattern": r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_.-]+:[^@\s\"']+@[a-zA-Z0-9_.-]+:\d+/[a-zA-Z0-9_.-]+",
        "env_var_prefix": "DATABASE_URL",
    },
    {
        "id": "SEC-INTERNAL-IP",
        "name": "Private/Internal IP Address",
        "severity": "MEDIUM",
        "pattern": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "env_var_prefix": "INTERNAL_HOST_IP",
    },
    {
        "id": "PRV-AI-PROVENANCE",
        "name": "AI Agent Fingerprint / Attribution Leak",
        "severity": "CRITICAL",
        "pattern": r"(?i)(generated|written|created|assisted|produced)\s+(by|with|using)\s+(claude|chatgpt|openai|copilot|github\s+copilot|cursor|antigravity|gemini|aider|devin|cline|roo[_-]code|windsurf|codex|v0\.dev|deepseek|anthropic|llm|ai\s+agent)",
        "env_var_prefix": "AGENT_PROVENANCE_VIOLATION",
    },
    {
        "id": "PRV-AI-COAUTHOR",
        "name": "AI Co-Author / Contributor Tag",
        "severity": "CRITICAL",
        "pattern": r"(?i)co-authored-by:\s*.*(claude|chatgpt|copilot|cursor|antigravity|gemini|aider|devin|cline|bot@|ai@|noreply@anthropic|noreply@openai|noreply@google)",
        "env_var_prefix": "AGENT_COAUTHOR_VIOLATION",
    },
]

SENSITIVE_COMMENT_PATTERNS = [
    (r"(?i)\b(bypass|backdoor|hardcoded\s+password|master\s+password)\b", "Exposes security bypass or hardcoded credentials"),
    (r"(?i)\bTODO:?\s*(fix\s+security\s+vulnerability|patch\s+exploit|remove\s+secret)\b", "Flags unpatched security vulnerability in comments"),
    (r"(?i)(prompted\s+by|written\s+with\s+(claude|cursor|chatgpt|copilot|gemini|antigravity))", "Leaking AI model identity in source comments allows attackers to exploit model-specific architectural weaknesses"),
]


def calculate_entropy(data: str) -> float:
    """Calculates Shannon entropy of string data."""
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


def is_placeholder(val: str) -> bool:
    """Checks if secret match is an innocuous documentation dummy or test placeholder."""
    val_upper = val.upper()
    return any(p in val_upper for p in KNOWN_PLACEHOLDER_SUBSTRINGS)


ALLOWED_ENV_TEMPLATES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
}

def is_forbidden_file(filename: str) -> bool:
    """Checks if filename matches strictly forbidden file patterns."""
    basename = os.path.basename(filename)
    if basename.lower() in ALLOWED_ENV_TEMPLATES:
        return False
    for pat in FORBIDDEN_FILE_PATTERNS:
        if re.search(pat, basename, re.IGNORECASE):
            return True
    return False


class PushSanitizer:
    def __init__(self, workspace_root: Optional[Path] = None, policy: Optional[Dict[str, Any]] = None):
        self.workspace_root = (workspace_root or ROOT_DIR).resolve()
        self.policy = policy or load_policy()
        vault_sub = self.policy.get("general", {}).get("vault_dir", ".skillguard/vault")
        self.vault_dir = (self.workspace_root / vault_sub).resolve()

    def ensure_gitignore_protection(self):
        """Ensures .env and .skillguard/vault/ are safely added to .gitignore."""
        gitignore_path = self.workspace_root / ".gitignore"
        required_entries = [".env", ".env.*", ".skillguard/vault/", "*.pem", "*.key"]
        existing = ""
        if gitignore_path.is_file():
            existing = gitignore_path.read_text(encoding="utf-8")

        missing = []
        for entry in required_entries:
            if entry not in existing:
                missing.append(entry)

        if missing:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n# SkillGuard Security Guards\n")
                for entry in missing:
                    f.write(f"{entry}\n")

    def inspect_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scans a single file for secret patterns, forbidden types, and sensitive comments."""
        findings = []
        rel_path = str(file_path.relative_to(self.workspace_root)).replace("\\", "/")

        # 1. Check forbidden file pattern
        if is_forbidden_file(file_path.name):
            findings.append({
                "id": "SEC-FORBIDDEN-FILE",
                "name": "Forbidden Sensitive File",
                "severity": "CRITICAL",
                "file": rel_path,
                "line": 0,
                "secret_value": "",
                "evidence": f"File '{file_path.name}' must never be committed to source control.",
                "why_dangerous": "Direct repository leak of secret keys, database dumps, or state files.",
                "remediation": f"Add '{file_path.name}' to .gitignore immediately and remove from staged changes.",
            })
            return findings

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # Check for inline ignore
            if "# skillguard: ignore" in line:
                continue

            # 2. Check secret patterns
            for rule in SECRET_RULES:
                for match in re.finditer(rule["pattern"], line):
                    secret_val = match.group(0)
                    if is_placeholder(secret_val):
                        continue
                    if rule["id"] == "SEC-INTERNAL-IP":
                        if any(secret_val.startswith(pfx) for pfx in EXEMPT_IP_PREFIXES):
                            continue

                    findings.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "file": rel_path,
                        "line": line_no,
                        "secret_value": secret_val,
                        "evidence": line.strip(),
                        "env_var_prefix": rule.get("env_var_prefix", "SECRET_KEY"),
                        "why_dangerous": f"Exposes live {rule['name']} in plain text.",
                        "remediation": f"Replace with environment variable and register in .env",
                    })

            # 3. High entropy assignment check: var = "..."
            entropy_assign = re.search(r'''\b(key|secret|token|password|auth|apikey|api_key)\s*[:=]\s*["']([^"'\s]{20,})["']''', line, re.IGNORECASE)
            if entropy_assign:
                var_name = entropy_assign.group(1)
                secret_str = entropy_assign.group(2)
                if not is_placeholder(secret_str) and calculate_entropy(secret_str) > 4.4:
                    if not any(f["line"] == line_no for f in findings):
                        findings.append({
                            "id": "SEC-HIGH-ENTROPY-TOKEN",
                            "name": "High Entropy Hardcoded Secret Assignment",
                            "severity": "CRITICAL",
                            "file": rel_path,
                            "line": line_no,
                            "secret_value": secret_str,
                            "evidence": line.strip(),
                            "env_var_prefix": var_name.upper(),
                            "why_dangerous": f"Hardcoded credential assigned to variable '{var_name}'.",
                            "remediation": f"Extract to environment variable {var_name.upper()}.",
                        })

            # 4. Sensitive comments check
            for pat, why_dang in SENSITIVE_COMMENT_PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "id": "SEC-SENSITIVE-COMMENT",
                        "name": "Security-Sensitive Code Comment",
                        "severity": "MEDIUM",
                        "file": rel_path,
                        "line": line_no,
                        "secret_value": "",
                        "evidence": line.strip(),
                        "why_dangerous": why_dang,
                        "remediation": "Generalize comments; do not expose internal bypasses or vulnerability details.",
                    })

        return findings

    def inspect_git_metadata(self) -> List[Dict[str, Any]]:
        """Inspects current branch name and recent commit message for AI agent provenance leaks."""
        findings = []
        try:
            # Check branch name
            res_br = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                check=False
            )
            if res_br.returncode == 0:
                branch = res_br.stdout.strip()
                agent_br_match = re.match(r"(?i)^(claude|devin|cursor|gemini|antigravity|copilot|cline|aider)/", branch)
                if agent_br_match:
                    findings.append({
                        "id": "PRV-AI-BRANCH",
                        "name": "AI Agent Provenance in Branch Name",
                        "severity": "CRITICAL",
                        "file": "git/branch",
                        "line": 0,
                        "secret_value": "",
                        "evidence": f"Branch name '{branch}' reveals AI tooling.",
                        "why_dangerous": "Reveals the specific AI agent to remote repository observers, enabling targeted attacks against known model weaknesses.",
                        "remediation": f"Rename branch to standard semantic naming (e.g. git branch -m {branch} feature/logic).",
                    })

            # Check recent commit message
            res_log = subprocess.run(
                ["git", "log", "-1", "--pretty=%B"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                check=False
            )
            if res_log.returncode == 0:
                commit_msg = res_log.stdout.strip()
                for line in commit_msg.splitlines():
                    if re.search(r"(?i)(co-authored-by:\s*.*(claude|chatgpt|copilot|cursor|antigravity|gemini|aider|devin|cline|bot@|ai@)|generated\s+by\s+(claude|cursor|gemini|copilot|chatgpt))", line):
                        findings.append({
                            "id": "PRV-AI-COMMIT-MSG",
                            "name": "AI Agent Provenance in Commit Message",
                            "severity": "CRITICAL",
                            "file": "git/commit",
                            "line": 0,
                            "secret_value": "",
                            "evidence": line.strip(),
                            "why_dangerous": "Exposes that the codebase was generated by a specific AI model, exposing known model biases and blind spots.",
                            "remediation": "Amend commit message to strip AI agent mentions: git commit --amend",
                        })
        except Exception:
            pass
        return findings

    def get_staged_files(self) -> List[Path]:
        """Gets all files currently staged in git index."""
        try:
            res = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                check=False
            )
            if res.returncode == 0:
                files = []
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line:
                        p = self.workspace_root / line
                        if p.is_file():
                            files.append(p)
                return files
        except Exception:
            pass
        return []

    def sanitize_file(self, file_path: Path, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Replaces secret values with environment variable references in code,
        backs up original content to vault, and appends to .env.example.
        """
        rel_path = str(file_path.relative_to(self.workspace_root)).replace("\\", "/")
        original_content = file_path.read_text(encoding="utf-8")
        sanitized_content = original_content
        ext = file_path.suffix.lower()

        timestamp = int(time.time())
        vault_record_dir = self.vault_dir / f"vault_{timestamp}"
        vault_record_dir.mkdir(parents=True, exist_ok=True)

        backup_file = vault_record_dir / file_path.name
        backup_file.write_text(original_content, encoding="utf-8")

        replacements = []
        env_example_entries = []

        counter = 1
        for f in findings:
            secret_val = f.get("secret_value")
            if not secret_val or secret_val not in sanitized_content:
                continue

            env_name = f"{f.get('env_var_prefix', 'SECRET')}_{counter}" if counter > 1 else f.get('env_var_prefix', 'SECRET')
            counter += 1

            # Format replacement syntax depending on file extension
            if ext == ".py":
                replacement_code = f'os.environ.get("{env_name}", "")'
                # Check if os is imported
                if "import os" not in sanitized_content:
                    sanitized_content = "import os\n" + sanitized_content
            elif ext in [".js", ".jsx", ".ts", ".tsx"]:
                replacement_code = f'process.env.{env_name}'
            elif ext == ".php":
                replacement_code = f"getenv('{env_name}')"
            else:
                replacement_code = f"${{{env_name}}}"

            # Replace secret inside quotes if possible
            quoted_match = re.search(rf'["\']{re.escape(secret_val)}["\']', sanitized_content)
            if quoted_match:
                sanitized_content = sanitized_content.replace(quoted_match.group(0), replacement_code, 1)
            else:
                sanitized_content = sanitized_content.replace(secret_val, replacement_code, 1)

            replacements.append({
                "secret": secret_val,
                "replacement": replacement_code,
                "env_name": env_name
            })
            env_example_entries.append(f"{env_name}=your_{env_name.lower()}_here")

        # Write sanitized content back to file
        file_path.write_text(sanitized_content, encoding="utf-8")

        # Update .env.example
        env_example_path = self.workspace_root / self.policy.get("sanitization", {}).get("env_example_path", ".env.example")
        if env_example_entries:
            with open(env_example_path, "a", encoding="utf-8") as f:
                f.write("\n# SkillGuard Auto-Generated Secrets Placeholders\n")
                for entry in env_example_entries:
                    f.write(f"{entry}\n")

        # Ensure .gitignore has vault & .env
        self.ensure_gitignore_protection()

        # Compute diff
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            sanitized_content.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}"
        ))
        diff_str = "".join(diff_lines)

        meta = {
            "timestamp": timestamp,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "target_file": str(file_path),
            "rel_path": rel_path,
            "backup_file": str(backup_file),
            "replacements": replacements,
            "diff": diff_str,
        }
        (vault_record_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        # Update latest pointer
        (self.vault_dir / "latest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return meta

    def undo_last_sanitization(self) -> Tuple[bool, str]:
        """Restores original file from the latest vault snapshot."""
        latest_ptr = self.vault_dir / "latest.json"
        if not latest_ptr.is_file():
            return False, "No vault snapshot found to undo."

        try:
            meta = json.loads(latest_ptr.read_text(encoding="utf-8"))
            target_path = Path(meta["target_file"])
            backup_path = Path(meta["backup_file"])
            if not backup_path.is_file():
                return False, f"Backup file '{backup_path}' does not exist."

            shutil.copy2(backup_path, target_path)
            latest_ptr.unlink(missing_ok=True)
            return True, f"Successfully restored '{meta['rel_path']}' from vault backup."
        except Exception as e:
            return False, f"Failed to undo sanitization: {e}"


def run_push_check(
    workspace_root: Optional[Path] = None,
    staged_only: bool = False,
    auto_sanitize: bool = False,
    single_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Coordinates scan across target files, produces findings, and performs sanitization if commanded."""
    sanitizer = PushSanitizer(workspace_root=workspace_root)
    root = sanitizer.workspace_root

    files_to_scan = []
    if single_file:
        files_to_scan = [single_file]
    elif staged_only:
        files_to_scan = sanitizer.get_staged_files()
    else:
        # Scan entire workspace except .git, node_modules, .skillguard, fixtures
        for r, dirs, fnames in os.walk(root):
            for skip in [".git", "node_modules", ".skillguard", "__pycache__", "venv", ".venv", "fixtures"]:
                if skip in dirs:
                    dirs.remove(skip)
            for fname in fnames:
                files_to_scan.append(Path(r) / fname)

    all_findings = []
    sanitized_records = []

    for fpath in files_to_scan:
        findings = sanitizer.inspect_file(fpath)
        if findings:
            all_findings.extend(findings)
            # Perform automatic code sanitization if requested and file is not a forbidden standalone file
            if auto_sanitize and not is_forbidden_file(fpath.name):
                replaceable = [f for f in findings if f.get("secret_value")]
                if replaceable:
                    meta = sanitizer.sanitize_file(fpath, replaceable)
                    sanitized_records.append(meta)

    # Check git metadata (branch name & commit message) for AI provenance leaks
    git_findings = sanitizer.inspect_git_metadata()
    if git_findings:
        all_findings.extend(git_findings)

    # Determine verdict
    has_critical = any(f["severity"] == "CRITICAL" for f in all_findings)
    has_forbidden = any(f["id"] == "SEC-FORBIDDEN-FILE" for f in all_findings)

    # If all secrets were automatically sanitized and no forbidden files exist, push may proceed
    if has_forbidden:
        verdict = "BLOCK_PUSH"
    elif has_critical and not auto_sanitize:
        verdict = "BLOCK_PUSH"
    elif has_critical and auto_sanitize and len(sanitized_records) > 0:
        verdict = "SANITIZED_PROCEED_WITH_WARNING"
    elif all_findings:
        verdict = "WARN"
    else:
        verdict = "CLEAN"

    # Rotation Warning
    rotation_notice = ""
    if has_critical:
        rotation_notice = (
            "\n" + "=" * 70 + "\n"
            "🚨 CRITICAL SECURITY ROTATION WARNING:\n"
            "If any of these secrets were previously committed or pushed to a remote git branch,\n"
            "sanitizing the code DOES NOT protect you! The secret must be IMMEDIATELY REVOKED/ROTATED\n"
            "at the service provider (AWS, GitHub, Stripe, OpenAI, etc.).\n"
            "To purge secrets permanently from git history, use: git filter-repo or BFG Repo-Cleaner.\n" +
            "=" * 70 + "\n"
        )

    return {
        "verdict": verdict,
        "scanned_files_count": len(files_to_scan),
        "findings_count": len(all_findings),
        "findings": all_findings,
        "sanitized_records": sanitized_records,
        "rotation_notice": rotation_notice,
    }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="SkillGuard Pre-Commit/Push Sanitizer")
    parser.add_argument("--staged", action="store_true", help="Inspect only staged git changes (for pre-commit/pre-push)")
    parser.add_argument("--auto-sanitize", action="store_true", help="Automatically replace secrets with env variables and backup to vault")
    parser.add_argument("--undo", action="store_true", help="Undo last sanitization and restore from vault")
    parser.add_argument("--file", type=str, help="Scan a specific file")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    sanitizer = PushSanitizer()

    if args.undo:
        ok, msg = sanitizer.undo_last_sanitization()
        print(msg)
        sys.exit(0 if ok else 1)

    target_file = Path(args.file).resolve() if args.file else None
    result = run_push_check(
        staged_only=args.staged,
        auto_sanitize=args.auto_sanitize,
        single_file=target_file,
    )

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if result["findings_count"] == 0:
            print("🛡️ SkillGuard Push Check: Clean. No leaked secrets or forbidden files found.")
        else:
            print(f"🛡️ SkillGuard Push Check: Found {result['findings_count']} potential secret/security finding(s):")
            for f in result["findings"]:
                print(f"  [{f['severity']}] {f['name']} ({f['file']}:{f['line']})")
                print(f"    Evidence: {f['evidence']}")

            if result["rotation_notice"]:
                print(result["rotation_notice"])

            if result["sanitized_records"]:
                print(f"\n✅ Automatically sanitized {len(result['sanitized_records'])} file(s).")
                print(f"Original content backed up to .skillguard/vault/. Run with --undo to revert.")

        print(f"\nFinal Verdict: {result['verdict']}")

    if result["verdict"] == "BLOCK_PUSH":
        sys.exit(2)
    elif result["verdict"] in ["WARN", "SANITIZED_PROCEED_WITH_WARNING"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
