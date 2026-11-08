"""
SkillGuard Installer: Git Hooks & Agent Lifecycle Hooks (install_hooks.py)
Configures git pre-commit / pre-push hooks and agent hooks.json.
Features non-destructive hook chaining, automatic backups, --dry-run, and --uninstall.
"""

import argparse
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy


GIT_PRE_COMMIT_SCRIPT = """#!/bin/sh
# --- SkillGuard Git Pre-Commit Hook ---
# Automatically scans staged files for leaked API keys, tokens, forbidden files, and AI agent provenance.

python scripts/sanitize_push.py --staged
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ SkillGuard: Staged commit blocked due to security violations."
    exit $EXIT_CODE
fi
"""

GIT_PRE_PUSH_SCRIPT = """#!/bin/sh
# --- SkillGuard Git Pre-Push Hook ---
# Performs database hygiene audit and verifies no critical vulnerabilities or secrets are pushed.

python scripts/sanitize_push.py --staged
SAN_EXIT=$?
if [ $SAN_EXIT -ne 0 ]; then
    echo "❌ SkillGuard: Push blocked due to unhandled secrets or forbidden files."
    exit $SAN_EXIT
fi

python scripts/db_guard.py
DB_EXIT=$?
if [ $DB_EXIT -eq 2 ]; then
    echo "❌ SkillGuard: Push blocked due to critical database security findings."
    exit $DB_EXIT
fi
"""


class HookInstaller:
    def __init__(self, workspace_root: Optional[Path] = None, dry_run: bool = False):
        self.workspace_root = (workspace_root or ROOT_DIR).resolve()
        self.dry_run = dry_run
        self.git_hooks_dir = self.workspace_root / ".git" / "hooks"
        self.agent_hooks_dir = self.workspace_root / ".agents"
        self.agent_hooks_file = self.agent_hooks_dir / "hooks.json"

    def install_git_hook(self, hook_name: str, script_content: str) -> str:
        """Installs or chains a git hook safely with backup."""
        if not (self.workspace_root / ".git").is_dir():
            return "SKIPPED: Not a git repository (no .git directory)."

        self.git_hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = self.git_hooks_dir / hook_name

        if hook_path.is_file():
            existing = hook_path.read_text(encoding="utf-8", errors="replace")
            if "SkillGuard" in existing:
                return f"ALREADY_INSTALLED: '{hook_name}' hook already configured."

            # Backup existing hook
            ts = int(time.time())
            backup_path = self.git_hooks_dir / f"{hook_name}.backup.{ts}"
            if not self.dry_run:
                shutil.copy2(hook_path, backup_path)

            # Chain: append SkillGuard invocation
            new_content = existing + "\n\n# --- Chained SkillGuard Hook ---\n" + script_content
            if not self.dry_run:
                hook_path.write_text(new_content, encoding="utf-8")
                # Make executable
                hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC)
            return f"CHAINED: Appended SkillGuard to '{hook_name}' (backed up original to {backup_path.name})."
        else:
            if not self.dry_run:
                hook_path.write_text(script_content, encoding="utf-8")
                hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC)
            return f"INSTALLED: Created new '{hook_name}' hook."

    def install_agent_hooks_json(self) -> str:
        """Configures or merges SkillGuard into .agents/hooks.json for Antigravity / Agent runtime."""
        skillguard_hook_config = {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "run_command|view_file|read_file",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/scan_skill.py --target .",
                            "timeout": 15
                        }
                    ]
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": "python scripts/prompt_guard.py --check-latest"
                }
            ]
        }

        if self.agent_hooks_file.is_file():
            try:
                data = json.loads(self.agent_hooks_file.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if "skillguard" in data:
                return "ALREADY_CONFIGURED: 'skillguard' hook already exists in .agents/hooks.json."
            data["skillguard"] = skillguard_hook_config
            if not self.dry_run:
                self.agent_hooks_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            return "MERGED: Added 'skillguard' hook block into existing .agents/hooks.json."
        else:
            data = {"skillguard": skillguard_hook_config}
            if not self.dry_run:
                self.agent_hooks_dir.mkdir(parents=True, exist_ok=True)
                self.agent_hooks_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            return "CREATED: Generated new .agents/hooks.json with SkillGuard lifecycle hooks."

    def uninstall_all(self) -> List[str]:
        """Removes SkillGuard git hooks and removes skillguard from .agents/hooks.json."""
        log = []
        # Git hooks
        for hname in ["pre-commit", "pre-push"]:
            hpath = self.git_hooks_dir / hname
            if hpath.is_file():
                content = hpath.read_text(encoding="utf-8", errors="replace")
                if "SkillGuard" in content:
                    # Look for backups
                    backups = sorted(self.git_hooks_dir.glob(f"{hname}.backup.*"), reverse=True)
                    if backups and not self.dry_run:
                        shutil.copy2(backups[0], hpath)
                        log.append(f"RESTORED: '{hname}' from latest backup '{backups[0].name}'.")
                    else:
                        if not self.dry_run:
                            hpath.unlink(missing_ok=True)
                        log.append(f"REMOVED: '{hname}' hook.")

        # Agent hooks.json
        if self.agent_hooks_file.is_file():
            try:
                data = json.loads(self.agent_hooks_file.read_text(encoding="utf-8"))
                if "skillguard" in data:
                    del data["skillguard"]
                    if not self.dry_run:
                        if data:
                            self.agent_hooks_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                        else:
                            self.agent_hooks_file.unlink()
                    log.append("REMOVED: 'skillguard' entry from .agents/hooks.json.")
            except Exception as e:
                log.append(f"ERROR: Could not parse .agents/hooks.json: {e}")

        return log

    def run_install(self) -> Dict[str, Any]:
        """Installs all supported hooks."""
        results = {}
        results["pre_commit"] = self.install_git_hook("pre-commit", GIT_PRE_COMMIT_SCRIPT)
        results["pre_push"] = self.install_git_hook("pre-push", GIT_PRE_PUSH_SCRIPT)
        results["agent_hooks"] = self.install_agent_hooks_json()
        return results


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="SkillGuard Hook Installer")
    parser.add_argument("--dry-run", action="store_true", help="Simulate installation without writing files")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall all SkillGuard git and agent hooks")
    parser.add_argument("--dir", default=".", help="Workspace root directory")
    args = parser.parse_args()

    installer = HookInstaller(workspace_root=Path(args.dir), dry_run=args.dry_run)

    if args.uninstall:
        print("🛡️ SkillGuard: Uninstalling hooks...")
        logs = installer.uninstall_all()
        for l in logs:
            print(f"  {l}")
        print("Done.")
        sys.exit(0)

    mode_label = "[DRY-RUN] " if args.dry_run else ""
    print(f"🛡️ SkillGuard: {mode_label}Installing lifecycle and git hooks...")
    res = installer.run_install()
    for k, v in res.items():
        print(f"  [{k}] {v}")

    print("\nSecurity Status:")
    print("  - Git Hooks: Deterministic blocking active for commits & pushes.")
    print("  - Agent Hooks: Configured for Antigravity / compatible agent runtimes.")


if __name__ == "__main__":
    main()
