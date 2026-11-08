"""
SkillGuard Module 2: Hash Lock, Rug-Pull Detection & Quarantine
Manages skillguard.lock with cryptographic chaining, verifies file integrity,
detects post-approval modifications (rug-pulls), and manages quarantine isolation.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy


def hash_file(file_path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_skill_fingerprint(skill_dir: Path) -> Dict[str, str]:
    """Computes individual SHA-256 hashes for all files in a skill directory."""
    skill_dir = skill_dir.resolve()
    file_hashes: Dict[str, str] = {}
    for root, dirs, files in os.walk(skill_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        for file in sorted(files):
            # Ignore lockfile or temporary files
            if file in [".SKILLGUARD_BLOCKED", "skillguard.lock"]:
                continue
            f_path = Path(root) / file
            rel = str(f_path.relative_to(skill_dir)).replace("\\", "/")
            file_hashes[rel] = hash_file(f_path)
    return file_hashes


def compute_composite_hash(file_hashes: Dict[str, str]) -> str:
    """Computes a composite hash of all file hashes."""
    hasher = hashlib.sha256()
    for rel_path in sorted(file_hashes.keys()):
        hasher.update(f"{rel_path}:{file_hashes[rel_path]}".encode("utf-8"))
    return hasher.hexdigest()


class SkillLockManager:
    def __init__(self, lock_path: Optional[Path] = None, policy: Optional[Dict[str, Any]] = None):
        self.policy = policy or load_policy()
        lock_file_name = self.policy.get("general", {}).get("lockfile_path", "skillguard.lock")
        self.lock_path = (lock_path or (ROOT_DIR / lock_file_name)).resolve()

        quarantine_dir_str = self.policy.get("general", {}).get("quarantine_dir", "~/.skillguard/quarantine")
        self.quarantine_root = Path(os.path.expanduser(quarantine_dir_str)).resolve()

        audit_log_str = self.policy.get("general", {}).get("audit_log_path", "~/.skillguard/audit.log")
        self.audit_log_path = Path(os.path.expanduser(audit_log_str)).resolve()

    def _read_lock(self) -> Dict[str, Any]:
        if not self.lock_path.is_file():
            return {
                "version": "1.0.0",
                "last_chain_hash": "GENESIS_0000000000000000000000000000000000000000000000000000000000000000",
                "skills": {}
            }
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "version": "1.0.0",
                "last_chain_hash": "CORRUPTED_RESET",
                "skills": {}
            }

    def _write_lock(self, data: Dict[str, Any]):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def log_audit(self, action: str, skill_name: str, details: Dict[str, Any]):
        """Appends tamper-evident chained audit log entry."""
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": now,
            "action": action,
            "skill": skill_name,
            "details": details,
        }
        entry_str = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash

        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def lock_skill(self, skill_name: str, skill_dir: Path, capabilities: Optional[List[str]] = None) -> Dict[str, Any]:
        """Locks a verified skill with SHA-256 chained record."""
        skill_dir = Path(skill_dir).resolve()
        file_hashes = compute_skill_fingerprint(skill_dir)
        composite = compute_composite_hash(file_hashes)

        data = self._read_lock()
        prev_chain_hash = data.get("last_chain_hash", "GENESIS")

        # Compute new chained hash
        new_chain_hasher = hashlib.sha256()
        new_chain_hasher.update(f"{prev_chain_hash}:{skill_name}:{composite}".encode("utf-8"))
        new_chain_hash = new_chain_hasher.hexdigest()

        lock_record = {
            "skill_name": skill_name,
            "path": str(skill_dir),
            "composite_hash": composite,
            "files": file_hashes,
            "capabilities": capabilities or ["read_project"],
            "locked_at": datetime.now(timezone.utc).isoformat(),
            "prev_chain_hash": prev_chain_hash,
            "chain_hash": new_chain_hash,
        }

        data["skills"][skill_name] = lock_record
        data["last_chain_hash"] = new_chain_hash
        self._write_lock(data)

        self.log_audit("SKILL_LOCKED", skill_name, {"composite_hash": composite, "files_count": len(file_hashes)})
        return lock_record

    def verify_skill(self, skill_name: str, skill_dir: Path) -> Tuple[bool, str, List[str]]:
        """
        Verifies a skill against skillguard.lock.
        Detects unauthorized modifications (Rug-Pull attacks).
        Returns: (is_valid, status, modified_or_new_files)
        """
        skill_dir = Path(skill_dir).resolve()
        data = self._read_lock()
        skills = data.get("skills", {})

        if skill_name not in skills:
            return False, "UNREGISTERED_SKILL", []

        record = skills[skill_name]
        expected_files = record.get("files", {})
        current_files = compute_skill_fingerprint(skill_dir)

        changed_files = []
        # Check for modified or deleted files
        for fpath, exp_hash in expected_files.items():
            if fpath not in current_files:
                changed_files.append(f"DELETED: {fpath}")
            elif current_files[fpath] != exp_hash:
                changed_files.append(f"MODIFIED: {fpath}")

        # Check for newly added files
        for fpath in current_files:
            if fpath not in expected_files:
                changed_files.append(f"ADDED: {fpath}")

        if changed_files:
            self.log_audit("RUG_PULL_DETECTED", skill_name, {"changed_files": changed_files})
            return False, "RUG_PULL_DETECTED", changed_files

        return True, "VERIFIED", []

    def quarantine_skill(self, skill_name: str, skill_dir: Path, reason: str) -> Path:
        """
        Quarantines a malicious/blocked skill into ~/.skillguard/quarantine/
        Leaves a .SKILLGUARD_BLOCKED marker file in its place.
        """
        skill_dir = Path(skill_dir).resolve()
        timestamp = int(time.time())
        dest_folder = self.quarantine_root / f"{skill_name}_{timestamp}"
        dest_folder.parent.mkdir(parents=True, exist_ok=True)

        # Copy skill to quarantine
        shutil.copytree(skill_dir, dest_folder)

        # Compute fingerprint before deleting
        file_hashes = compute_skill_fingerprint(skill_dir)
        composite = compute_composite_hash(file_hashes)

        # Clear files in original dir and write marker
        for item in skill_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

        marker_file = skill_dir / ".SKILLGUARD_BLOCKED"
        marker_data = {
            "skill_name": skill_name,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "quarantine_location": str(dest_folder),
            "original_composite_hash": composite,
            "instructions": (
                "DO NOT LOAD OR EXECUTE THIS SKILL. It has been blocked and quarantined by SkillGuard. "
                "To inspect, view the quarantine directory. To restore (if safe), run: skillguard unquarantine"
            )
        }
        with open(marker_file, "w", encoding="utf-8") as f:
            json.dump(marker_data, f, indent=2, ensure_ascii=False)

        self.log_audit("SKILL_QUARANTINED", skill_name, {
            "reason": reason,
            "quarantine_location": str(dest_folder),
            "composite_hash": composite
        })
        return dest_folder

    def unquarantine_skill(self, skill_name: str, target_dir: Path) -> bool:
        """Restores the most recent quarantined backup of a skill."""
        target_dir = Path(target_dir).resolve()
        matching_dirs = sorted(self.quarantine_root.glob(f"{skill_name}_*"), reverse=True)
        if not matching_dirs:
            return False

        latest_backup = matching_dirs[0]
        # Remove blocked marker and existing content
        for item in target_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

        # Copy back from quarantine
        for item in latest_backup.iterdir():
            if item.is_dir():
                shutil.copytree(item, target_dir / item.name)
            else:
                shutil.copy2(item, target_dir / item.name)

        self.log_audit("SKILL_UNQUARANTINED", skill_name, {"restored_from": str(latest_backup)})
        return True


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="SkillGuard Skill Lock & Quarantine Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # lock command
    lock_cmd = subparsers.add_parser("lock", help="Lock and verify a skill in skillguard.lock")
    lock_cmd.add_argument("name", help="Name of the skill")
    lock_cmd.add_argument("path", help="Path to the skill directory")

    # verify command
    ver_cmd = subparsers.add_parser("verify", help="Verify skill integrity against skillguard.lock")
    ver_cmd.add_argument("name", help="Name of the skill")
    ver_cmd.add_argument("path", help="Path to the skill directory")

    # quarantine command
    q_cmd = subparsers.add_parser("quarantine", help="Quarantine a skill")
    q_cmd.add_argument("name", help="Name of the skill")
    q_cmd.add_argument("path", help="Path to the skill directory")
    q_cmd.add_argument("--reason", default="Critical security finding", help="Reason for quarantine")

    # unquarantine command
    unq_cmd = subparsers.add_parser("unquarantine", help="Restore skill from quarantine")
    unq_cmd.add_argument("name", help="Name of the skill")
    unq_cmd.add_argument("path", help="Path to restore into")

    args = parser.parse_args()
    mgr = SkillLockManager()

    if args.command == "lock":
        rec = mgr.lock_skill(args.name, Path(args.path))
        print(f"Locked '{args.name}' with composite SHA-256: {rec['composite_hash']}")
    elif args.command == "verify":
        valid, status, changes = mgr.verify_skill(args.name, Path(args.path))
        if valid:
            print(f"PASSED: '{args.name}' matches lockfile.")
            sys.exit(0)
        else:
            print(f"FAILED: '{args.name}' status: {status}")
            for c in changes:
                print(f"  - {c}")
            sys.exit(1)
    elif args.command == "quarantine":
        dest = mgr.quarantine_skill(args.name, Path(args.path), args.reason)
        print(f"Quarantined '{args.name}' to: {dest}")
    elif args.command == "unquarantine":
        ok = mgr.unquarantine_skill(args.name, Path(args.path))
        if ok:
            print(f"Restored '{args.name}' into {args.path}")
        else:
            print(f"No quarantine record found for '{args.name}'")
            sys.exit(1)


if __name__ == "__main__":
    main()
