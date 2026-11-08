"""
SkillGuard Module 5: Tech Stack & Dependency CVE Audit (stack_audit.py)
Inspects ecosystem manifests (package.json, requirements.txt, composer.json, Cargo.toml, go.mod),
queries OSV.dev API (strictly package name & version, zero user code transmitted),
supports offline local caching (~/.skillguard/cache/osv_cache.json), and enforces security upgrades.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy, load_network_allowlist

OSV_API_ENDPOINT = "https://api.osv.dev/v1/query"


def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Extracts package names and versions from requirements.txt."""
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Split on ==, >=, <=, ~=, <, >
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=|<|>)\s*([a-zA-Z0-9_.-]+)", line)
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
        else:
            name_m = re.match(r"^([a-zA-Z0-9_.-]+)", line)
            if name_m:
                pkgs.append({"name": name_m.group(1), "version": "0.0.0", "ecosystem": "PyPI"})
    return pkgs


def parse_package_json(content: str) -> List[Dict[str, str]]:
    """Extracts package dependencies and versions from package.json."""
    pkgs = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        for name, ver in all_deps.items():
            clean_ver = re.sub(r"[^0-9.]", "", ver)
            pkgs.append({"name": name, "version": clean_ver or "0.0.0", "ecosystem": "npm"})
    except Exception:
        pass
    return pkgs


def parse_composer_json(content: str) -> List[Dict[str, str]]:
    """Extracts PHP dependencies from composer.json."""
    pkgs = []
    try:
        data = json.loads(content)
        deps = data.get("require", {})
        for name, ver in deps.items():
            if name.lower() == "php" or "/" not in name:
                continue
            clean_ver = re.sub(r"[^0-9.]", "", ver)
            pkgs.append({"name": name, "version": clean_ver or "0.0.0", "ecosystem": "Packagist"})
    except Exception:
        pass
    return pkgs


def parse_cargo_toml(content: str) -> List[Dict[str, str]]:
    """Extracts Rust dependencies from Cargo.toml."""
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[dependencies]") or line.startswith("[dev-dependencies]"):
            in_deps = True
            continue
        elif line.startswith("["):
            in_deps = False
            continue

        if in_deps and "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            pkg_name = k.strip()
            v = v.strip().strip('"\'')
            clean_ver = re.sub(r"[^0-9.]", "", v)
            pkgs.append({"name": pkg_name, "version": clean_ver or "0.0.0", "ecosystem": "crates.io"})
    return pkgs


def parse_go_mod(content: str) -> List[Dict[str, str]]:
    """Extracts Go dependencies from go.mod."""
    pkgs = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        elif in_require and line == ")":
            in_require = False
            continue

        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                name = parts[0]
                ver = parts[1].lstrip("v")
                pkgs.append({"name": name, "version": ver, "ecosystem": "Go"})
    return pkgs


class StackAuditor:
    def __init__(self, workspace_root: Optional[Path] = None, policy: Optional[Dict[str, Any]] = None, offline: bool = False):
        self.workspace_root = (workspace_root or ROOT_DIR).resolve()
        self.policy = policy or load_policy()
        self.allowlist = load_network_allowlist()
        self.offline = offline

        cache_dir = Path(os.path.expanduser("~/.skillguard/cache")).resolve()
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = cache_dir / "osv_cache.json"

    def _load_cache(self) -> Dict[str, Any]:
        if not self.cache_file.is_file():
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_cache(self, cache_data: Dict[str, Any]):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def detect_manifests(self) -> List[Dict[str, str]]:
        """Finds dependencies declared in manifests throughout the repository."""
        packages = []
        for root, dirs, files in os.walk(self.workspace_root):
            for skip in [".git", "node_modules", ".skillguard", "venv", ".venv"]:
                if skip in dirs:
                    dirs.remove(skip)
            for file in files:
                fpath = Path(root) / file
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    if file == "requirements.txt":
                        packages.extend(parse_requirements_txt(content))
                    elif file == "package.json":
                        packages.extend(parse_package_json(content))
                    elif file == "composer.json":
                        packages.extend(parse_composer_json(content))
                    elif file == "Cargo.toml":
                        packages.extend(parse_cargo_toml(content))
                    elif file == "go.mod":
                        packages.extend(parse_go_mod(content))
                except Exception:
                    continue

        # Deduplicate
        seen = set()
        deduped = []
        for p in packages:
            key = (p["ecosystem"], p["name"], p["version"])
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped

    def query_osv(self, pkg: Dict[str, str]) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Queries OSV.dev for known vulnerabilities.
        Falls back cleanly to local offline cache if network is unavailable or domain is not allowlisted.
        Returns: (vulnerabilities, is_offline_cache_used)
        """
        cache_key = f"{pkg['ecosystem']}:{pkg['name']}:{pkg['version']}"
        cache = self._load_cache()

        if self.offline:
            cached_item = cache.get(cache_key)
            return (cached_item or []), True

        # Check domain allowlist
        parsed_url = urllib.parse.urlparse(OSV_API_ENDPOINT)
        if parsed_url.hostname not in self.allowlist:
            cached_item = cache.get(cache_key)
            return (cached_item or []), True

        req_payload = {
            "package": {
                "name": pkg["name"],
                "ecosystem": pkg["ecosystem"],
            }
        }
        if pkg["version"] and pkg["version"] != "0.0.0":
            req_payload["version"] = pkg["version"]

        try:
            req_data = json.dumps(req_payload).encode("utf-8")
            req = urllib.request.Request(
                OSV_API_ENDPOINT,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "SkillGuard-StackAudit/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                    vulns = resp_json.get("vulns", [])
                    # Update local cache
                    cache[cache_key] = vulns
                    self._save_cache(cache)
                    return vulns, False
        except Exception:
            pass

        # Offline fallback
        cached_item = cache.get(cache_key)
        if cached_item is not None:
            return cached_item, True

        return [], True

    def audit_package(self, pkg: Dict[str, str]) -> List[Dict[str, Any]]:
        """Audits a single package and extracts formatted vulnerability records."""
        vulns, is_offline = self.query_osv(pkg)
        findings = []

        for v in vulns:
            vuln_id = v.get("id", "UNKNOWN-CVE")
            summary = v.get("summary", v.get("details", "Known security vulnerability"))
            if len(summary) > 180:
                summary = summary[:177] + "..."

            # Find patched versions
            fixed_versions = []
            for affected in v.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

            fix_advice = f"Upgrade '{pkg['name']}' to version {', '.join(fixed_versions)}" if fixed_versions else f"Review advisories or replace {pkg['name']}"

            # Determine severity
            severity = "HIGH"
            aliases = v.get("aliases", [])
            for alias in aliases:
                if "KEV" in alias or "CRITICAL" in summary.upper():
                    severity = "CRITICAL"

            findings.append({
                "id": "STACK-CVE-DETECTED",
                "cve_id": vuln_id,
                "package": pkg["name"],
                "installed_version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "severity": severity,
                "summary": summary,
                "remediation": fix_advice,
                "is_offline_cache": is_offline,
                "aliases": aliases,
            })
        return findings

    def run_audit(self) -> Dict[str, Any]:
        """Runs the complete tech stack audit."""
        packages = self.detect_manifests()
        all_findings = []
        used_offline_cache = False

        for pkg in packages:
            pkg_findings = self.audit_package(pkg)
            if any(f.get("is_offline_cache") for f in pkg_findings):
                used_offline_cache = True
            all_findings.extend(pkg_findings)

        has_critical = any(f["severity"] == "CRITICAL" for f in all_findings)
        has_high = any(f["severity"] == "HIGH" for f in all_findings)

        if has_critical:
            verdict = "BLOCK_DEPLOY"
        elif has_high:
            verdict = "CONFIRM_UPGRADE"
        elif all_findings:
            verdict = "WARN"
        else:
            verdict = "ALLOW"

        return {
            "packages_found_count": len(packages),
            "packages": packages,
            "vulnerabilities_count": len(all_findings),
            "findings": all_findings,
            "verdict": verdict,
            "used_offline_cache": used_offline_cache,
        }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="SkillGuard Dependency & Stack CVE Auditor")
    parser.add_argument("--dir", default=".", help="Directory to audit")
    parser.add_argument("--offline", action="store_true", help="Audit strictly using local offline cache")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--lang", default="tr", choices=["tr", "en"], help="Output language (tr/en)")
    args = parser.parse_args()

    auditor = StackAuditor(workspace_root=Path(args.dir), offline=args.offline)
    report = auditor.run_audit()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        if args.lang == "tr":
            print("[SKILLGUARD] Teknoloji Yigini & CVE Denetimi")
            print(f"Tespit Edilen Bagimlilik Sayisi: {report['packages_found_count']}")
            if report["used_offline_cache"]:
                print("[WARN] Cevrimdisi onbellekten denetlendi (veri guncel olmayabilir).")
            print(f"Toplam Zafiyet: {report['vulnerabilities_count']} | Karar: {report['verdict']}\n")

            if report["findings"]:
                for f in report["findings"]:
                    print(f"  [{f['severity']}] {f['cve_id']} - {f['package']} (v{f['installed_version']})")
                    print(f"    Ozet: {f['summary']}")
                    print(f"    Onerilen Yama: {f['remediation']}\n")
            else:
                print("[OK] Bilinen kritik CVE veya guvenlik zafiyeti bulunamadi.")
        else:
            print("[SKILLGUARD] Tech Stack & Dependency CVE Audit")
            print(f"Packages Audited: {report['packages_found_count']}")
            if report["used_offline_cache"]:
                print("[WARN] Audited via offline local cache (data may be outdated).")
            print(f"Total Advisories: {report['vulnerabilities_count']} | Verdict: {report['verdict']}\n")

            if report["findings"]:
                for f in report["findings"]:
                    print(f"  [{f['severity']}] {f['cve_id']} - {f['package']} (v{f['installed_version']})")
                    print(f"    Summary: {f['summary']}")
                    print(f"    Remediation: {f['remediation']}\n")
            else:
                print("[OK] No known critical CVEs or dependency vulnerabilities found.")

    if report["verdict"] == "BLOCK_DEPLOY":
        sys.exit(2)
    elif report["verdict"] in ["CONFIRM_UPGRADE", "WARN"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
