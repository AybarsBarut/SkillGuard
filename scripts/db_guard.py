"""
SkillGuard Module 4: Database Security Guard (db_guard.py)
Inspects projects for database exposures, user data dumps, default credentials,
unprotected ports, destructive migrations, and SQL injection vulnerabilities.
Provides precise parameterized query remediations and least privilege guidance.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_loader import load_policy


# ==============================================================================
# PATTERNS & HEURISTICS
# ==============================================================================

WEAK_CREDENTIAL_PATTERNS = [
    (r"(?i)\b[a-zA-Z0-9_]*(password|passwd|pwd)\b\s*[:=]\s*[\"']?(root|admin|password|123456|postgres|test|qwerty)[\"']?\b", "Trivial default password"),
    (r"(?i)postgres:postgres@", "Default PostgreSQL superuser credentials"),
    (r"(?i)root:root@", "Default MySQL/MariaDB root credentials"),
    (r"(?i)admin:admin@", "Default admin credentials"),
    (r"(?i)sa:yourStrong(!)Password@", "Default MSSQL sa credentials"),
]

UNSAFE_PORTS = [
    (r"(?i)0\.0\.0\.0:5432", "PostgreSQL port 5432 exposed to all network interfaces (0.0.0.0)"),
    (r"(?i)0\.0\.0\.0:3306", "MySQL port 3306 exposed to all network interfaces (0.0.0.0)"),
    (r"(?i)0\.0\.0\.0:27017", "MongoDB port 27017 exposed to all network interfaces without binding to 127.0.0.1"),
    (r"(?i)0\.0\.0\.0:6379", "Redis port 6379 exposed to all network interfaces"),
]

INSECURE_TLS_FLAGS = [
    (r"(?i)sslmode\s*=\s*disable", "Database SSL/TLS encryption explicitly disabled (sslmode=disable)"),
    (r"(?i)rejectUnauthorized\s*:\s*false", "TLS certificate verification disabled (rejectUnauthorized: false)"),
    (r"(?i)allowPublicKeyRetrieval\s*=\s*true", "Insecure MySQL public key retrieval enabled without TLS"),
]

SQL_INJECTION_PATTERNS = [
    # Python: f-strings or % formatting in query execution
    {
        "lang": "python",
        "pattern": r"(?i)\b(execute|raw|select)\s*\(\s*f[\"'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{.+?\}.*?[\"']\s*\)",
        "name": "Python SQL Injection (f-string in query)",
        "why": "Unsanitized variables interpolated directly into SQL string allow SQL Injection.",
        "remediation": 'Use parameterized query: cursor.execute("SELECT ... WHERE col = %s", (var,))',
    },
    {
        "lang": "python",
        "pattern": r"(?i)\b(execute|raw)\s*\(\s*[\"'].*?(SELECT|INSERT|UPDATE|DELETE).*?%s.*?[\"']\s*%\s*\(?.+?\)?\s*\)",
        "name": "Python SQL Injection (% operator formatting)",
        "why": "Using Python % operator inside SQL string instead of driver parameterization.",
        "remediation": 'Pass parameters as a separate tuple: cursor.execute("SELECT ... WHERE col = %s", (var,))',
    },
    # PHP: String concatenation in query
    {
        "lang": "php",
        "pattern": r"(?i)(mysqli_query|->query|->exec)\s*\(\s*.*?(SELECT|INSERT|UPDATE|DELETE).*?\.\s*\$[a-zA-Z0-9_]+",
        "name": "PHP SQL Injection (String Concatenation)",
        "why": "Concatenating user variables directly into SQL queries allows attackers to execute arbitrary SQL commands.",
        "remediation": 'Use PDO prepared statements: $stmt = $pdo->prepare("SELECT ... WHERE id = :id"); $stmt->execute(["id" => $id]);',
    },
    # JavaScript / TypeScript: Template literals
    {
        "lang": "javascript",
        "pattern": r"(?i)\b(query|execute)\s*\(\s*`.*?(SELECT|INSERT|UPDATE|DELETE).*?\$\{.+?\}.*?`\s*\)",
        "name": "JavaScript/Node SQL Injection (Template Literal)",
        "why": "Template literal interpolation (${var}) in SQL allows arbitrary command execution.",
        "remediation": 'Use driver parameter arrays: db.query("SELECT ... WHERE id = $1", [id])',
    },
]

DESTRUCTIVE_MIGRATION_PATTERNS = [
    (r"(?i)\bDROP\s+TABLE\s+(IF\s+EXISTS\s+)?[a-zA-Z0-9_]+", "Destructive migration: DROP TABLE permanently deletes user tables."),
    (r"(?i)\bTRUNCATE\s+(TABLE\s+)?[a-zA-Z0-9_]+", "Destructive migration: TRUNCATE permanently wipes all table records."),
    (r"(?i)\bALTER\s+TABLE\s+[a-zA-Z0-9_]+\s+DROP\s+COLUMN\b", "Destructive migration: DROP COLUMN permanently drops table column and data."),
]

DUMP_SENSITIVE_DATA_PATTERNS = [
    (r"(?i)INSERT\s+INTO\s+.*?(users|accounts|customers|members|auth)\s+VALUES", "Database dump contains live user/customer table insert statements"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "Plaintext email address pattern detected in database dump"),
    (r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", "Bcrypt password hash pattern detected in database dump"),
]


class DatabaseGuard:
    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = (workspace_root or ROOT_DIR).resolve()

    def detect_db_stack(self) -> Dict[str, Any]:
        """Detects if database technologies are used in the workspace."""
        detected = {
            "has_database": False,
            "technologies": set(),
            "evidence_files": [],
        }
        indicators = {
            "prisma": ["schema.prisma", "prisma"],
            "postgresql": ["pg", "psycopg2", "asyncpg", "postgres", "postgresql"],
            "mysql": ["mysql", "mysql2", "mysqli", "pymysql"],
            "sqlite": [".sqlite", ".sqlite3", ".db", "sqlite3"],
            "mongodb": ["mongodb", "mongoose", "pymongo"],
            "redis": ["redis", "ioredis"],
            "sqlalchemy": ["sqlalchemy", "alembic.ini"],
            "django_db": ["settings.py", "models.py"],
        }

        # Check docker-compose
        for dc in ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"]:
            dc_path = self.workspace_root / dc
            if dc_path.is_file():
                content = dc_path.read_text(encoding="utf-8", errors="replace").lower()
                detected["evidence_files"].append(dc)
                for tech in ["postgres", "mysql", "mariadb", "redis", "mongo"]:
                    if tech in content:
                        detected["has_database"] = True
                        detected["technologies"].add(tech)

        # Check manifests
        for fname in ["package.json", "requirements.txt", "pyproject.toml", "composer.json", "Gemfile", "Cargo.toml"]:
            m_path = self.workspace_root / fname
            if m_path.is_file():
                content = m_path.read_text(encoding="utf-8", errors="replace").lower()
                for tech, keywords in indicators.items():
                    if any(kw in content for kw in keywords):
                        detected["has_database"] = True
                        detected["technologies"].add(tech)
                        detected["evidence_files"].append(fname)

        detected["technologies"] = sorted(list(detected["technologies"]))
        return detected

    def scan_dumps_and_data_files(self) -> List[Dict[str, Any]]:
        """Checks for database dump files (.sql, .db, .sqlite) containing real user data."""
        findings = []
        dump_extensions = {".sql", ".sqlite", ".sqlite3", ".db", ".bak", ".dump"}

        for root, dirs, files in os.walk(self.workspace_root):
            for skip in [".git", "node_modules", ".skillguard", "venv", ".venv"]:
                if skip in dirs:
                    dirs.remove(skip)
            for file in files:
                fpath = Path(root) / file
                rel_path = str(fpath.relative_to(self.workspace_root)).replace("\\", "/")
                ext = fpath.suffix.lower()

                if ext in dump_extensions:
                    # Check if file contains real user data
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="replace")[:100000] # Inspect first 100KB
                        data_matches = []
                        for pat, desc in DUMP_SENSITIVE_DATA_PATTERNS:
                            if re.search(pat, content):
                                data_matches.append(desc)

                        severity = "CRITICAL" if data_matches else "HIGH"
                        evidence_desc = f"Database file '{file}' committed in repository."
                        if data_matches:
                            evidence_desc += f" Evidence of real user records: {'; '.join(data_matches)}"

                        findings.append({
                            "id": "DBG-DATA-DUMP",
                            "name": "Committed Database Dump / Data File",
                            "severity": severity,
                            "file": rel_path,
                            "line": 1,
                            "evidence": evidence_desc,
                            "why_dangerous": "Committing database dumps exposes customer PII, hashed passwords, or private production tables directly in git history.",
                            "remediation": f"Delete '{rel_path}' immediately, add '{ext}' to .gitignore, and purge git history with git filter-repo.",
                        })
                    except Exception:
                        pass
        return findings

    def scan_configuration_hygiene(self) -> List[Dict[str, Any]]:
        """Inspects docker-compose, environment templates, and config files for weak credentials and exposed ports."""
        findings = []
        config_files = []

        for root, dirs, files in os.walk(self.workspace_root):
            for skip in [".git", "node_modules", ".skillguard", "venv", ".venv"]:
                if skip in dirs:
                    dirs.remove(skip)
            for file in files:
                if file.endswith((".yml", ".yaml", ".json", ".env.example", ".env.template", ".conf", ".ini", ".toml")):
                    config_files.append(Path(root) / file)

        for fpath in config_files:
            rel_path = str(fpath.relative_to(self.workspace_root)).replace("\\", "/")
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for line_no, line in enumerate(content.splitlines(), start=1):
                # 1. Weak credentials
                for pat, desc in WEAK_CREDENTIAL_PATTERNS:
                    if re.search(pat, line):
                        findings.append({
                            "id": "DBG-WEAK-CREDENTIALS",
                            "name": "Weak / Default Database Credentials",
                            "severity": "CRITICAL",
                            "file": rel_path,
                            "line": line_no,
                            "evidence": line.strip(),
                            "why_dangerous": f"{desc}. Default passwords are automatically scanned and breached by bots.",
                            "remediation": "Generate a strong, random password (min 24 chars) and reference via environment variables.",
                        })

                # 2. Exposed ports on 0.0.0.0
                for pat, desc in UNSAFE_PORTS:
                    if re.search(pat, line):
                        findings.append({
                            "id": "DBG-EXPOSED-PORT",
                            "name": "Database Port Exposed Publicly (0.0.0.0)",
                            "severity": "HIGH",
                            "file": rel_path,
                            "line": line_no,
                            "evidence": line.strip(),
                            "why_dangerous": f"{desc}. Anyone on the public internet or local network can probe the database port.",
                            "remediation": "Bind port to localhost only (127.0.0.1:5432:5432) or use internal Docker networking.",
                        })

                # 3. Insecure TLS
                for pat, desc in INSECURE_TLS_FLAGS:
                    if re.search(pat, line):
                        findings.append({
                            "id": "DBG-INSECURE-TLS",
                            "name": "Database TLS Encryption Disabled",
                            "severity": "HIGH",
                            "file": rel_path,
                            "line": line_no,
                            "evidence": line.strip(),
                            "why_dangerous": f"{desc}. Database traffic (including passwords and queries) travels in unencrypted plain text.",
                            "remediation": "Enforce TLS in connection string (sslmode=require or verify-full).",
                        })

        return findings

    def scan_sql_injection(self) -> List[Dict[str, Any]]:
        """Scans application code for SQL injection vulnerabilities."""
        findings = []
        code_exts = {".py", ".php", ".js", ".jsx", ".ts", ".tsx", ".go", ".java"}

        for root, dirs, files in os.walk(self.workspace_root):
            for skip in [".git", "node_modules", ".skillguard", "venv", ".venv"]:
                if skip in dirs:
                    dirs.remove(skip)
            for file in files:
                fpath = Path(root) / file
                if fpath.suffix.lower() not in code_exts:
                    continue

                rel_path = str(fpath.relative_to(self.workspace_root)).replace("\\", "/")
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for line_no, line in enumerate(content.splitlines(), start=1):
                    for rule in SQL_INJECTION_PATTERNS:
                        if re.search(rule["pattern"], line):
                            findings.append({
                                "id": "DBG-SQL-INJECTION",
                                "name": rule["name"],
                                "severity": "CRITICAL",
                                "file": rel_path,
                                "line": line_no,
                                "evidence": line.strip(),
                                "why_dangerous": rule["why"],
                                "remediation": rule["remediation"],
                            })
        return findings

    def scan_migrations(self) -> List[Dict[str, Any]]:
        """Checks migration scripts for destructive commands."""
        findings = []
        migration_indicators = ["migration", "migrate", "alembic", "schema"]

        for root, dirs, files in os.walk(self.workspace_root):
            for skip in [".git", "node_modules", ".skillguard", "venv", ".venv"]:
                if skip in dirs:
                    dirs.remove(skip)
            for file in files:
                fpath = Path(root) / file
                rel_path = str(fpath.relative_to(self.workspace_root)).replace("\\", "/")
                is_migration = any(ind in rel_path.lower() for ind in migration_indicators) or fpath.suffix.lower() == ".sql"
                if not is_migration:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for line_no, line in enumerate(content.splitlines(), start=1):
                    for pat, desc in DESTRUCTIVE_MIGRATION_PATTERNS:
                        if re.search(pat, line):
                            findings.append({
                                "id": "DBG-DESTRUCTIVE-MIGRATION",
                                "name": "Destructive Database Migration Operation",
                                "severity": "MEDIUM",
                                "file": rel_path,
                                "line": line_no,
                                "evidence": line.strip(),
                                "why_dangerous": desc,
                                "remediation": "Ensure zero-downtime deprecation strategy: soft-delete columns, take snapshots before dropping tables.",
                            })
        return findings

    def run_audit(self) -> Dict[str, Any]:
        """Runs the complete database security inspection suite."""
        db_info = self.detect_db_stack()
        dump_findings = self.scan_dumps_and_data_files()
        config_findings = self.scan_configuration_hygiene()
        sqli_findings = self.scan_sql_injection()
        mig_findings = self.scan_migrations()

        all_findings = dump_findings + config_findings + sqli_findings + mig_findings

        # Determine overall exposure grade
        critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")

        if critical_count > 0:
            exposure_level = "CRITICAL_EXPOSURE"
            verdict = "BLOCK"
        elif high_count > 0:
            exposure_level = "ELEVATED_RISK"
            verdict = "CONFIRM"
        elif all_findings:
            exposure_level = "MODERATE_WARNING"
            verdict = "WARN"
        else:
            exposure_level = "SECURE"
            verdict = "ALLOW"

        # Best practice architectural recommendations
        recommendations = [
            "1. Enforce Least Privilege: Create an unprivileged application database user (e.g. app_user) with SELECT/INSERT/UPDATE permissions only. Never connect as postgres or root.",
            "2. Enable Row-Level Security (RLS): For multi-tenant databases (PostgreSQL/Supabase), enable RLS to enforce tenant boundaries at the database engine level.",
            "3. Enforce Strict TLS: Set sslmode=verify-full or sslmode=require in production database URIs.",
            "4. Automated Daily Backups: Ensure point-in-time recovery (PITR) and encrypted backup snapshots stored offsite.",
        ]

        return {
            "has_database": db_info["has_database"],
            "technologies": db_info["technologies"],
            "exposure_level": exposure_level,
            "verdict": verdict,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "recommendations": recommendations,
        }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="SkillGuard Database Security Guard")
    parser.add_argument("--dir", default=".", help="Directory to audit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--lang", default="tr", choices=["tr", "en"], help="Output language (tr/en)")
    args = parser.parse_args()

    guard = DatabaseGuard(workspace_root=Path(args.dir))
    report = guard.run_audit()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        if args.lang == "tr":
            print(f"[SKILLGUARD] Veritabani Guvenlik Denetimi")
            print(f"Tespit Edilen Yigin: {', '.join(report['technologies']) if report['technologies'] else 'Veritabani izi bulunamadi'}")
            print(f"Risk Seviyesi: {report['exposure_level']} (Bulgu: {report['findings_count']})\n")
            if report["findings"]:
                print("Bulunan Guvenlik Aciklari:")
                for f in report["findings"]:
                    print(f"  [{f['severity']}] {f['name']} ({f['file']}:{f['line']})")
                    print(f"    Kanit: {f['evidence']}")
                    print(f"    Nasil Duzeltilir: {f['remediation']}\n")
            else:
                print("[OK] Veritabani guvenlik acigi, acikta port veya SQL injection riski bulunamadi.\n")

            print("Mimari Guvenlik Tavsiyeleri:")
            for r in report["recommendations"]:
                print(f"  {r}")
        else:
            print(f"[SKILLGUARD] Database Security Audit")
            print(f"Detected Stack: {', '.join(report['technologies']) if report['technologies'] else 'No database indicators detected'}")
            print(f"Exposure Level: {report['exposure_level']} (Findings: {report['findings_count']})\n")
            if report["findings"]:
                print("Identified Vulnerabilities:")
                for f in report["findings"]:
                    print(f"  [{f['severity']}] {f['name']} ({f['file']}:{f['line']})")
                    print(f"    Evidence: {f['evidence']}")
                    print(f"    Remediation: {f['remediation']}\n")
            else:
                print("[OK] No database exposure, weak credentials, or SQL injection risks identified.\n")

            print("Architectural Recommendations:")
            for r in report["recommendations"]:
                print(f"  {r}")

    if report["verdict"] == "BLOCK":
        sys.exit(2)
    elif report["verdict"] in ["CONFIRM", "WARN"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
