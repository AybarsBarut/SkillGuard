"""
Tests for Phase 4: Database Guard and Tech Stack / CVE Auditor.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add scripts directory to sys.path
import sys
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from db_guard import DatabaseGuard
from stack_audit import (
    StackAuditor,
    parse_requirements_txt,
    parse_package_json,
    parse_composer_json,
    parse_cargo_toml,
    parse_go_mod,
)


class TestDatabaseGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="skillguard_db_test_")
        self.workspace = Path(self.temp_dir)
        self.guard = DatabaseGuard(workspace_root=self.workspace)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_db_stack(self):
        # Create a docker-compose.yml with postgres
        (self.workspace / "docker-compose.yml").write_text(
            "version: '3.8'\n"
            "services:\n"
            "  db:\n"
            "    image: postgres:15\n"
            "    ports:\n"
            "      - '0.0.0.0:5432:5432'\n",
            encoding="utf-8"
        )
        info = self.guard.detect_db_stack()
        self.assertTrue(info["has_database"])
        self.assertIn("postgres", info["technologies"])

    def test_scan_dumps_and_data_files(self):
        dump_file = self.workspace / "backup.sql"
        dump_file.write_text(
            "-- Database dump\n"
            "INSERT INTO users VALUES (1, 'alice@example.com', '$2a$12$e80y9y49y949y949y949yO');\n",
            encoding="utf-8"
        )
        findings = self.guard.scan_dumps_and_data_files()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "DBG-DATA-DUMP")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("Evidence of real user records", findings[0]["evidence"])

    def test_configuration_hygiene(self):
        config_file = self.workspace / "docker-compose.yml"
        config_file.write_text(
            "services:\n"
            "  db:\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: admin\n"
            "    ports:\n"
            "      - '0.0.0.0:5432:5432'\n",
            encoding="utf-8"
        )
        findings = self.guard.scan_configuration_hygiene()
        rule_ids = {f["id"] for f in findings}
        self.assertIn("DBG-WEAK-CREDENTIALS", rule_ids)
        self.assertIn("DBG-EXPOSED-PORT", rule_ids)

    def test_sql_injection_detection(self):
        code_file = self.workspace / "controller.py"
        code_file.write_text(
            "def get_user(user_id):\n"
            "    # Bad SQL query using f-string\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n",
            encoding="utf-8"
        )
        findings = self.guard.scan_sql_injection()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "DBG-SQL-INJECTION")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("parameterized query", findings[0]["remediation"])

    def test_destructive_migrations(self):
        mig_file = self.workspace / "0002_migration.sql"
        mig_file.write_text(
            "ALTER TABLE users DROP COLUMN old_token;\n"
            "DROP TABLE legacy_orders;\n",
            encoding="utf-8"
        )
        findings = self.guard.scan_migrations()
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "DBG-DESTRUCTIVE-MIGRATION")


class TestStackAuditor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="skillguard_stack_test_")
        self.workspace = Path(self.temp_dir)
        self.auditor = StackAuditor(workspace_root=self.workspace)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_parsers(self):
        # 1. requirements.txt
        reqs = parse_requirements_txt("requests==2.20.0\nflask>=2.0.0\n# comment\n")
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0]["name"], "requests")
        self.assertEqual(reqs[0]["version"], "2.20.0")

        # 2. package.json
        pkg_json = parse_package_json('{"dependencies": {"lodash": "^4.17.15", "express": "~4.16.0"}}')
        self.assertEqual(len(pkg_json), 2)
        pkg_names = {p["name"] for p in pkg_json}
        self.assertIn("lodash", pkg_names)
        self.assertIn("express", pkg_names)

        # 3. composer.json
        comp = parse_composer_json('{"require": {"php": ">=8.1", "guzzlehttp/guzzle": "^6.3.0"}}')
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["name"], "guzzlehttp/guzzle")

        # 4. Cargo.toml
        cargo = parse_cargo_toml('[dependencies]\nserde = "1.0.104"\n')
        self.assertEqual(len(cargo), 1)
        self.assertEqual(cargo[0]["name"], "serde")

        # 5. go.mod
        go = parse_go_mod('module myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n')
        self.assertEqual(len(go), 1)
        self.assertEqual(go[0]["name"], "github.com/gin-gonic/gin")

    def test_offline_cache_cve_lookup(self):
        # Seed test cache with a known vulnerability
        cache_key = "PyPI:vulnerable-pkg:1.0.0"
        dummy_advisory = [{
            "id": "GHSA-1234-5678-9000",
            "summary": "Critical Remote Code Execution in vulnerable-pkg",
            "aliases": ["CVE-2024-9999"],
            "affected": [{
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]
                }]
            }]
        }]
        cache = self.auditor._load_cache()
        cache[cache_key] = dummy_advisory
        self.auditor._save_cache(cache)

        offline_auditor = StackAuditor(workspace_root=self.workspace, offline=True)
        findings = offline_auditor.audit_package({"name": "vulnerable-pkg", "version": "1.0.0", "ecosystem": "PyPI"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cve_id"], "GHSA-1234-5678-9000")
        self.assertIn("Upgrade 'vulnerable-pkg' to version 1.0.1", findings[0]["remediation"])


if __name__ == "__main__":
    unittest.main()
