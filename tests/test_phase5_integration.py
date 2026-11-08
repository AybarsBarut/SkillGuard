"""
Tests for Phase 5: Hook Installation, Security Reporting (MD, JSON, SARIF), and Evals Suite.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "scripts"))
sys.path.insert(0, str(ROOT_DIR / "evals"))

from install_hooks import HookInstaller
from report import run_full_security_report, convert_findings_to_sarif, generate_markdown_report
from run_evals import run_all_evals


class TestPhase5Integration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="skillguard_p5_test_")
        self.workspace = Path(self.temp_dir)
        (self.workspace / ".git" / "hooks").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_hook_installer_lifecycle(self):
        installer = HookInstaller(workspace_root=self.workspace)

        # 1. Install hooks
        res = installer.run_install()
        self.assertIn("INSTALLED", res["pre_commit"])
        self.assertIn("INSTALLED", res["pre_push"])
        self.assertIn("CREATED", res["agent_hooks"])

        pre_commit_file = self.workspace / ".git" / "hooks" / "pre-commit"
        self.assertTrue(pre_commit_file.is_file())
        self.assertIn("SkillGuard", pre_commit_file.read_text(encoding="utf-8"))

        agent_hooks_file = self.workspace / ".agents" / "hooks.json"
        self.assertTrue(agent_hooks_file.is_file())
        agent_data = json.loads(agent_hooks_file.read_text(encoding="utf-8"))
        self.assertIn("skillguard", agent_data)

        # 2. Test chaining when hook already exists with other content
        other_hook = self.workspace / ".git" / "hooks" / "pre-commit"
        other_hook.write_text("#!/bin/sh\necho 'Existing linter'\n", encoding="utf-8")
        chain_res = installer.install_git_hook("pre-commit", "echo 'SkillGuard'")
        self.assertIn("CHAINED", chain_res)
        chained_content = other_hook.read_text(encoding="utf-8")
        self.assertIn("Existing linter", chained_content)
        self.assertIn("Chained SkillGuard Hook", chained_content)

        # 3. Test uninstall
        uninst_logs = installer.uninstall_all()
        self.assertTrue(len(uninst_logs) >= 2)
        # Agent hook entry should be removed
        if agent_hooks_file.is_file():
            post_uninst_agent = json.loads(agent_hooks_file.read_text(encoding="utf-8"))
            self.assertNotIn("skillguard", post_uninst_agent)

    def test_report_generation_md_json_sarif(self):
        report_data = run_full_security_report(workspace_root=self.workspace, output_sarif=True, lang="tr")

        md_file = self.workspace / "SECURITY_REPORT.md"
        json_file = self.workspace / "security-report.json"
        sarif_file = self.workspace / "security-report.sarif"

        self.assertTrue(md_file.is_file(), "SECURITY_REPORT.md must be generated")
        self.assertTrue(json_file.is_file(), "security-report.json must be generated")
        self.assertTrue(sarif_file.is_file(), "security-report.sarif must be generated")

        # Verify SARIF format
        sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "SkillGuard")

        # Verify Markdown structure
        md_text = md_file.read_text(encoding="utf-8")
        self.assertIn("GUVENLIK DENETIM RAPORU", md_text)
        self.assertIn("Genel Karar", md_text)

    def test_evals_benchmark(self):
        success = run_all_evals()
        self.assertTrue(success, "All evals benchmark scenarios must pass with 100% score.")


if __name__ == "__main__":
    unittest.main()
