"""
Tests for Phase 3: Pre-Commit & Pre-Push Sanitizer, Vault Management, and Undo Functionality.
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

from sanitize_push import (
    PushSanitizer,
    run_push_check,
    is_forbidden_file,
    is_placeholder,
    calculate_entropy,
)


class TestSanitizePush(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="skillguard_push_test_")
        self.workspace = Path(self.temp_dir)
        self.sanitizer = PushSanitizer(workspace_root=self.workspace)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_forbidden_file_detection(self):
        forbidden_names = [
            ".env",
            ".env.production",
            ".env.local",
            "id_rsa",
            "id_ed25519",
            "server.pem",
            "privkey.key",
            "database_dump.sql",
            "app.sqlite3",
            "terraform.tfstate",
        ]
        for fname in forbidden_names:
            self.assertTrue(is_forbidden_file(fname), f"Expected '{fname}' to be recognized as forbidden")

        allowed_names = [
            "config.py",
            "README.md",
            "styles.css",
            "index.html",
            "schema.prisma",
            ".env.example",
        ]
        for fname in allowed_names:
            self.assertFalse(is_forbidden_file(fname), f"'{fname}' should not be forbidden")

    def test_placeholder_exemption(self):
        self.assertTrue(is_placeholder("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(is_placeholder("YOUR_API_KEY_HERE"))
        self.assertTrue(is_placeholder("fake_test_token"))
        self.assertFalse(is_placeholder("ghp_987654321012345678901234567890123456"))

    def test_secret_patterns_detection(self):
        code_file = self.workspace / "app.py"
        code_file.write_text(
            '# Sample application\n'
            'openai_key = "sk-1234567890abcdef1234567890abcdef12345678"\n'
            'aws_key = "AKIA1234567890ABCDEF"\n'
            'gh_token = "ghp_123456789012345678901234567890123456"\n'
            'db_conn = "postgres://usr:p4ssw0rd123@prod-db.internal:5432/main"\n'
            'doc_ip = "198.51.100.42"\n'  # RFC 5737 doc IP exempt
            'internal_ip = "10.0.1.15"\n'  # Internal IP flagged
            '# bypass auth check temporarily\n',
            encoding="utf-8"
        )

        findings = self.sanitizer.inspect_file(code_file)
        rule_ids = {f["id"] for f in findings}

        self.assertIn("SEC-OPENAI-KEY", rule_ids)
        self.assertIn("SEC-AWS-KEY", rule_ids)
        self.assertIn("SEC-GITHUB-TOKEN", rule_ids)
        self.assertIn("SEC-DB-URI", rule_ids)
        self.assertIn("SEC-INTERNAL-IP", rule_ids)
        self.assertIn("SEC-SENSITIVE-COMMENT", rule_ids)

        # Ensure doc_ip was not flagged
        self.assertFalse(any(f.get("secret_value") == "198.51.100.42" for f in findings))

    def test_auto_sanitization_vault_and_undo(self):
        secret_token = "ghp_123456789012345678901234567890123456"
        py_file = self.workspace / "service.py"
        original_source = f'client_token = "{secret_token}"\nprint("Connecting")\n'
        py_file.write_text(original_source, encoding="utf-8")

        # 1. Run check with auto_sanitize
        result = run_push_check(workspace_root=self.workspace, auto_sanitize=True)
        self.assertEqual(result["verdict"], "SANITIZED_PROCEED_WITH_WARNING")
        self.assertEqual(len(result["sanitized_records"]), 1)

        # 2. Verify file content was sanitized safely
        sanitized_content = py_file.read_text(encoding="utf-8")
        self.assertNotIn(secret_token, sanitized_content)
        self.assertIn('os.environ.get("GITHUB_TOKEN', sanitized_content)
        self.assertIn("import os", sanitized_content)

        # 3. Verify .env.example was generated
        env_ex = self.workspace / ".env.example"
        self.assertTrue(env_ex.is_file())
        self.assertIn("GITHUB_TOKEN=your_github_token_here", env_ex.read_text(encoding="utf-8"))

        # 4. Verify .gitignore was updated
        gitignore = self.workspace / ".gitignore"
        self.assertTrue(gitignore.is_file())
        gi_content = gitignore.read_text(encoding="utf-8")
        self.assertIn(".env", gi_content)
        self.assertIn(".skillguard/vault/", gi_content)

        # 5. Verify vault record exists
        vault_dir = self.workspace / ".skillguard" / "vault"
        self.assertTrue(vault_dir.is_dir())
        self.assertTrue((vault_dir / "latest.json").is_file())

        # 6. Test Undo restores exact original code
        ok, msg = self.sanitizer.undo_last_sanitization()
        self.assertTrue(ok, f"Undo failed: {msg}")
        restored_content = py_file.read_text(encoding="utf-8")
        self.assertEqual(restored_content, original_source)

    def test_forbidden_file_blocks_push(self):
        env_file = self.workspace / ".env"
        env_file.write_text("DATABASE_PASSWORD=secret_value\n", encoding="utf-8")

        result = run_push_check(workspace_root=self.workspace, auto_sanitize=True)
        self.assertEqual(result["verdict"], "BLOCK_PUSH")
        self.assertTrue(any(f["id"] == "SEC-FORBIDDEN-FILE" for f in result["findings"]))
        self.assertIn("CRITICAL SECURITY ROTATION WARNING", result["rotation_notice"])


    def test_ai_agent_provenance_and_stealth_leak(self):
        # 1. Test watermark / attribution in source code
        leaky_code = self.workspace / "leak.py"
        leaky_code.write_text(
            "# Module helper\n"
            "# Generated by Claude 3.5 Sonnet\n"
            "def run():\n"
            "    # Co-authored-by: Cursor <bot@cursor.com>\n"
            "    pass\n",
            encoding="utf-8"
        )
        findings = self.sanitizer.inspect_file(leaky_code)
        rule_ids = {f["id"] for f in findings}
        self.assertIn("PRV-AI-PROVENANCE", rule_ids)
        self.assertIn("PRV-AI-COAUTHOR", rule_ids)

        # 2. Test push check blocks on provenance leak
        result = run_push_check(workspace_root=self.workspace, single_file=leaky_code)
        self.assertEqual(result["verdict"], "BLOCK_PUSH")


if __name__ == "__main__":
    unittest.main()
