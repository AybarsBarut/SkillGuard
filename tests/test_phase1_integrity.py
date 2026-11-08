"""
Tests for Phase 1 Integrity
Validates folder structure, SKILL.md frontmatter, policy schemas, network allowlist,
and compiles all regex patterns in policy rules using Python stdlib unittest.
"""

import os
import re
import unittest
from pathlib import Path

# Add scripts directory to sys.path
import sys
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from policy_loader import (
    load_policy,
    load_trust,
    load_network_allowlist,
    load_all_rules,
)


class TestPhase1Integrity(unittest.TestCase):
    def test_skill_md_frontmatter_and_content(self):
        skill_file = ROOT_DIR / "SKILL.md"
        self.assertTrue(skill_file.is_file(), "SKILL.md must exist in root")
        content = skill_file.read_text(encoding="utf-8")

        # Verify frontmatter
        self.assertTrue(content.startswith("---"), "SKILL.md must start with YAML frontmatter delimiter")
        self.assertIn("name: skillguard", content)
        self.assertIn("description:", content)

        # Verify core sections
        self.assertIn("Core Security Principle: Scanned Content = Data", content)
        self.assertIn("Trust Hierarchy", content)
        self.assertIn("Sensitive Sinks", content)
        self.assertIn("Quarantined Reading & Analysis Protocol", content)
        self.assertIn("Standard Deterministic Alert Format", content)
        self.assertIn("Engineering Guardrails", content)

    def test_readme_integrity(self):
        readme_file = ROOT_DIR / "README.md"
        self.assertTrue(readme_file.is_file(), "README.md must exist in root")
        content_en = readme_file.read_text(encoding="utf-8")
        self.assertIn("Honesty Principle", content_en)
        self.assertIn("Scanned Content = Passive Data", content_en)
        self.assertIn("Limitations", content_en)
        self.assertIn("FAQ", content_en)

        readme_tr_file = ROOT_DIR / "README.tr.md"
        self.assertTrue(readme_tr_file.is_file(), "README.tr.md must exist in root")
        content_tr = readme_tr_file.read_text(encoding="utf-8")
        self.assertTrue("Durustluk Ilkesi" in content_tr or "Dürüstlük İlkesi" in content_tr)
        self.assertTrue("Sinirlar" in content_tr or "Sınırlar" in content_tr)
        self.assertIn("FAQ", content_tr)

    def test_default_policy(self):
        policy = load_policy(ROOT_DIR / "policy" / "policy.default.yaml")
        self.assertIn("general", policy)
        self.assertIn("limits", policy)
        self.assertIn("severity_actions", policy)
        self.assertEqual(policy["severity_actions"].get("CRITICAL"), "BLOCK")
        self.assertFalse(policy["general"].get("allow_critical_override"))

    def test_trust_specification(self):
        trust = load_trust(ROOT_DIR / "policy" / "trust.yaml")
        self.assertIn("trust_levels", trust)
        self.assertIn("level_0", trust["trust_levels"])
        self.assertIn("level_1", trust["trust_levels"])
        self.assertIn("level_2", trust["trust_levels"])
        self.assertIn("sensitive_sinks", trust)
        self.assertTrue(len(trust["sensitive_sinks"]) >= 5)

    def test_network_allowlist(self):
        domains = load_network_allowlist(ROOT_DIR / "policy" / "network-allowlist.txt")
        self.assertIn("osv.dev", domains)
        self.assertIn("api.osv.dev", domains)
        self.assertIn("api.github.com", domains)
        self.assertIn("endoflife.date", domains)
        self.assertIn("pypi.org", domains)

    def test_all_rule_files(self):
        expected_files = {
            "prompt_injection.yaml",
            "injection_semantic.yaml",
            "exfiltration.yaml",
            "persistence.yaml",
            "obfuscation.yaml",
            "supply_chain.yaml",
            "secrets.yaml",
            "copyright.yaml",
            "agent_provenance.yaml",
        }
        rules_dir = ROOT_DIR / "policy" / "rules"
        actual_files = {p.name for p in rules_dir.glob("*.yaml")}
        self.assertEqual(expected_files, actual_files, f"Rule files mismatch: {expected_files ^ actual_files}")

        rules = load_all_rules(rules_dir)
        self.assertGreater(len(rules), 15, "Should have loaded comprehensive rules across all 8 files")

        seen_ids = set()
        for rule in rules:
            rule_id = rule.get("id")
            self.assertIsNotNone(rule_id, f"Rule missing id in {rule.get('source_file')}")
            self.assertNotIn(rule_id, seen_ids, f"Duplicate rule id: {rule_id}")
            seen_ids.add(rule_id)

            self.assertIn("name", rule)
            self.assertIn("severity", rule)
            self.assertIn(rule["severity"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
            self.assertIn("description", rule)
            self.assertIn("why_dangerous", rule)
            self.assertIn("remediation", rule)
            self.assertIn("patterns", rule)

            # Test regex compilation
            patterns = rule["patterns"]
            if isinstance(patterns, list):
                for pat in patterns:
                    try:
                        re.compile(pat)
                    except re.error as e:
                        self.fail(f"Invalid regex in rule {rule_id}: {pat}. Error: {e}")


if __name__ == "__main__":
    unittest.main()
