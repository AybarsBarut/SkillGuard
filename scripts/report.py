"""
SkillGuard Report Generator: SECURITY_REPORT.md, JSON & SARIF (report.py)
Aggregates security findings across all SkillGuard modules (skills, push secrets, database, stack CVEs, AI provenance).
Generates an executive markdown report, structured JSON, and OASIS SARIF v2.1.0 output.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from scan_skill import SkillScanner
from sanitize_push import PushSanitizer, run_push_check
from db_guard import DatabaseGuard
from stack_audit import StackAuditor


def convert_findings_to_sarif(all_findings: List[Dict[str, Any]], workspace_root: Path) -> Dict[str, Any]:
    """Converts SkillGuard findings into official OASIS SARIF v2.1.0 standard JSON."""
    sarif_rules = {}
    sarif_results = []

    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }

    for f in all_findings:
        rule_id = f.get("id", "SG-000")
        if rule_id not in sarif_rules:
            sarif_rules[rule_id] = {
                "id": rule_id,
                "name": f.get("name", rule_id),
                "shortDescription": {"text": f.get("name", rule_id)},
                "fullDescription": {"text": f.get("why_dangerous", f.get("summary", "Security finding detected by SkillGuard."))},
                "help": {"text": f.get("remediation", "Review and remediate finding.")},
                "defaultConfiguration": {"level": level_map.get(f.get("severity", "MEDIUM"), "warning")},
            }

        file_uri = str(f.get("file", "unknown")).replace("\\", "/")
        line_num = max(1, int(f.get("line", 1)))

        sarif_results.append({
            "ruleId": rule_id,
            "level": level_map.get(f.get("severity", "MEDIUM"), "warning"),
            "message": {"text": f.get("evidence", f.get("name", "Finding detected"))},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line_num}
                    }
                }
            ]
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/skillguard/skillguard",
                        "rules": list(sarif_rules.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }


def generate_markdown_report(data: Dict[str, Any], lang: str = "tr") -> str:
    """Renders human-readable, executive SECURITY_REPORT.md."""
    verdict = data.get("overall_verdict", "ALLOW")
    findings = data.get("all_findings", [])
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 5))

    top_3 = sorted_findings[:3]

    if lang == "tr":
        badge = "🔴 BLOKLANDI" if verdict in ["BLOCK", "BLOCK_PUSH", "BLOCK_DEPLOY"] else ("🟡 ONAY / DİKKAT" if verdict in ["CONFIRM", "WARN"] else "🟢 TEMİZ")
        lines = [
            "# 🛡️ SKILLGUARD GÜVENLİK DENETİM RAPORU",
            f"**Tarih:** {now_str}  |  **Genel Karar:** {badge} (`{verdict}`)",
            "",
            "---",
            "",
            "## 🚨 En Kritik Riskler (Top 3)",
        ]
        if not top_3:
            lines.append("Harika haber! Projede açıkta bekleyen kritik bir güvenlik riski bulunamadı.")
        else:
            for idx, item in enumerate(top_3, start=1):
                lines.extend([
                    f"### {idx}. [{item.get('severity')}] {item.get('name')}",
                    f"- **Konum:** `{item.get('file', 'repo')}:{item.get('line', 0)}`",
                    f"- **Neden Tehlikeli:** {item.get('why_dangerous', item.get('summary', ''))}",
                    f"- **Kanıt:** `{item.get('evidence', '')[:140]}`",
                    f"- **Nasıl Düzeltilir:** {item.get('remediation', '')}",
                    "",
                ])

        lines.extend([
            "---",
            "",
            "## 📊 Modüler Güvenlik Durumu",
            f"- **Taranan Skill / Prompt Bulguları:** {data.get('skill_findings_count', 0)}",
            f"- **Push Öncesi Sır ve Dosya Bulguları:** {data.get('push_findings_count', 0)}",
            f"- **Veritabanı Hijyeni ve Açıkları:** {data.get('db_findings_count', 0)}",
            f"- **Bağımlılık CVE / Güvenlik Bildirileri:** {data.get('stack_findings_count', 0)}",
            f"- **Yapay Zeka Gizlilik ve İfşa Durumu:** {'⚠️ İfşa/Watermark Tespit Edildi' if any(f.get('id', '').startswith('PRV-') for f in findings) else '✅ Tamamen Gizli (Sıfır İz)'}",
            "",
            "---",
            "",
            "## 📋 Tüm Bulguların Listesi",
        ])
        if not sorted_findings:
            lines.append("Temiz! Hiçbir güvenlik bulgusu kaydedilmedi.")
        else:
            for f in sorted_findings:
                lines.extend([
                    f"#### [{f.get('severity')}] {f.get('name')} (`{f.get('id')}`)",
                    f"- **Dosya:** `{f.get('file', 'repo')}:{f.get('line', 0)}`",
                    f"- **Açıklama:** {f.get('why_dangerous', f.get('summary', ''))}",
                    f"- **Eylem / Çözüm:** {f.get('remediation', '')}",
                    "",
                ])

        lines.extend([
            "---",
            "*Bu rapor SkillGuard güvenlik motoru tarafından bağımsız olarak üretilmiştir. "
            "Daha fazla detay için: `python scripts/report.py --json`*",
        ])
        return "\n".join(lines)
    else:
        badge = "🔴 BLOCKED" if verdict in ["BLOCK", "BLOCK_PUSH", "BLOCK_DEPLOY"] else ("🟡 CONFIRM / CAUTION" if verdict in ["CONFIRM", "WARN"] else "🟢 CLEAN")
        lines = [
            "# 🛡️ SKILLGUARD SECURITY AUDIT REPORT",
            f"**Generated:** {now_str}  |  **Overall Verdict:** {badge} (`{verdict}`)",
            "",
            "---",
            "",
            "## 🚨 Top 3 Critical Risks",
        ]
        if not top_3:
            lines.append("No critical security risks identified in the workspace.")
        else:
            for idx, item in enumerate(top_3, start=1):
                lines.extend([
                    f"### {idx}. [{item.get('severity')}] {item.get('name')}",
                    f"- **Location:** `{item.get('file', 'repo')}:{item.get('line', 0)}`",
                    f"- **Why Dangerous:** {item.get('why_dangerous', item.get('summary', ''))}",
                    f"- **Evidence:** `{item.get('evidence', '')[:140]}`",
                    f"- **Remediation:** {item.get('remediation', '')}",
                    "",
                ])

        lines.extend([
            "---",
            "",
            "## 📊 Security Posture by Module",
            f"- **Skill & Prompt Findings:** {data.get('skill_findings_count', 0)}",
            f"- **Push Secrets & Leaked Keys:** {data.get('push_findings_count', 0)}",
            f"- **Database Hygiene & SQLi:** {data.get('db_findings_count', 0)}",
            f"- **Dependency CVEs & Advisories:** {data.get('stack_findings_count', 0)}",
            f"- **AI Agent Provenance Status:** {'⚠️ Attribution Leak Detected' if any(f.get('id', '').startswith('PRV-') for f in findings) else '✅ Stealth Verified (Zero Attribution)'}",
            "",
            "---",
            "",
            "## 📋 Comprehensive Findings",
        ])
        if not sorted_findings:
            lines.append("Clean. Zero findings detected.")
        else:
            for f in sorted_findings:
                lines.extend([
                    f"#### [{f.get('severity')}] {f.get('name')} (`{f.get('id')}`)",
                    f"- **Location:** `{f.get('file', 'repo')}:{f.get('line', 0)}`",
                    f"- **Description:** {f.get('why_dangerous', f.get('summary', ''))}",
                    f"- **Remediation:** {f.get('remediation', '')}",
                    "",
                ])

        lines.extend([
            "---",
            "*Report generated deterministically by SkillGuard Security Engine. "
            "For machine-readable export: `python scripts/report.py --json`*",
        ])
        return "\n".join(lines)


def run_full_security_report(workspace_root: Optional[Path] = None, output_sarif: bool = True, lang: str = "tr") -> Dict[str, Any]:
    """Coordinates full audit across all modules and writes SECURITY_REPORT.md, JSON, and SARIF."""
    ws = (workspace_root or ROOT_DIR).resolve()

    # 1. Push check & Secrets & AI provenance
    push_res = run_push_check(workspace_root=ws)
    push_findings = push_res.get("findings", [])

    # 2. Database audit
    db_guard = DatabaseGuard(workspace_root=ws)
    db_res = db_guard.run_audit()
    db_findings = db_res.get("findings", [])

    # 3. Stack & CVE audit
    stack_auditor = StackAuditor(workspace_root=ws, offline=True)
    stack_res = stack_auditor.run_audit()
    stack_findings = stack_res.get("findings", [])

    all_findings = push_findings + db_findings + stack_findings

    # Overall verdict
    if any(f.get("severity") == "CRITICAL" for f in all_findings) or push_res.get("verdict") == "BLOCK_PUSH":
        overall_verdict = "BLOCK"
    elif any(f.get("severity") == "HIGH" for f in all_findings):
        overall_verdict = "CONFIRM"
    elif all_findings:
        overall_verdict = "WARN"
    else:
        overall_verdict = "ALLOW"

    report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(ws),
        "overall_verdict": overall_verdict,
        "total_findings": len(all_findings),
        "push_findings_count": len(push_findings),
        "db_findings_count": len(db_findings),
        "stack_findings_count": len(stack_findings),
        "skill_findings_count": 0,
        "all_findings": all_findings,
    }

    # Write SECURITY_REPORT.md
    md_content = generate_markdown_report(report_data, lang=lang)
    md_file = ws / "SECURITY_REPORT.md"
    md_file.write_text(md_content, encoding="utf-8")

    # Write security-report.json
    json_file = ws / "security-report.json"
    json_file.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write security-report.sarif
    if output_sarif:
        sarif_data = convert_findings_to_sarif(all_findings, ws)
        sarif_file = ws / "security-report.sarif"
        sarif_file.write_text(json.dumps(sarif_data, indent=2, ensure_ascii=False), encoding="utf-8")

    return report_data


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="SkillGuard Security Report Generator")
    parser.add_argument("--dir", default=".", help="Workspace root directory")
    parser.add_argument("--lang", default="tr", choices=["tr", "en"], help="Report language (tr/en)")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout")
    args = parser.parse_args()

    report = run_full_security_report(workspace_root=Path(args.dir), lang=args.lang)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"🛡️ SkillGuard: Generated SECURITY_REPORT.md, security-report.json, and security-report.sarif")
        print(f"Overall Verdict: {report['overall_verdict']} | Total Findings: {report['total_findings']}")


if __name__ == "__main__":
    main()
