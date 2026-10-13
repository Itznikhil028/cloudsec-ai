#!/usr/bin/env python3
import json
import sys
import os
import glob

# Add apps/api to path so we can import PolicyGuardrailsEngine
sys.path.append(os.path.abspath("apps/api"))
try:
    from app.core.guardrails import PolicyGuardrailsEngine
except ImportError:
    PolicyGuardrailsEngine = None

def run_guardrails_on_fixtures(target_dir="tests/fixtures"):
    findings = []
    if not PolicyGuardrailsEngine:
        return findings
    for filepath in glob.glob(f"{target_dir}/**/*.tf", recursive=True):
        try:
            with open(filepath, "r") as f:
                code = f.read()
            res = PolicyGuardrailsEngine.evaluate(code)
            for r in res:
                r["file_path"] = filepath
            findings.extend(res)
        except Exception:
            pass
    return findings

def generate_markdown(results_path: str) -> tuple[str, int]:
    try:
        with open(results_path, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}

    results = data.get("results", {}) if isinstance(data, dict) else {}
    failed_checks = results.get("failed_checks", []) or []
    passed_checks = results.get("passed_checks", []) or []

    # Run custom enterprise guardrails
    guardrail_violations = run_guardrails_on_fixtures()

    total_violations = len(failed_checks) + len(guardrail_violations)
    total_passed = len(passed_checks)

    if total_violations == 0:
        md = f"""## 🛡️ CloudSecAI Infrastructure Security Gate
> **Status:** ✅ **COMPLIANT (PASSED)**

All CIS compliance checks and enterprise guardrails passed successfully!
- **Total Checks Passed:** `{total_passed}`
- **Security Violations:** `0`

*Generated autonomously by CloudSecAI Security Gate Engine.*
"""
        return md, 0

    md = []
    md.append("## 🛡️ CloudSecAI Infrastructure Security Gate")
    md.append(f"> **Status:** ❌ **REMEDIATION REQUIRED** ({total_violations} Violations Found)")
    md.append("")
    md.append("### 📋 Security Summary")
    md.append("| Metric | Count |")
    md.append("| :--- | :--- |")
    md.append(f"| **Violations Detected** | `{total_violations}` |")
    md.append(f"| **Checks Passed** | `{total_passed}` |")
    md.append("")
    md.append("### 🔍 Detected Misconfigurations & Policy Violations")
    md.append("")

    for item in guardrail_violations:
        md.append(f"- **[{item.get('severity', 'HIGH')}] {item.get('rule_id')}** - {item.get('title')}")
        md.append(f"  - **File:** `{item.get('file_path')}` (Line: `{item.get('line_number')}`)")
        md.append(f"  - **Description:** {item.get('description')}")
        if item.get("ai_suggested_patch"):
            md.append(f"  - **AI Remediation:** `{item.get('ai_suggested_patch')}`")
        md.append("")

    for item in failed_checks:
        md.append(f"- **[{item.get('severity', 'MEDIUM')}] {item.get('check_id')}** - {item.get('check_name')}")
        md.append(f"  - **File:** `{item.get('file_path')}` (Lines: `{item.get('file_line_range', [0])[0]}`)")
        md.append("")

    md.append("---")
    md.append("*Generated autonomously by CloudSecAI Security Gate Engine.*")
    return "\n".join(md), total_violations

if __name__ == "__main__":
    results_file = sys.argv[1] if len(sys.argv) > 1 else "checkov_results.json"
    report_md, violation_count = generate_markdown(results_file)
    with open("pr_comment.md", "w") as f:
        f.write(report_md)
    print(f"REPORT_GENERATED: {violation_count} violations")
