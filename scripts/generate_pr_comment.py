#!/usr/bin/env python3
import json
import sys
import os
import glob

sys.path.append(os.path.abspath("apps/api"))
try:
    from app.core.guardrails import PolicyGuardrailsEngine
except ImportError:
    PolicyGuardrailsEngine = None

def run_guardrails(target_dir="tests/fixtures"):
    findings = []
    if not PolicyGuardrailsEngine:
        return findings
    for fp in glob.glob(os.path.join(target_dir, "**/*.tf"), recursive=True):
        try:
            with open(fp, "r") as f:
                code_content = f.read()
            res = PolicyGuardrailsEngine.evaluate(code_content)
            for r in res:
                r["file_path"] = fp
            findings.extend(res)
        except Exception:
            pass
    return findings

def generate_markdown(results_path="checkov_results.json"):
    try:
        with open(results_path, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}

    res = data.get("results", {}) if isinstance(data, dict) else {}
    failed_checks = res.get("failed_checks", []) or []
    passed_checks = res.get("passed_checks", []) or []
    guardrail_violations = run_guardrails()

    total_violations = len(failed_checks) + len(guardrail_violations)
    total_passed = len(passed_checks)

    lines = []
    lines.append("## 🛡️ CloudSecAI Infrastructure Security Gate")

    if total_violations == 0:
        lines.append("> **Status:** ✅ **COMPLIANT (PASSED)**\n")
        lines.append("All security checks and guardrails passed!")
        lines.append(f"- Checks Passed: `{total_passed}`")
        lines.append("- Violations: `0`\n")
        lines.append("*Generated autonomously by CloudSecAI Security Gate Engine.*")
        return "\n".join(lines), 0

    lines.append(f"> **Status:** ❌ **REMEDIATION REQUIRED** ({total_violations} Violations Found)\n")
    lines.append("### 📋 Security Summary")
    lines.append("| Metric | Count |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Violations Detected** | `{total_violations}` |")
    lines.append(f"| **Checks Passed** | `{total_passed}` |\n")
    lines.append("### 🔍 Detected Misconfigurations & Policy Violations\n")

    for item in guardrail_violations:
        sev = item.get("severity", "HIGH")
        rid = item.get("rule_id", "POLICY_ERR")
        title = item.get("title", "Policy Violation")
        fpath = item.get("file_path", "unknown")
        line = item.get("line_number", 1)
        desc = item.get("description", "")
        patch = item.get("ai_suggested_patch")

        lines.append(f"- **[{sev}] {rid}** - {title}")
        lines.append(f"  - **File:** `{fpath}` (Line: `{line}`)")
        lines.append(f"  - **Description:** {desc}")
        if patch:
            lines.append(f"  - **AI Remediation:** `{patch}`")
        lines.append("")

    for item in failed_checks:
        cid = item.get("check_id", "CKV")
        cname = item.get("check_name", "Checkov Finding")
        fpath = item.get("file_path", "unknown")
        lines.append(f"- **[MEDIUM] {cid}** - {cname}")
        lines.append(f"  - **File:** `{fpath}`")
        lines.append("")

    lines.append("---")
    lines.append("*Generated autonomously by CloudSecAI Security Gate Engine.*")
    return "\n".join(lines), total_violations

if __name__ == "__main__":
    rfile = sys.argv[1] if len(sys.argv) > 1 else "checkov_results.json"
    md, count = generate_markdown(rfile)
    with open("pr_comment.md", "w") as f:
        f.write(md)
    print(f"REPORT_GENERATED: {count} violations")
