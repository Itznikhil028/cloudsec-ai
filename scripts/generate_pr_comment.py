#!/usr/bin/env python3
import json
import sys

def generate_markdown(results_path: str) -> str:
    try:
        with open(results_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        return f"### ⚠️ CloudSecAI Security Gate Error\nCould not parse scan results: {e}"

    results = data.get("results", {}) if isinstance(data, dict) else {}
    failed_checks = results.get("failed_checks", [])
    passed_checks = results.get("passed_checks", [])

    total_violations = len(failed_checks)
    total_passed = len(passed_checks)

    if total_violations == 0:
        return f"""## 🛡️ CloudSecAI Infrastructure Security Gate
> **Status:** ✅ **COMPLIANT (PASSED)**

All CIS compliance checks and security benchmarks passed successfully!
- **Total Checks Passed:** `{total_passed}`
- **Security Violations:** `0`
"""

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

    for idx, check in enumerate(failed_checks[:10], start=1):
        rule_id = check.get("check_id", "UNKNOWN")
        title = check.get("check_name", "Misconfiguration")
        file_path = check.get("file_path", "main.tf")
        lines = check.get("file_line_range", [1])
        resource = check.get("resource", "AWS Resource")
        guideline = check.get("guideline") or "Review CIS AWS Foundation Benchmark."

        md.append(f"#### {idx}. `{rule_id}` - {title}")
        md.append(f"- **Target Resource:** `{resource}`")
        md.append(f"- **File Location:** `{file_path}:{lines[0]}`")
        md.append(f"- **Guideline:** [Documentation Reference]({guideline})")
        md.append("")

    if total_violations > 10:
        md.append(f"> *...and {total_violations - 10} more findings. Download full CI artifact for complete report.*")
        md.append("")

    md.append("---")
    md.append("*Generated autonomously by **CloudSecAI Security Gate Engine**.*")
    return "\n".join(md)

if __name__ == "__main__":
    file_input = sys.argv[1] if len(sys.argv) > 1 else "checkov_results.json"
    output_md = generate_markdown(file_input)
    with open("pr_comment.md", "w") as out:
        out.write(output_md)
    print("Successfully generated pr_comment.md")
