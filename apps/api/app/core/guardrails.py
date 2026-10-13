"""Custom Policy Guardrails Engine for CloudSecAI."""
from typing import List, Dict, Any
import re

class PolicyGuardrailsEngine:
    MANDATORY_TAGS = ["Environment", "Owner"]
    DISALLOWED_INSTANCES = ["p4d.24xlarge", "p3.16xlarge", "g5.12xlarge", "m5.metal"]

    @classmethod
    def evaluate(cls, raw_hcl: str) -> List[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        # 1. Mandatory Tags Check
        bucket_matches = re.finditer(r'resource\s+"aws_s3_bucket"\s+"([a-zA-Z0-9_-]+)"\s*\{([^}]*)\}', raw_hcl)
        for m in bucket_matches:
            name, body = m.group(1), m.group(2)
            for tag in cls.MANDATORY_TAGS:
                if f'"{tag}"' not in body and f"{tag}" not in body:
                    violations.append({
                        "id": f"GUARDRAIL_TAG_{tag.upper()}",
                        "rule_id": f"ORG_POL_TAG_{tag.upper()}",
                        "title": f"Missing Mandatory Tag '{tag}' on S3 Bucket",
                        "severity": "HIGH",
                        "file_path": "main.tf",
                        "line_number": 1,
                        "description": f"Enterprise Tagging Baseline requires '{tag}' for governance.",
                        "ai_root_cause": f"Organization Guardrail Violation: Missing mandatory tag '{tag}'.",
                        "ai_suggested_patch": f"  tags = {{\n    {tag} = \"Production\"\n  }}"
                    })

        # 2. FinOps Check
        for dis in cls.DISALLOWED_INSTANCES:
            if dis in raw_hcl:
                violations.append({
                    "id": "GUARDRAIL_FINOPS_01",
                    "rule_id": "ORG_POL_FINOPS_01",
                    "title": f"Disallowed High-Cost Compute Family: {dis}",
                    "severity": "CRITICAL",
                    "file_path": "main.tf",
                    "line_number": 1,
                    "description": f"Instance family '{dis}' exceeds budget guardrails.",
                    "ai_root_cause": f"FinOps Policy Violation: Compute family '{dis}' blocked.",
                    "ai_suggested_patch": "  instance_type = \"t3.medium\""
                })

        return violations
