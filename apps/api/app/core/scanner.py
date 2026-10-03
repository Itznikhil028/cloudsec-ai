import json
import tempfile
import subprocess
import os
from typing import List, Dict, Any

class IaCScanner:
    @staticmethod
    def scan_terraform_string(iac_code: str) -> List[Dict[str, Any]]:
        findings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, 'main.tf')
            with open(file_path, 'w') as f:
                f.write(iac_code)

            cmd = [
                'checkov',
                '-f', file_path,
                '--framework', 'terraform',
                '-o', 'json',
                '--compact',
                '--quiet'
            ]

            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if not process.stdout:
                return findings

            try:
                data = json.loads(process.stdout)
                results = data.get('results', {}) if isinstance(data, dict) else {}
                failed_checks = results.get('failed_checks', [])

                for check in failed_checks:
                    findings.append({
                        'rule_id': check.get('check_id', 'UNKNOWN'),
                        'title': check.get('check_name', 'Security Misconfiguration'),
                        'severity': IaCScanner._map_severity(check.get('severity')),
                        'file_path': 'main.tf',
                        'line_number': check.get('file_line_range', [1])[0] if check.get('file_line_range') else 1,
                        'description': check.get('guideline') or check.get('check_name'),
                        'raw_metadata': {
                            'resource': check.get('resource'),
                            'evaluations': check.get('evaluations')
                        }
                    })
            except json.JSONDecodeError:
                pass

        return findings

    @staticmethod
    def _map_severity(sev: Any) -> str:
        if not sev:
            return 'MEDIUM'
        s = str(sev).upper()
        if 'CRIT' in s: return 'CRITICAL'
        if 'HIGH' in s: return 'HIGH'
        if 'LOW' in s: return 'LOW'
        if 'INFO' in s: return 'INFO'
        return 'MEDIUM'
