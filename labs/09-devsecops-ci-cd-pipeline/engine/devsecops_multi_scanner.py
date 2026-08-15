# -*- coding: utf-8 -*-
"""
Enterprise DevSecOps Multi-Scanner Security Gate Engine v3.0
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import ast
import re
import json
import time
from typing import Dict, List, Any

class SecretScannerEngine:
    PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CRITICAL"),
        (r'-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----', "Private Key Certificate Block", "CRITICAL"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
        (r'xox[baprs]-[0-9a-zA-Z]{10,48}', "Slack OAuth Access Token", "HIGH"),
        (r'(?i)password\s*=\s*['"][^'"]{6,}['"]', "Hardcoded Password String", "HIGH")
    ]

    @classmethod
    def scan_text(cls, content: str, filename: str = "source.py") -> List[Dict[str, Any]]:
        findings = []
        for line_num, line in enumerate(content.splitlines(), 1):
            for regex, desc, sev in cls.PATTERNS:
                if re.search(regex, line):
                    findings.append({
                        "tool": "SecretScanner",
                        "severity": sev,
                        "file": filename,
                        "line": line_num,
                        "issue": desc,
                        "snippet": line.strip()[:60] + "..."
                    })
        return findings

class ASTStaticCodeAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str = "source.py"):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node):
        # Detect insecure eval / exec
        if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
            self.findings.append({
                "tool": "SAST-AST",
                "severity": "CRITICAL",
                "file": self.filename,
                "line": node.lineno,
                "issue": f"Dangerous dynamic execution function detected: '{node.func.id}()'",
                "remediation": "Refactor code to avoid dynamic string evaluation."
            })
        # Detect insecure subprocess with shell=True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ["Popen", "run", "call", "check_output"]:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "tool": "SAST-AST",
                        "severity": "HIGH",
                        "file": self.filename,
                        "line": node.lineno,
                        "issue": "Subprocess executed with shell=True (Command Injection Risk)",
                        "remediation": "Pass command arguments as a list and set shell=False."
                    })
        self.generic_visit(node)

class DevSecOpsGateOrchestrator:
    def __init__(self):
        self.all_findings: List[Dict[str, Any]] = []

    def evaluate_code(self, source_code: str, filename: str = "app.py") -> Dict[str, Any]:
        # 1. Secret Scanning
        secret_findings = SecretScannerEngine.scan_text(source_code, filename)
        
        # 2. AST SAST Analysis
        sast_findings = []
        try:
            tree = ast.parse(source_code)
            analyzer = ASTStaticCodeAnalyzer(filename)
            analyzer.visit(tree)
            sast_findings = analyzer.findings
        except SyntaxError as e:
            sast_findings.append({"tool": "SAST-AST", "severity": "MEDIUM", "file": filename, "line": e.lineno, "issue": f"Syntax parsing error: {e}", "remediation": "Fix syntax."})

        total = secret_findings + sast_findings
        self.all_findings.extend(total)

        gate_status = "PASSED" if not any(f["severity"] == "CRITICAL" for f in total) else "BLOCKED"

        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scanned_file": filename,
            "gate_status": gate_status,
            "total_findings": len(total),
            "findings": total
        }

if __name__ == "__main__":
    gate = DevSecOpsGateOrchestrator()
    vulnerable_code = """
import os, subprocess
API_KEY = "AKIA1111222233334444"
def execute_user_command(user_input):
    eval(user_input)
    subprocess.run("ping " + user_input, shell=True)
"""
    report = gate.evaluate_code(vulnerable_code, "payment_processor.py")
    print(json.dumps(report, indent=2))
