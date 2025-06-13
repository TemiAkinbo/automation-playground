import re
import os
import sys
import json
import argparse
from pathlib import Path

# Rule definitions with metadata
RULES = [
    {
        "id": "VB6-SHELL-COMMAND",
        "name": "Command Execution (Shell)",
        "pattern": r"\bShell\s*\(",
        "severity": "error",
        "description": "Use of 'Shell' may allow arbitrary OS command execution, leading to remote code execution (RCE).",
        "cwe": "CWE-78",
        "owasp": "A1:2021 - Broken Access Control",
        "help_url": "https://cwe.mitre.org/data/definitions/78.html"
    },
    {
        "id": "VB6-FILE-ACCESS",
        "name": "Filesystem Access (FileSystemObject)",
        "pattern": r"CreateObject\s*\(\s*\"Scripting\.FileSystemObject\"",
        "severity": "warning",
        "description": "Access to filesystem without input sanitization may lead to directory traversal or insecure file writes.",
        "cwe": "CWE-732",
        "owasp": "A5:2021 - Security Misconfiguration",
        "help_url": "https://cwe.mitre.org/data/definitions/732.html"
    },
    {
        "id": "VB6-HARDCODED-PASSWORD",
        "name": "Hardcoded Password",
        "pattern": r"(password\s*=\s*\"[^\"]+\")|(pwd\s*=\s*\"[^\"]+\")",
        "severity": "error",
        "description": "Hardcoded passwords are insecure and violate secure credential storage practices.",
        "cwe": "CWE-259",
        "owasp": "A2:2021 - Cryptographic Failures",
        "help_url": "https://cwe.mitre.org/data/definitions/259.html"
    },
    {
        "id": "VB6-REGISTRY-ACCESS",
        "name": "Registry Access (WScript.Shell)",
        "pattern": r"CreateObject\s*\(\s*\"WScript\.Shell\"",
        "severity": "note",
        "description": "Accessing Windows Registry can be a risk if user input influences keys or values.",
        "cwe": "CWE-489",
        "owasp": "A5:2021 - Security Misconfiguration",
        "help_url": "https://cwe.mitre.org/data/definitions/489.html"
    },
    {
        "id": "VB6-EXTERNAL-LIBRARY",
        "name": "External Library Access",
        "pattern": r"Declare\s+Function.*Lib\s+\".*\.dll\"",
        "severity": "warning",
        "description": "Calling unmanaged DLLs can lead to memory corruption or security bypass if not handled properly.",
        "cwe": "CWE-427",
        "owasp": "A3:2021 - Injection",
        "help_url": "https://cwe.mitre.org/data/definitions/427.html"
    },
    {
        "id": "VB6-INSECURE-API",
        "name": "Use of Insecure API (WriteProcessMemory)",
        "pattern": r"WriteProcessMemory",
        "severity": "error",
        "description": "Dangerous API that can be abused for process injection and privilege escalation.",
        "cwe": "CWE-123",
        "owasp": "A1:2021 - Broken Access Control",
        "help_url": "https://cwe.mitre.org/data/definitions/123.html"
    }
]

VB6_EXTENSIONS = ['.bas', '.frm', '.cls', '.vbp']

def scan_file(file_path):
    results = []
    with open(file_path, 'r', errors='ignore') as f:
        lines = f.readlines()
        for i, line in enumerate(lines, 1):
            for rule in RULES:
                if re.search(rule['pattern'], line, re.IGNORECASE):
                    results.append({
                        'file': str(file_path),
                        'line': i,
                        'issue': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'rule_id': rule['id'],
                        'cwe': rule['cwe'],
                        'owasp': rule['owasp'],
                        'help_url': rule['help_url'],
                        'code': line.strip()
                    })
    return results

def scan_directory(path):
    all_results = []
    for subdir, _, files in os.walk(path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in VB6_EXTENSIONS):
                file_path = os.path.join(subdir, file)
                all_results.extend(scan_file(file_path))
    return all_results

def scan_input_path(path):
    path = Path(path)
    if path.is_dir():
        return scan_directory(path)
    elif path.is_file() and any(path.name.lower().endswith(ext) for ext in VB6_EXTENSIONS):
        return scan_file(path)
    else:
        print(f"Invalid file or directory: {path}")
        return []

def export_json(results, output_path):
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"JSON saved: {output_path}")

def export_sarif(results, output_path):
    sarif_output = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VB6 SAST Scanner",
                    "rules": [{
                        "id": rule['id'],
                        "name": rule['name'],
                        "shortDescription": { "text": rule['description'] },
                        "fullDescription": { "text": rule['description'] },
                        "helpUri": rule['help_url'],
                        "properties": {
                            "cwe": rule['cwe'],
                            "owasp": rule['owasp'],
                            "severity": rule['severity']
                        }
                    } for rule in RULES]
                }
            },
            "results": [{
                "ruleId": res['rule_id'],
                "level": res['severity'],
                "message": { "text": res['description'] },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": res['file'].replace("\\", "/") },
                        "region": {
                            "startLine": res['line']
                        }
                    }
                }]
            } for res in results]
        }]
    }
    with open(output_path, 'w') as f:
        json.dump(sarif_output, f, indent=2)
    print(f"SARIF saved: {output_path}")

def export_sonarqube_issues(results, output_path):
    severity_map = {
        "error": "CRITICAL",
        "warning": "MAJOR",
        "note": "MINOR"
    }
    
    sonar_issues = []
    for res in results:
        enriched_msg = f"{res['description']} (CWE: {res['cwe']}) See: {res['help_url']}"

        sonar_issues.append({
            "engineId": "vb6-sast",
            "ruleId": res['rule_id'],
            "severity": severity_map.get(res['severity'], "MAJOR"),
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": enriched_msg,
                "filePath": res['file'],
                "textRange": {
                    "startLine": res['line'],
                    "endLine": res['line']
                }
            }
        })
    with open(output_path, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"SonarQube JSON saved: {output_path}")

def parse_args():
    parser = argparse.ArgumentParser(description="VB6 SAST Scanner")
    parser.add_argument('--input', required=True, help="Path to VB6 file or directory to scan")
    parser.add_argument('--output-dir', default='.', help="Directory to write reports to")
    parser.add_argument('--formats', default='json,sarif,sonarqube', help="Comma-separated list of formats (json, sarif, sonarqube)")
    parser.add_argument('--report-name', default='vb6_sast_results', help="Base name for output files")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    results = scan_input_path(args.input)

    if not results:
        print("No issues found.")
        sys.exit(0)

    print(f"\n🔍 Found {len(results)} issues\n")
    for res in results:
        print(f"{res['file']} (Line {res['line']}): [{res['severity'].upper()}] {res['issue']}")
        print(f"  >> {res['code']}\n")

    formats = [f.strip().lower() for f in args.formats.split(',')]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if 'json' in formats:
        export_json(results, output_dir / f"{args.report_name}.json")
    if 'sarif' in formats:
        export_sarif(results, output_dir / f"{args.report_name}.sarif")
    if 'sonarqube' in formats:
        export_sonarqube_issues(results, output_dir / f"{args.report_name}_sonarqube.json")
