import os
import autogen
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress
from zapv2 import ZAPv2
import argparse
import json
from datetime import datetime
from scanner import VulnerabilityScanner, EthicalScanner
from fastapi.responses import JSONResponse
import subprocess
import re
# Load environment variables
load_dotenv()

console = Console()

def ensure_ollama_models():
    """Ensure required Ollama models are pulled"""
    required_models = ['deepseek-coder:6.7b', 'phi']
    
    console.print("[yellow]Checking for required Ollama models...[/yellow]")
    for model in required_models:
        try:
            # Check if model exists
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            if model not in result.stdout:
                console.print(f"[yellow]Pulling {model}...[/yellow]")
                subprocess.run(['ollama', 'pull', model], check=True)
            else:
                console.print(f"[green]Model {model} already available[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error pulling model {model}: {e}[/red]")
            exit(1)

class SecurityConfig:
    def __init__(self):
        self.max_requests_per_second = int(os.getenv('MAX_REQUESTS_PER_SECOND', 2))
        self.scan_timeout = int(os.getenv('SCAN_TIMEOUT', 3600))
        self.respect_robots_txt = os.getenv('RESPECT_ROBOTS_TXT', 'true').lower() == 'true'
        self.allowed_domains = os.getenv('ALLOWED_DOMAINS', '').split(',')
        self.max_depth = int(os.getenv('MAX_DEPTH', 3))
        self.exclude_paths = os.getenv('EXCLUDE_PATHS', '').split(',')

class SecurityScanner:
    def __init__(self, target_url, scan_type):
        self.target_url = target_url
        self.scan_type = scan_type
        self.config = SecurityConfig()
        self.zap = None
        self.vulnerability_scanner = None
        self.ethical_scanner = EthicalScanner(self.config)
        self.setup_zap()

    def setup_zap(self):
        """Initialize OWASP ZAP connection"""
        try:
            self.zap = ZAPv2(
                apikey=os.getenv('ZAP_API_KEY'),
                proxies={'http': f'http://localhost:{os.getenv("ZAP_PORT")}', 
                        'https': f'http://localhost:{os.getenv("ZAP_PORT")}'}
            )
            # Initialize vulnerability scanner with ZAP instance
            self.vulnerability_scanner = VulnerabilityScanner(self.zap, self.config)
            console.print("[green]Successfully connected to OWASP ZAP[/green]")
        except Exception as e:
            console.print(f"[red]Error connecting to ZAP: {e}[/red]")
            console.print("[yellow]Make sure OWASP ZAP is running and the API key is correctly set in .env[/yellow]")
            exit(1)

    def perform_scan(self):
        """Execute the security scan"""
        if not self.ethical_scanner.validate_target(self.target_url):
            console.print("[red]Target validation failed. Aborting scan.[/red]")
            return None

        try:
            findings = self.vulnerability_scanner.scan_for_vulnerabilities(self.target_url)
            report_path = self.vulnerability_scanner.generate_report(
                findings, 
                os.getenv('REPORT_OUTPUT_DIR', './reports')
            )
            return report_path
        except Exception as e:
            console.print(f"[red]Error during scan: {e}[/red]")
            return None

def get_relevant_files(findings, project_dir):
    """
    Map ZAP findings to potentially relevant source files.
    Returns a dict mapping finding IDs to relevant file contents.
    """
    relevant_files = {}
    file_contents = list(read_project_files(project_dir))
    for finding in findings:
        finding_id = finding.get('id')
        name = finding.get('name', '').lower()
        risk = finding.get('risk_level', '').lower()
        
        # Map informational findings to low severity
        if risk == 'informational':
            relevant_files[finding_id] = []  # No files for informational
            continue
        
        file_patterns = {
            "sql injection": ["db", "database", "query", "sql", "model"],
            "xss": ["template", "render", "html", "view", "response"],
            "csrf": ["form", "post", "submit", "controller", "token"],
            "authentication": ["auth", "login", "session", "user", "jwt"],
            "idor": ["controller", "route", "param", "url", "object"],
            "security headers": ["middleware", "headers", "response", "server"],
            "sensitive data exposure": ["config", "credentials", "env", "settings"],
            "logging": ["log", "logger", "error", "print"],
        }
        relevant = []
        for pattern, keywords in file_patterns.items():
            if any(word in name.lower() for word in pattern.lower().split()):
                for content in file_contents:
                    if any(keyword in content.lower() for keyword in keywords):
                        relevant.append(content)
                break
        # mapping
        # file_patterns = {
        #     'sql injection': ['database', 'query', 'sql'],
        #     'xss': ['template', 'html', 'js', 'view'],
        #     'authentication': ['auth', 'login', 'session'],
        #     'csrf': ['form', 'post', 'controller'],
        #     'user agent fuzzer': ['middleware', 'request', 'handler']
        # }
        # relevant = []
        # for pattern, keywords in file_patterns.items():
        #     if pattern in name:
        #         for content in file_contents:
        #             if any(keyword in content.lower() for keyword in keywords):
        #                 relevant.append(content)
        #         break
        relevant_files[finding_id] = relevant if relevant else file_contents[:2]
    return relevant_files

def read_project_files(
    project_dir,
    allowed_extensions=(".py", ".js", ".html", ".ts", ".css"),
    ignore_dirs=("venv", "node_modules", ".git"),
    max_file_size_kb=100
):
    """
    Yield file contents one at a time with line numbers.
    """
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for filename in files:
            if filename.endswith(allowed_extensions):
                file_path = os.path.join(root, filename)
                try:
                    if os.path.getsize(file_path) > max_file_size_kb * 1024:
                        console.print(f"[yellow]Skipping large file: {file_path} ({os.path.getsize(file_path)/1024:.1f} KB)[/yellow]")
                        continue
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    numbered_lines = [
                        f"{str(i + 1).rjust(4)} | {line.rstrip()}" for i, line in enumerate(lines)
                    ]
                    file_content = f"File: {file_path}\n" + "\n".join(numbered_lines) + "\n\n"
                    yield file_content
                except Exception as e:
                    yield f"File: {file_path}\n[Error reading file: {e}]\n\n"

def create_security_agents():
    """Create AutoGen agents using Ollama models"""
    config_list = [
        {
            "model": "phi4-mini:latest",
            "base_url": "http://localhost:11434/v1",
            "api_type": "ollama",
            "max_tokens": 4096,
            "temperature": 0.3  # Lower for deterministic output
        }
    ]

    # Updated system message
    security_assistant = autogen.AssistantAgent(
        name="security_expert",
        system_message="""
You are a security analyst tasked with producing structured JSON vulnerability reports for developers.
Analyze the provided ZAP findings and project code, then return a JSON object with the following structure:

{
  "high": [
    {
      "id": "<The corresponding id of the vulnerability>",
      "file": "<file path of the affected project file or N/A>",
      "action": "<Detailed description and fix>"
    }
  ],
  "medium": [
    {
      "id": "<The corresponding id of the vulnerability>",
      "file": "<file path of the affected project file or N/A>",
      "action": "<Detailed description and fix>"
    }
  ],
  "low": [
    {
      "id": "<The corresponding id of the vulnerability>",
      "file": "<file path of the affected project file or N/A>",
      "action": "<Detailed description and fix>"
    }
  ]
}

RULES:
- Classify each finding into one of three groups: "high", "medium", or "low".
  - "high": severe issues like authentication flaws, injection risks, missing access control, or critical misconfigurations.
  - "medium": issues like weak headers, CSP absence, insecure defaults, or improper error exposure.
  - "low": minor issues or best practices, like missing caching headers or informational leaks.
- For each item:
  - Use the finding's 'id' (e.g., 'VULN-001') as the 'id'.
  - Extract the file path from the provided PROJECT_CODE (files listed after "File:") or use "N/A" if no file is identified.
  - The 'action' must combine the issue description and recommended fix in one sentence, referencing line numbers if available.
- Return ONLY the JSON object, with no additional text, markdown, explanations, or comments.
- Example output for a finding:
  {
    "high": [],
    "medium": [
      {
        "id": "VULN-001",
        "file": "templates/index.html",
        "action": "XSS vulnerability in user input at line 15; use Jinja2 autoescaping or bleach library."
      }
    ],
    "low": []
  }
""",
        llm_config={
            "config_list": config_list,
            "cache_seed": 44
        }
    )

    user_proxy = autogen.UserProxyAgent(
        name="user_proxy",
        system_message="SECURITY REPORT SENDER - NO CONVERSATION - TECHNICAL DATA ONLY",
        human_input_mode="NEVER",
        code_execution_config=False,
        llm_config={
            "config_list": config_list,
            "cache_seed": 44
        }
    )

    return security_assistant, user_proxy

def run_security_scan(target_url: str, scan_type: str, project_dir, report_path: dict = None, batch_size=5):
    """
    Run security scan and/or analyze existing report in batches.
    Expects project_dir to be a directory path.
    """
    if report_path:
        findings = report_path.get("data", {}).get("findings", [])
        #findings = report_path.get("findings", [])
        risk_levels = {"high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            risk = f.get('risk_level', '').lower()
            if risk in risk_levels:
                risk_levels[risk] += 1

        security_assistant, user_proxy = create_security_agents()
        relevant_files = get_relevant_files(findings, project_dir)
        result = {"high": [], "medium": [], "low": []}

        # Process findings in batches
        for i in range(0, len(findings), batch_size):
            batch_findings = findings[i:i + batch_size]
            raw_findings_json = json.dumps([
                {
                    'id': f['id'],
                    'risk': f['risk_level'],
                    'name': f['name'],
                    'description': f['description'],
                    'solution': f['solution']
                } for f in batch_findings
            ], indent=2)

            batch_prompt = f"""SECURITY_ANALYSIS_REQUEST
TARGET: {target_url or 'N/A'}
SCAN_TYPE: {scan_type}
TOTAL_VULNERABILITIES: {len(batch_findings)}
STATISTICS: {{'high': {risk_levels['high']}, 'medium': {risk_levels['medium']}, 'low': {risk_levels['low']}, 'info': {risk_levels['informational']}}}
RAW_FINDINGS:
{raw_findings_json}
OUTPUT FORMAT REQUIREMENTS:
{{
  "high": [...],
  "medium": [...],
  "low": [...]
}}
RULES:
- For each finding, use only these files:
"""
            for finding in batch_findings:
                finding_id = finding['id']
                files = relevant_files.get(finding_id, [])
                batch_prompt += f"Finding {finding_id}:\n{''.join(files)}\n"

            try:
                import threading, _thread
                def timeout_handler():
                    _thread.interrupt_main()

                timer = threading.Timer(600.0, timeout_handler)
                timer.start()

                response = user_proxy.initiate_chat(
                    security_assistant,
                    message=batch_prompt,
                    max_turns=1
                )
                timer.cancel()

                content = response.chat_history[-1]["content"]
                cleaned = re.sub(r"^```json\s*|\s*```$", "", content.strip(), flags=re.DOTALL)

                try:
                    batch_result = json.loads(cleaned)
                    # Validate JSON structure
                    if not isinstance(batch_result, dict) or not all(k in batch_result for k in ["high", "medium", "low"]):
                        raise ValueError("Invalid JSON structure: missing required keys")
                    for severity in ["high", "medium", "low"]:
                        for item in batch_result[severity]:
                            if not all(k in item for k in ["id", "file", "action"]):
                                raise ValueError(f"Invalid item in {severity}: missing required fields")
                    # Merge batch results
                    for severity in ["high", "medium", "low"]:
                        result[severity].extend(batch_result[severity])
                except json.JSONDecodeError as e:
                    console.print(f"[red]Error parsing JSON in batch {i//batch_size + 1}: {str(e)}[/red]")
                    console.print(f"[yellow]Raw response: {content}[/yellow]")
                    continue
                except ValueError as e:
                    console.print(f"[red]Validation error in batch {i//batch_size + 1}: {str(e)}[/red]")
                    console.print(f"[yellow]Raw response: {content}[/yellow]")
                    continue

            except Exception as e:
                console.print(f"[red]Error processing batch {i//batch_size + 1}: {str(e)}[/red]")
                continue

        return result

    else:
        scanner = SecurityScanner(target_url, scan_type)
        generated_report_path = scanner.perform_scan()
        if not generated_report_path:
            return {"status": "error", "message": "Scan failed or was aborted."}
        return run_security_scan(target_url, scan_type, project_dir, generated_report_path)