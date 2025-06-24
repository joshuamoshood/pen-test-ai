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


def read_project_files(
    project_dir,
    allowed_extensions=(".py", ".js", ".html", ".ts", ".css"),
    ignore_dirs=("venv", "node_modules", ".git"),
    max_file_size_kb=100
):
    """
    Recursively read files with allowed extensions, skipping ignored directories,
    and include line numbers for each line.
    """
    contents = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for filename in files:
            if filename.endswith(allowed_extensions):
                file_path = os.path.join(root, filename)
                try:
                    if os.path.getsize(file_path) > max_file_size_kb * 1024:
                        continue

                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    numbered_lines = [
                        f"{str(i + 1).rjust(4)} | {line.rstrip()}" for i, line in enumerate(lines)
                    ]

                    file_content = f"File: {file_path}\n" + "\n".join(numbered_lines) + "\n\n"
                    contents.append(file_content)

                except Exception as e:
                    contents.append(f"File: {file_path}\n[Error reading file: {e}]\n\n")

    return "\n".join(contents)


def create_security_agents():
    """Create AutoGen agents using Ollama models"""
    
    config_list = [
        {
            "model": "phi4-mini:latest",
            "base_url": "http://localhost:11434/v1",  # change this url for windows to http://localhost:11434/api 
            "api_type": "ollama"
        }
    ]

    # Create the assistant agent for security scanning
    security_assistant = autogen.AssistantAgent(
        name="security_expert",
        system_message = """
You are a security analyst tasked with producing structured JSON vulnerability reports for developers.

OUTPUT FORMAT REQUIREMENTS:
Return the output ONLY as valid JSON with the following structure:

{
  "high": [
    {
      "id": 1,
      "file": "<relative_file_path_or_N/A>",
      "action": "<concise combined description and fix>"
    }
  ],
  "medium": [
    {
      "id": 1,
      "file": "<relative_file_path_or_N/A>",
      "action": "<concise combined description and fix>"
    }
  ],
  "low": [
    {
      "id": 1,
      "file": "<relative_file_path_or_N/A>",
      "action": "<concise combined description and fix>"
    }
  ]
}

RULES:
- Classify each finding into one of the three groups: "high", "medium", or "low".
  - "high": severe issues like authentication flaws, injection risks, missing access control, or critical misconfigurations.
  - "medium": issues like weak headers, CSP absence, insecure defaults, or improper error exposure.
  - "low": minor issues or best practices, like missing caching headers or informational leaks.
- For each item:
  - Use a sequential integer for the "id", starting from 1 within each severity group.
  - Extract the file path from the `affected_urls` (use the path portion of the first URL). If unavailable, use "N/A".
  - The "action" should summarize both the issue and the recommended fix in a single sentence, developer-readable.
- DO NOT return any text, markdown, explanations, or comments outside of the JSON object.
""",
        llm_config={
            "config_list": config_list,
            "cache_seed": 99
        }
    )

    # Create the user proxy agent
    user_proxy = autogen.UserProxyAgent(
        name="user_proxy",
        system_message="SECURITY REPORT SENDER - NO CONVERSATION - TECHNICAL DATA ONLY",
        human_input_mode="NEVER",
        code_execution_config=False,
        llm_config={
            "config_list": config_list,
            "cache_seed": 99
        }
    )

    return security_assistant, user_proxy

def extract_vuln_sections(response_str):
    sections = {
        "critical": "",
        "medium": "",
        "actions": ""
    }

    # # Regexes to capture each section
    critical_match = re.search(r'\d*\.*\s*CRITICAL VULNERABILITIES:\s*(.*?)(?=\n\s*\d*\.*\s*(MEDIUM VULNERABILITIES:|IMMEDIATE ACTIONS:|$))',
                response_str, re.DOTALL | re.IGNORECASE)
    medium_match = re.search(r'\d*\.*\s*MEDIUM VULNERABILITIES:\s*(.*?)(?=\n\s*\d*\.*\s*(IMMEDIATE ACTIONS:|$))',
                response_str, re.DOTALL | re.IGNORECASE)
    action_match = re.search(r'\d*\.*\s*IMMEDIATE ACTIONS:\s*(.*?)(?=\n[-=]{3,}|$)',
                response_str, re.DOTALL | re.IGNORECASE)


    def clean_text(text):
        # Remove newlines and sequences of - or =, replace them with a single space
        text = re.sub(r'[\n\r]+', ' ', text)                # replace all line breaks with space
        text = re.sub(r'[-=]{2,}', ' ', text)               # replace sequences of - or = with space
        text = re.sub(r'[\/|]+', '', text)                   # remove slashes / and pipes |
        text = re.sub(r'\s+', ' ', text)                    # collapse multiple spaces into one
        # Optional: reduce repeated "DO NOT CHANGE ANY OTHER LINE." to one occurrence
        text = re.sub(r'(DO NOT CHANGE ANY OTHER LINE\.)+', 'DO NOT CHANGE ANY OTHER LINE.', text)
        return text.strip()

    if critical_match:
        sections["critical"] = clean_text(critical_match.group(1))
    if medium_match:
        sections["medium"] = clean_text(medium_match.group(1))
    if action_match:
        sections["actions"] = clean_text(action_match.group(1))

    return sections

def normalize_to_severity_format(critical_text, medium_text, actions_text):
    def build_entries(severity_text, file_fallback, start_id=1):
        if not severity_text:
            return []

        return [
            {
                "id": idx + start_id,
                "file": file_fallback,
                "action": sentence.strip()
            }
            for idx, sentence in enumerate(re.split(r'(?<=\.)\s+', severity_text.strip()))
            if sentence
        ]

    # Example fallback file path (replace with real extraction logic if needed)
    fallback_file = "src/app/guards/auth.guard.ts"

    formatted_json = {
        "high": build_entries(critical_text, fallback_file),
        "medium": build_entries(medium_text, fallback_file),
        "low": build_entries(actions_text, fallback_file)
    }
    return formatted_json

def run_security_scan(target_url: str, scan_type: str, project_code, report_path: str = None):
    """
    Run security scan and/or analyze existing report.
    Returns structured analysis including vulnerabilities and actions.
    """
    # if not report_path:
    #     ensure_ollama_models()

    # console.print(f"[bold green]{'Analyzing saved report' if report_path else 'Starting security scan for ' + (target_url or 'N/A')}[/bold green]")

    try:
        if report_path:
            # with open(report_path, 'r') as f:
            #     report_content = json.load(f)
            report_content = report_path

            # findings = report_content.get('findings', [])
            findings = report_content.get("data", {}).get("findings", [])
            risk_levels = {"high": 0, "medium": 0, "low": 0, "informational": 0}

            for f in findings:
                risk = f.get('risk_level', '').lower()
                if risk in risk_levels:
                    risk_levels[risk] += 1

            security_assistant, user_proxy = create_security_agents()

            raw_findings_json = json.dumps([
                {
                    'id': f'VULN-{i+1:03d}',
                    'risk': f['risk_level'],
                    'name': f['name'],
                    'description': f['description'],
                    # 'url': f['url'],
                    'affected_urls': f['affected_urls'],
                    'solution': f['solution']
                }
                for i, f in enumerate(findings)
            ], indent=2)

            report_summary = f"""SECURITY_ANALYSIS_REQUEST
==========================
TARGET: {target_url if target_url else 'N/A'}
SCAN_TYPE: {scan_type}
TOTAL_VULNERABILITIES: {len(findings)}

STATISTICS:
- HIGH: {risk_levels['high']}
- MEDIUM: {risk_levels['medium']}
- LOW: {risk_levels['low']}
- INFO: {risk_levels['informational']}

RAW_FINDINGS:
{raw_findings_json}

- PROJECT_CODE:
{project_code}

ONLY RETURN:
------------------------
1. CRITICAL VULNERABILITIES
2. MEDIUM VULNERABILITIES
3. IMMEDIATE ACTIONS

DO NOT INCLUDE ANY OTHER CONTENT OR DISCUSSION.
=========================="""

            try:
                import threading, _thread

                # result = {"critical": "", "medium": "", "actions": ""}
                result = {}
                def timeout_handler():
                    _thread.interrupt_main()

                timer = threading.Timer(300.0, timeout_handler)
                timer.start()

                try:
                    response = user_proxy.initiate_chat(
                        security_assistant,
                        message=report_summary,
                        max_turns=1
                    )
                    timer.cancel()
                    
                    if not response:
                        return {"status": "error", "message": "No analysis generated."}

                    # Extract sections using regex or delimiters (basic split)
                    content = response.chat_history[-1]["content"]
                    return content
                    # sections = extract_vuln_sections(content)
                    # result.update(sections)
                    ################
                    # converted = normalize_to_severity_format(
                    #                 critical_text=sections.get("critical", ""),
                    #                 medium_text=sections.get("medium", ""),
                    #                 actions_text=sections.get("actions", "")
                    #                 )
                    # print(json.dumps(converted, indent=2))
                    # return JSONResponse(content=converted)
                    
                    ################
                    return result
                except KeyboardInterrupt:
                    timer.cancel()
                    return {"status": "timeout", "message": "Analysis timed out after 5 minutes."}

            except Exception as e:
                return {"status": "error", "message": f"Analysis failed: {str(e)}"}

        else:
            # No report path: run scan first, then re-analyze
            scanner = SecurityScanner(target_url, scan_type)
            generated_report_path = scanner.perform_scan()
            if not generated_report_path:
                return {"status": "error", "message": "Scan failed or was aborted."}

            # Read project code again in case changes occurred
            updated_code = read_project_files(os.path.abspath("../renewable-energy-app-main"))
            return run_security_scan(target_url, scan_type, updated_code, generated_report_path)

    except FileNotFoundError:
        return {"status": "error", "message": f"Report file not found: {report_path}"}
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON in report file."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

