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
        system_message="""SECURITY VULNERABILITY ANALYZER
        
You are a secure code specialist. Your sole task is to fix vulnerabilities based ONLY on the provided PROJECT_CODE and RAW_FINDINGS.

OUTPUT FORMAT REQUIREMENTS:
------------------------
1. CRITICAL VULNERABILITIES:
   - ID: <vuln-id>
   - Description: <brief description>
   - Impact: <security impact>
   - Steps to Reproduce: <numbered steps>
   - Fix: <specific commands or code>

2. MEDIUM VULNERABILITIES:
   - Same format as above

3. IMMEDIATE ACTIONS:
   - File: <path to the file from PROJECT_CODE>
   - Actions: <exact line numbers and fix instructions (code changes, additions, or deletions)>

RULES:
1. Follow ONLY the required format above.
2. DO NOT include explanations, justifications, summaries, or any extra text.
3. DO NOT include JSON, Markdown, or block formatting.
4. DO NOT reference anything outside of the provided PROJECT_CODE.
5. DO NOT modify or refer to any file that is not included in PROJECT_CODE.
6. DO NOT invent vulnerabilities — only respond to listed RAW_FINDINGS.
7. DO NOT repeat or include the full project code — only show the changed or added lines needed for the fix.""",
        llm_config={
            "config_list": config_list,
            "cache_seed": 50
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
            "cache_seed": 42
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
    critical_match = re.search(r'CRITICAL VULNERABILITIES:\n(.*?)(?=\n(?:MEDIUM|IMMEDIATE ACTIONS|$))', response_str, re.DOTALL)
    medium_match = re.search(r'MEDIUM VULNERABILITIES:\n(.*?)(?=\n(?:IMMEDIATE ACTIONS|$))', response_str, re.DOTALL)
    action_match = re.search(r'IMMEDIATE ACTIONS:\n(.*?)(?=\n[-=]{5,}|$)', response_str, re.DOTALL)
    

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


def run_security_scan(target_url: str, scan_type: str, project_code, report_path: str = None):
    """
    Run security scan and/or analyze existing report.
    Returns structured analysis including vulnerabilities and actions.
    """
    if not report_path:
        ensure_ollama_models()

    console.print(f"[bold green]{'Analyzing saved report' if report_path else 'Starting security scan for ' + (target_url or 'N/A')}[/bold green]")

    try:
        if report_path:
            with open(report_path, 'r') as f:
                report_content = json.load(f)

            findings = report_content.get('findings', [])
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
                    'url': f['url'],
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

                result = {"critical": "", "medium": "", "actions": ""}

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
                
                    # result["summary"] = content

                    sections = extract_vuln_sections(content)
                    result.update(sections)

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



def main():
    parser = argparse.ArgumentParser(description='AI-powered ethical web security scanner')
    parser.add_argument('--target', help='Target URL to scan')
    parser.add_argument('--scan-type', choices=['basic', 'full'], default='basic', help='Type of scan to perform')
    parser.add_argument('--report', help='Path to existing report file to analyze')
    parser.add_argument('--project-path', default='../renewable-energy-api-main', help='Path to the project source code')

    args = parser.parse_args()

    # Validation: at least target or report must be provided
    if not args.report and not args.target:
        console.print("[red]Error: Either --target or --report must be specified[/red]")
        return

    if args.target and not args.target.startswith(('http://', 'https://')):
        console.print("[red]Error: Target URL must start with http:// or https://[/red]")
        return

    # Read project code
    project_path = os.path.abspath(args.project_path)
    project_code = read_project_files(project_path)

    # Run scan
    result = run_security_scan(
        target_url=args.target,
        scan_type=args.scan_type,
        project_code=project_code,
        report_path=args.report
    )

    # Print formatted JSON result
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
