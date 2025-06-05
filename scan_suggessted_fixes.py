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

def create_security_agents():
    """Create AutoGen agents using Ollama models"""
    
    config_list = [
        {
            "model": "deepseek-coder:6.7b",
            "base_url": "http://localhost:11434/api",
            "api_type": "ollama"
        }
    ]

    # Create the assistant agent for security scanning
    security_assistant = autogen.AssistantAgent(
        name="security_expert",
        system_message="""SECURITY VULNERABILITY ANALYZER

OUTPUT FORMAT REQUIREMENTS:
------------------------
1. CRITICAL VULNERABILITIES:
   - ID: <vuln-id>
   - Description: <brief description>
   - Impact: <security impact>
   - Steps to Reproduce: <numbered steps>
   - Fix: <specific commands or code>
   - Timeline: <days to fix>

2. MEDIUM VULNERABILITIES:
   - Same format as above

3. IMMEDIATE ACTIONS:
   - Numbered list of urgent fixes

4. TIMELINE SUMMARY:
   - Day 1: <actions>
   - Day 2-3: <actions>
   - Day 4-7: <actions>

RULES:
1. ONLY use the above format
2. NO discussions or explanations
3. NO JSON examples or formatting
4. NO casual conversation
5. Focus ONLY on technical findings""",
        llm_config={
            "config_list": config_list,
            "cache_seed": 42
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

def run_security_scan(target_url: str, scan_type: str, report_path: str = None):
    """Main function to run the security scan"""
    if not report_path:
        ensure_ollama_models()
    
    console.print(f"[bold green]{'Analyzing saved report' if report_path else 'Starting security scan for ' + target_url}[/bold green]")
    
    try:
        if report_path:
            with open(report_path, 'r') as f:
                report_content = json.load(f)
                
            risk_levels = {"high": 0, "medium": 0, "low": 0, "informational": 0}
            for finding in report_content.get('findings', []):
                risk_level = finding['risk_level'].lower()
                if risk_level in risk_levels:
                    risk_levels[risk_level] += 1
                
            security_assistant, user_proxy = create_security_agents()
            
            report_summary = f"""SECURITY_ANALYSIS_REQUEST
==========================
TARGET: {target_url if target_url else 'N/A'}
SCAN_TYPE: {scan_type}
TOTAL_VULNERABILITIES: {len(report_content.get('findings', []))}

STATISTICS:
- HIGH: {risk_levels['high']}
- MEDIUM: {risk_levels['medium']}
- LOW: {risk_levels['low']}
- INFO: {risk_levels['informational']}

RAW_FINDINGS:
{json.dumps([{
    'id': f'VULN-{i+1:03d}',
    'risk': f['risk_level'],
    'name': f['name'],
    'description': f['description'],
    'url': f['url'],
    'solution': f['solution']
} for i, f in enumerate(report_content.get('findings', []))], indent=2)}

REQUIRED_RESPONSE_FORMAT:
------------------------
1. CRITICAL VULNERABILITIES
2. MEDIUM VULNERABILITIES
3. IMMEDIATE ACTIONS
4. TIMELINE SUMMARY

DO NOT INCLUDE ANY OTHER CONTENT OR DISCUSSION.
=========================="""

            try:
                import threading
                import _thread
                
                def timeout_handler():
                    _thread.interrupt_main()
                
                timer = threading.Timer(300.0, timeout_handler)
                timer.start()
                
                try:
                    response = user_proxy.initiate_chat(
                        security_assistant,
                        message=report_summary,
                        max_turns=1  # Limit to single response
                    )
                    
                    if response:
                        console.print("[green]Security analysis complete.[/green]")
                    else:
                        console.print("[yellow]No analysis generated. Please check the report file directly.[/yellow]")
                        
                except KeyboardInterrupt:
                    console.print("[red]Analysis timed out after 5 minutes.[/red]")
                    console.print(f"[yellow]Raw report available at: {report_path}[/yellow]")
                finally:
                    timer.cancel()
                    
            except Exception as e:
                console.print(f"[red]Analysis error: {str(e)}[/red]")
                console.print(f"[yellow]Raw report available at: {report_path}[/yellow]")
        else:
            scanner = SecurityScanner(target_url, scan_type)
            report_path = scanner.perform_scan()
            if not report_path:
                console.print("[red]Scan failed or was aborted.[/red]")
                return
            
            run_security_scan(target_url, scan_type, report_path)
            
    except FileNotFoundError:
        console.print(f"[red]Error: Report file not found: {report_path}[/red]")
    except json.JSONDecodeError:
        console.print(f"[red]Error: Invalid JSON in report file: {report_path}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def main():
    parser = argparse.ArgumentParser(description='AI-powered ethical web security scanner')
    parser.add_argument('--target', help='Target URL to scan')
    parser.add_argument('--scan-type', choices=['basic', 'full'], default='basic',
                      help='Type of scan to perform')
    parser.add_argument('--report', help='Path to existing report file to analyze')
    
    args = parser.parse_args()
    
    if not args.report and not args.target:
        console.print("[red]Error: Either --target or --report must be specified[/red]")
        return
    
    if args.target and not args.target.startswith(('http://', 'https://')):
        console.print("[red]Error: Target URL must start with http:// or https://[/red]")
        return
    
    run_security_scan(args.target, args.scan_type, args.report)

if __name__ == "__main__":
    main() 