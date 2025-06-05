import os
import autogen
from dotenv import load_dotenv
from rich.console import Console
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
    required_models = ['mixtral:latest']
    
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
            # Clear previous session and results
            self.zap.core.new_session(name="", overwrite=True)
            self.zap.alert.delete_all_alerts()
            
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
            "model": "mixtral:latest",
            "base_url": "http://localhost:11434/api",
            "api_type": "ollama"
        }
    ]

    # Create the assistant agent for security scanning
    security_assistant = autogen.AssistantAgent(
        name="security_expert",
        system_message="""CRITICAL INSTRUCTION: YOU MUST RESPOND WITH PURE JSON ONLY.

DO NOT ADD:
- NO markdown
- NO code blocks
- NO explanations
- NO text before or after JSON
- NO formatting

EXAMPLE RESPONSE FORMAT:
{
    "scan_metadata": {
        "timestamp": "2024-03-05T12:34:56Z",
        "target": "example.com",
        "scan_type": "basic"
    },
    "vulnerabilities": [
        {
            "id": "VULN-001",
            "name": "SQL Injection",
            "risk_level": "HIGH",
            "cwe_id": "CWE-89",
            "cve_refs": ["CVE-2024-1234"],
            "description": "SQL injection in login form",
            "replication_steps": [
                "1. Access /login endpoint",
                "2. Insert malicious payload"
            ],
            "fix": {
                "summary": "Use parameterized queries",
                "technical_steps": [
                    "1. Replace string concatenation with prepared statements",
                    "2. Implement input validation"
                ]
            }
        }
    ],
    "remediation_plan": {
        "critical": ["Deploy WAF"],
        "high": ["Update queries"],
        "medium": ["Add validation"],
        "low": ["Update docs"]
    }
}

REMEMBER: OUTPUT JSON ONLY. ANY OTHER FORMAT WILL BE REJECTED.""",
        llm_config={
            "config_list": config_list,
            "cache_seed": 42,
            "temperature": 0.1  # Lower temperature for more structured output
        }
    )

    # Create the user proxy agent
    user_proxy = autogen.UserProxyAgent(
        name="user_proxy",
        system_message="SECURITY REPORT SENDER - ENFORCE JSON OUTPUT ONLY",
        human_input_mode="NEVER",
        code_execution_config=False,
        llm_config={
            "config_list": config_list,
            "cache_seed": 42,
            "temperature": 0.1
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
            
            report_summary = f"""RESPOND WITH JSON ONLY. NO OTHER TEXT.

INPUT_DATA:
{json.dumps({
    'target': target_url,
    'scan_type': scan_type,
    'findings': [{
        'id': f'VULN-{i+1:03d}',
        'name': f['name'],
        'risk_level': f['risk_level'],
        'description': f['description'],
        'url': f['url'],
        'solution': f['solution']
    } for i, f in enumerate(report_content.get('findings', []))],
    'statistics': {
        'high': risk_levels['high'],
        'medium': risk_levels['medium'],
        'low': risk_levels['low'],
        'info': risk_levels['informational']
    }
}, indent=2)}"""

            try:
                import threading
                import _thread
                from datetime import datetime
                
                def timeout_handler():
                    _thread.interrupt_main()
                
                timer = threading.Timer(300.0, timeout_handler)
                timer.start()
                
                try:
                    # Get the chat history after analysis
                    chat_history = user_proxy.initiate_chat(
                        security_assistant,
                        message=report_summary,
                        max_turns=1
                    )
                    
                    if chat_history:
                        # Get the last message from the security assistant
                        messages = list(filter(
                            lambda x: x.get('role') == 'assistant' and x.get('name') == 'security_expert',
                            chat_history.chat_history
                        ))
                        
                        if messages:
                            # Clean up the message content
                            last_message = messages[-1].get('content', '').strip()
                            # Remove any markdown code block indicators
                            last_message = re.sub(r'^```json\s*|\s*```$', '', last_message, flags=re.MULTILINE)
                            last_message = last_message.strip()
                            
                            try:
                                # Try to parse the entire message as JSON
                                enhanced_report = json.loads(last_message)
                                
                                # Write enhanced report to new file
                                output_dir = os.path.dirname(report_path)
                                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                enhanced_report_path = os.path.join(
                                    output_dir, 
                                    f'enhanced_security_report_{timestamp}.json'
                                )
                                
                                with open(enhanced_report_path, 'w') as f:
                                    json.dump(enhanced_report, f, indent=2)
                                
                                console.print(f"[green]Enhanced security report written to: {enhanced_report_path}[/green]")
                            except json.JSONDecodeError:
                                console.print("[red]Invalid JSON in response.[/red]")
                                console.print("[yellow]Raw response:[/yellow]")
                                console.print(last_message)
                        else:
                            console.print("[red]No response from security expert.[/red]")
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