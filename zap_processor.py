import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any
import os
from zapv2 import ZAPv2
import requests
import sys
import time
import threading
import _thread
import re
from rich.console import Console
from dotenv import load_dotenv
from urllib.parse import urlparse
import autogen
import subprocess

# Load environment variables
load_dotenv()

console = Console()

def ensure_ollama_models():
    """Ensure required Ollama models are pulled"""
    required_models = ['phi4-mini:latest']
    
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
            sys.exit(1)

class SecurityExpert:
    def __init__(self):
        # Ensure required models are available
        # ensure_ollama_models()
        
        ollama_port = os.getenv("OLLAMA_PORT", "11434")
        
        config_list = [
            {
                "model": "phi4-mini:latest",
                "base_url": f"http://ollama:{ollama_port}/api",
                "api_type": "ollama"
            }
        ]

        # Create the assistant for security analysis
        self.assistant = autogen.AssistantAgent(
            name="security_expert",
            system_message="""You are a Security Expert specialized in vulnerability analysis and CVE/CWE mapping.
Your task is to analyze vulnerability descriptions and provide accurate CVE/CWE mappings.

RESPONSE FORMAT:
{
    "cwe": "CWE-XXX",
    "cwe_name": "Name of the weakness",
    "cve_examples": ["CVE-YYYY-XXXXX", ...],  // Up to 3 recent, relevant CVEs
    "confidence": "HIGH|MEDIUM|LOW",
    "explanation": "Brief explanation of the mapping"
}

RULES:
1. Only respond with valid JSON
2. If unsure about CVE/CWE, set confidence as "LOW"
3. Provide most relevant and recent CVEs
4. Focus on accuracy over completeness
5. If no mapping found, return empty strings but maintain format
6. Keep responses concise and focused on technical details""",
            llm_config={
                "config_list": config_list,
                "cache_seed": 42
            }
        )

        # Create the user proxy
        self.user_proxy = autogen.UserProxyAgent(
            name="user_proxy",
            system_message="VULNERABILITY MAPPING - NO CONVERSATION - TECHNICAL DATA ONLY",
            human_input_mode="NEVER",
            code_execution_config=False,
            llm_config={
                "config_list": config_list,
                "cache_seed": 42
            }
        )

    def get_vulnerability_mapping(self, vuln_name: str, description: str) -> Dict[str, Any]:
        """Get CVE/CWE mapping for a vulnerability using LLM"""
        try:
            query = f"""Analyze this vulnerability and provide CVE/CWE mapping:
Name: {vuln_name}
Description: {description}

Provide mapping in the specified JSON format."""

            def timeout_handler():
                _thread.interrupt_main()
            
            timer = threading.Timer(300.0, timeout_handler)
            timer.start()

            try:
                chat_response = self.user_proxy.initiate_chat(
                    self.assistant,
                    message=query,
                    max_turns=1
                )

                # 💡 Get the actual text from the LLM reply
                try:
                    # Autogen v0.2 or newer structure
                    response_text = chat_response.chat_history[-1]["content"]
                except (AttributeError, IndexError, TypeError):
                    # Fallback: try another method
                    try:
                        response_text = chat_response.summary or chat_response.last_message().content
                    except Exception:
                        response_text = str(chat_response)

                # 🧠 Log the LLM response (debugging)
                console.print(f"[dim]LLM Response:\n{response_text}[/dim]")

                # Try parsing from a ```json block
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1).strip()
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError as e:
                        console.print(f"[yellow]Warning: JSON parse error in code block: {str(e)}[/yellow]")

                # Fallback: find raw JSON-like object in text
                json_pattern = r'\{\s*"cwe"\s*:\s*".*?",\s*"cwe_name"\s*:\s*".*?",\s*"cve_examples"\s*:\s*\[.*?\],\s*"confidence"\s*:\s*".*?",\s*"explanation"\s*:\s*".*?"\s*\}'
                json_match = re.search(json_pattern, response_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0).strip()
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError as e:
                        console.print(f"[yellow]Warning: JSON parse error in raw text: {str(e)}[/yellow]")

            except KeyboardInterrupt:
                console.print("[yellow]Warning: LLM response timed out[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Warning: Error in LLM processing: {str(e)}[/yellow]")
            finally:
                timer.cancel()

            # Default response if nothing worked
            return {
                "cwe": "",
                "cwe_name": "",
                "cve_examples": [],
                "confidence": "LOW",
                "explanation": "Failed to get mapping"
            }
        except Exception as e:
            console.print(f"[yellow]Warning: Error getting vulnerability mapping: {str(e)}[/yellow]")
            return {
                "cwe": "",
                "cwe_name": "",
                "cve_examples": [],
                "confidence": "LOW",
                "explanation": f"Error: {str(e)}"
            }


class VulnerabilityProcessor:
    def __init__(self, target_url: str):
        self.vulnerability_counter = 0
        self.target_domain = urlparse(target_url).netloc
        console.print(f"[dim]Target domain: {self.target_domain}[/dim]")
        self.security_expert = SecurityExpert()
        
    def generate_vuln_id(self) -> str:
        """Generate a unique vulnerability ID"""
        self.vulnerability_counter += 1
        return f"VULN-{self.vulnerability_counter:03d}"

    def normalize_risk_level(self, risk: str) -> str:
        """Normalize risk levels from ZAP to standard format"""
        # ZAP uses these risk levels:
        # 0: Informational
        # 1: Low
        # 2: Medium
        # 3: High
        risk_mapping = {
            0: "Informational",
            1: "Low",
            2: "Medium",
            3: "High",
            "0": "Informational",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            # Keep original text values if provided
            "Informational": "Informational",
            "Low": "Low",
            "Medium": "Medium",
            "High": "High"
        }
        
        # Try to convert to int first if it's a string number
        try:
            if isinstance(risk, str) and risk.isdigit():
                risk = int(risk)
        except (ValueError, TypeError):
            pass
            
        return risk_mapping.get(risk, str(risk))  # Return the original value if not in mapping

    def is_target_domain(self, url: str) -> bool:
        """Check if the URL belongs to the target domain"""
        try:
            url_domain = urlparse(url).netloc
            return url_domain == self.target_domain or url_domain.endswith('.' + self.target_domain)
        except Exception:
            return False

    def group_findings(self, zap_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Group findings by vulnerability name and solution"""
        grouped_findings = defaultdict(lambda: {
            "urls": set(),
            "risk_level": "",
            "description": "",
            "solution": "",
            "reference": "",
            "cwe": "",
            "cwe_link": "",
            "count": 0
        })

        skipped_urls = set()
        for alert in zap_results:
            url = alert.get("url", "")
            if not self.is_target_domain(url):
                skipped_urls.add(url)
                continue

            key = f"{alert['name']}_{alert['solution']}"
            original_risk = alert.get("risk")
            normalized_risk = self.normalize_risk_level(original_risk)
            
            # Extract CWE info from ZAP
            cwe_id = alert.get('cweid')
            cwe_link = ""
            if cwe_id and cwe_id != '-1':
                cwe_id = f"CWE-{cwe_id}"
                # Try to get the CWE link from tags
                tags = alert.get('tags', {})
                cwe_link = tags.get(cwe_id, "")
            else:
                cwe_id = ""  # Clear invalid CWE IDs
            
            grouped_findings[key]["urls"].add(url)
            grouped_findings[key]["risk_level"] = normalized_risk
            grouped_findings[key]["description"] = alert["description"]
            grouped_findings[key]["solution"] = alert["solution"]
            grouped_findings[key]["reference"] = alert.get("reference", "")
            grouped_findings[key]["cwe"] = cwe_id
            grouped_findings[key]["cwe_link"] = cwe_link
            grouped_findings[key]["count"] += 1
            grouped_findings[key]["name"] = alert["name"]

        if skipped_urls:
            console.print(f"[yellow]Skipped {len(skipped_urls)} URLs not belonging to target domain[/yellow]")
            console.print("[dim]Skipped URLs examples (up to 5):[/dim]")
            for url in list(skipped_urls)[:5]:
                console.print(f"[dim] - {url}[/dim]")

        return grouped_findings

    def calculate_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate summary statistics from findings"""
        risk_distribution = defaultdict(int)
        for finding in findings:
            risk_distribution[finding["risk_level"]] += 1

        return {
            "total_findings": sum(risk_distribution.values()),
            "unique_vulnerabilities": len(findings),
            "risk_distribution": dict(risk_distribution),
            "scan_timestamp": datetime.now().isoformat()
        }

    def process_zap_results(self, zap_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process ZAP results into normalized format with grouping and stats"""
        grouped_findings = self.group_findings(zap_results)
        
        processed_findings = []
        total_findings = len(grouped_findings)
        
        console.print("\n[yellow]Enriching vulnerability data with CVE/CWE mappings...[/yellow]")
        with console.status("[bold green]Processing vulnerabilities...") as status:
            for i, (_, finding_data) in enumerate(grouped_findings.items(), 1):
                status.update(f"[bold green]Processing vulnerability {i}/{total_findings}...")
                
                # Get CWE from ZAP or LLM as fallback
                cwe = finding_data["cwe"]
                cwe_link = finding_data.get("cwe_link", "")
                
                # If ZAP didn't provide a CWE, try LLM
                if not cwe:
                    mapping = self.security_expert.get_vulnerability_mapping(
                        finding_data["name"],
                        finding_data["description"]
                    )
                    cwe = mapping["cwe"]
                
                processed_finding = {
                    "id": self.generate_vuln_id(),
                    "name": finding_data["name"],
                    "risk_level": finding_data["risk_level"],
                    "description": finding_data["description"],
                    "solution": finding_data["solution"],
                    "reference": finding_data["reference"],
                    "cwe": cwe,
                    "cwe_link": cwe_link,
                    "affected_urls": list(finding_data["urls"]),
                    "occurrence_count": finding_data["count"],
                    "tags": self.generate_tags(finding_data)
                }
                processed_findings.append(processed_finding)

        # Sort findings by risk level
        risk_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        processed_findings.sort(key=lambda x: risk_order.get(x["risk_level"], 4))

        return {
            "findings": processed_findings,
            "summary": self.calculate_stats(processed_findings)
        }

    def generate_tags(self, finding_data: Dict[str, Any]) -> List[str]:
        """Generate relevant tags for a finding"""
        tags = []
        
        # Add risk level tag
        tags.append(f"risk:{finding_data['risk_level'].lower()}")
        
        # Add category tags based on vulnerability name
        if "XSS" in finding_data["name"]:
            tags.append("category:injection")
        elif "SQL" in finding_data["name"]:
            tags.append("category:injection")
            tags.append("category:database")
        elif "Header" in finding_data["name"]:
            tags.append("category:headers")
        elif "Authentication" in finding_data["name"]:
            tags.append("category:authentication")
        
        # Add CWE tag if available from LLM mapping
        if finding_data.get("cwe"):
            tags.append(f"cwe:{finding_data['cwe']}")
            
        return tags

def save_report(report_data: Dict[str, Any], output_dir: str) -> str:
    """Save the processed report to a JSON file"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"security_report_{timestamp}.json")
    
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    return report_path

def generate_html_report(zap: ZAPv2, target_url: str, output_dir: str) -> str:
    """Generate HTML report using ZAP's core.htmlreport method"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(output_dir, f"zap_report_{timestamp}.html")
    
    try:
        html_report = zap.core.htmlreport()
        with open(html_path, 'w') as f:
            f.write(html_report)
        console.print(f"[green]HTML report saved to: {html_path}[/green]")
        return html_path
        
    except Exception as e:
        console.print(f"[yellow]Warning: Could not generate HTML report: {str(e)}[/yellow]")
        return None

def check_rate_limit(max_requests_per_second: int = 2):
    """Implement rate limiting"""
    time.sleep(1.0 / max_requests_per_second)

def save_raw_findings(findings: List[Dict[str, Any]], output_dir: str) -> str:
    """Save the raw ZAP findings before processing"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_report_path = os.path.join(output_dir, f"raw_findings_{timestamp}.json")
    
    with open(raw_report_path, 'w') as f:
        json.dump(findings, f, indent=2)
    
    console.print(f"[green]Raw findings saved to: {raw_report_path}[/green]")
    return raw_report_path

def process_raw_findings(raw_findings_path: str, target_url: str, output_dir: str = "reports") -> str:
    """Process existing raw findings file with CVE/CWE mapping"""
    try:
        with open(raw_findings_path, 'r') as f:
            alerts = json.load(f)
        
        # Process results
        processor = VulnerabilityProcessor(target_url)
        report_data = processor.process_zap_results(alerts)
        
        # Save report
        report_path = save_report(report_data, output_dir)
        console.print(f"[green]Processed report saved to: {report_path}[/green]")
        
        return report_path
        
    except FileNotFoundError:
        console.print(f"[red]Error: Raw findings file not found: {raw_findings_path}[/red]")
        raise FileNotFoundError(f"Raw findings file not found: {raw_findings_path}")
    except json.JSONDecodeError:
        console.print(f"[red]Error: Invalid JSON in raw findings file: {raw_findings_path}[/red]")
        raise ValueError(f"Invalid JSON in raw findings file: {raw_findings_path}")
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")
        raise

def process_zap_scan(target_url: str, output_dir: str = "reports", save_raw: bool = True) -> tuple:
    """Main function to process ZAP scan and generate report"""
    try:
        # Initialize ZAP connection
        zap = ZAPv2(
            apikey=os.getenv('ZAP_API_KEY', '12345'),
            proxies={
                'http': f'http://zap:{os.getenv("ZAP_PORT", "8080")}',
                'https': f'http://zap:{os.getenv("ZAP_PORT", "8080")}'
            }
        )
        
        console.print("[yellow]Starting vulnerability scan...[/yellow]")
        
        # Start spidering the target
        console.print("Starting spider scan...")
        scan_id = zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(zap.spider.status(scan_id)) < 100:
            check_rate_limit()
            console.print(f"Spider progress: {zap.spider.status(scan_id)}%")
        
        # Perform active scan
        console.print("Starting active scan...")
        scan_id = zap.ascan.scan(target_url)
        
        # Wait for active scan to complete
        while int(zap.ascan.status(scan_id)) < 100:
            check_rate_limit()
            console.print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
        
        # Get all alerts
        alerts = zap.core.alerts()
        
        # Save raw findings if requested
        if save_raw:
            raw_report_path = save_raw_findings(alerts, output_dir)
            console.print(f"[green]Raw findings saved. To process them later, use: python {sys.argv[0]} --raw-findings {raw_report_path} --target {target_url}[/green]")
        
        # Process results
        processor = VulnerabilityProcessor(target_url)
        report_data = processor.process_zap_results(alerts)
        
        # Save JSON report
        report_path = save_report(report_data, output_dir)
        console.print(f"[green]Final report saved to: {report_path}[/green]")
        
        # Generate HTML report
        html_path = generate_html_report(zap, target_url, output_dir)
        
        return report_path, html_path
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error connecting to ZAP: {str(e)}[/red]")
        console.print("[yellow]Make sure OWASP ZAP is running and the port is correct[/yellow]")
        raise ConnectionError(f"Error connecting to ZAP: {str(e)}")
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Process ZAP scan results and generate normalized report')
    parser.add_argument('--target', required=True, help='Target URL that was scanned')
    parser.add_argument('--output-dir', default='reports', help='Directory to save the report')
    parser.add_argument('--raw-findings', help='Path to raw findings JSON file to process')
    parser.add_argument('--no-raw-save', action='store_true', help='Do not save raw findings')
    
    args = parser.parse_args()
    
    if args.raw_findings:
        process_raw_findings(args.raw_findings, args.target, args.output_dir)
    else:
        process_zap_scan(args.target, args.output_dir, not args.no_raw_save) 