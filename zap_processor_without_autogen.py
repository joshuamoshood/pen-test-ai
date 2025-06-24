import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any
import os
from zapv2 import ZAPv2
import requests
import sys
import time
from rich.console import Console
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

console = Console()

class ZAPConnectionError(Exception):
    """Custom exception for ZAP connection issues"""
    pass

class VulnerabilityProcessor:
    def __init__(self, target_url: str):
        self.vulnerability_counter = 0
        self.target_domain = urlparse(target_url).netloc
        console.print(f"[dim]Target domain: {self.target_domain}[/dim]")
        self.cwe_mapping = {
            "Missing Anti-clickjacking Header": "CWE-1021",
            "X-Frame-Options Header Not Set": "CWE-1021",
            "Cross Site Scripting (XSS)": "CWE-79",
            "SQL Injection": "CWE-89",
            "Directory Browsing": "CWE-548",
            "Insecure Direct Object References": "CWE-639",
            "Server Side Request Forgery": "CWE-918"
        }
        
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
            console.print(f"[dim]Debug: Original risk: {original_risk} -> Normalized: {normalized_risk}[/dim]")
            
            grouped_findings[key]["urls"].add(url)
            grouped_findings[key]["risk_level"] = normalized_risk
            grouped_findings[key]["description"] = alert["description"]
            grouped_findings[key]["solution"] = alert["solution"]
            grouped_findings[key]["reference"] = alert.get("reference", "")
            grouped_findings[key]["cwe"] = self.cwe_mapping.get(alert["name"], "")
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
        for _, finding_data in grouped_findings.items():
            processed_finding = {
                "id": self.generate_vuln_id(),
                "name": finding_data["name"],
                "risk_level": finding_data["risk_level"],
                "description": finding_data["description"],
                "solution": finding_data["solution"],
                "reference": finding_data["reference"],
                "cwe": finding_data["cwe"],
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
        
        # Add CWE tag if available
        if finding_data["cwe"]:
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

def check_rate_limit(max_requests_per_second: int = 2):
    """Implement rate limiting"""
    time.sleep(1.0 / max_requests_per_second)

def process_zap_scan(target_url: str, output_dir: str = "reports") -> str:
    """Main function to process ZAP scan and generate report"""
    try:
        # Initialize ZAP connection
        zap = ZAPv2(
            apikey=os.getenv('ZAP_API_KEY', '12345'),
            proxies={
                'http': f'http://localhost:{os.getenv("ZAP_PORT", "8080")}',
                'https': f'http://localhost:{os.getenv("ZAP_PORT", "8080")}'
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
        
        # Process results
        processor = VulnerabilityProcessor(target_url)
        report_data = processor.process_zap_results(alerts)
        
        # Save report
        report_path = save_report(report_data, output_dir)
        console.print(f"[green]Report saved to: {report_path}[/green]")
        
        return report_path
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error connecting to ZAP: {str(e)}[/red]")
        console.print("[yellow]Make sure OWASP ZAP is running and the port is correct[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Process ZAP scan results and generate normalized report')
    parser.add_argument('--target', required=True, help='Target URL that was scanned')
    parser.add_argument('--output-dir', default='reports', help='Directory to save the report')
    
    args = parser.parse_args()
    
    process_zap_scan(args.target, args.output_dir) 