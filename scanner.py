import time
from typing import List, Dict
from rich.console import Console
from zapv2 import ZAPv2
import requests
import json
from datetime import datetime
import os

console = Console()

class VulnerabilityScanner:
    def __init__(self, zap: ZAPv2, config: dict):
        self.zap = zap
        self.config = config
        self.findings = []
        
    def check_rate_limit(self):
        """Implement rate limiting"""
        time.sleep(1.0 / self.config.max_requests_per_second)
    
    def scan_for_vulnerabilities(self, target_url: str) -> List[Dict]:
        """Main vulnerability scanning method"""
        console.print("[yellow]Starting vulnerability scan...[/yellow]")
        
        # Start spidering the target
        console.print("Starting spider scan...")
        scan_id = self.zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            self.check_rate_limit()
            console.print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
        
        # Perform active scan
        console.print("Starting active scan...")
        scan_id = self.zap.ascan.scan(target_url)
        
        # Wait for active scan to complete
        while int(self.zap.ascan.status(scan_id)) < 100:
            self.check_rate_limit()
            console.print(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
        
        # Get all alerts
        alerts = self.zap.core.alerts()
        
        return self._process_alerts(alerts)
    
    def _process_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Process and format alerts"""
        processed_alerts = []
        
        for alert in alerts:
            processed_alert = {
                'risk_level': alert.get('risk'),
                'name': alert.get('name'),
                'description': alert.get('description'),
                'url': alert.get('url'),
                'solution': alert.get('solution'),
                'reference': alert.get('reference'),
                'timestamp': datetime.now().isoformat()
            }
            processed_alerts.append(processed_alert)
        
        return processed_alerts
    
    def generate_report(self, findings: List[Dict], output_dir: str):
        """Generate a detailed security report"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        report_file = os.path.join(output_dir, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'findings': findings,
            'summary': {
                'total_vulnerabilities': len(findings),
                'risk_levels': {
                    'high': len([f for f in findings if f['risk_level'] == 'High']),
                    'medium': len([f for f in findings if f['risk_level'] == 'Medium']),
                    'low': len([f for f in findings if f['risk_level'] == 'Low']),
                    'informational': len([f for f in findings if f['risk_level'] == 'Informational'])
                }
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
            
        console.print(f"[green]Report generated: {report_file}[/green]")
        
        return report_file

class EthicalScanner:
    def __init__(self, config: dict):
        self.config = config
        
    def check_robots_txt(self, url: str) -> bool:
        """Check if scanning is allowed by robots.txt"""
        if not self.config.respect_robots_txt:
            return True
            
        try:
            robots_url = f"{url.rstrip('/')}/robots.txt"
            response = requests.get(robots_url)
            
            if response.status_code == 200:
                return 'Disallow: /' not in response.text
            return True
        except:
            return True
            
    def validate_target(self, url: str) -> bool:
        """Validate if the target is allowed to be scanned"""
        from urllib.parse import urlparse
        
        domain = urlparse(url).netloc
        
        # Check if domain is in allowed list
        if self.config.allowed_domains and domain not in self.config.allowed_domains:
            console.print(f"[red]Error: Domain {domain} is not in the allowed list[/red]")
            return False
            
        # Check robots.txt
        if not self.check_robots_txt(url):
            console.print("[red]Error: Scanning not allowed by robots.txt[/red]")
            return False
            
        return True 