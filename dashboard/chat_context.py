"""
Chat Context Manager
Loads scan results and dashboard context for AI chatbot
"""
import os
import json
from pathlib import Path
from datetime import datetime

class ChatContext:
    """Manages context from scan reports for AI chatbot"""
    
    def __init__(self, report_dir: str = "/reports"):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)
    
    def get_latest_scan_context(self) -> str:
        """Extract context from latest scan report"""
        try:
            # Find latest JSON report
            reports = sorted(
                Path(self.report_dir).glob("report_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            if not reports:
                return None
            
            latest_report = reports[0]
            with open(latest_report, 'r') as f:
                data = json.load(f)
            
            # Extract key vulnerabilities
            findings = data.get("findings", [])
            if not findings:
                return None
            
            context_lines = [
                f"Latest Scan Report: {latest_report.name}",
                f"Scan Time: {data.get('timestamp', 'Unknown')}",
                f"Target: {data.get('target_url', 'Unknown')}",
                f"Total Findings: {len(findings)}\n",
                "VULNERABILITIES FOUND:"
            ]
            
            # Group by severity
            by_severity = {}
            for finding in findings:
                severity = finding.get("severity", "Unknown").upper()
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(finding)
            
            # Format by severity
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for severity in severity_order:
                if severity in by_severity:
                    vulns = by_severity[severity]
                    context_lines.append(f"\n{severity} ({len(vulns)}):")
                    for vuln in vulns[:3]:  # Limit to first 3 per severity
                        context_lines.append(f"  • {vuln.get('title', 'Unknown')}")
                        context_lines.append(f"    {vuln.get('description', '')[:100]}")
            
            return "\n".join(context_lines)
        
        except Exception as e:
            return f"(Could not load scan context: {e})"
    
    def get_scan_stats(self) -> dict:
        """Get statistics about scans"""
        try:
            reports = list(Path(self.report_dir).glob("report_*.json"))
            
            total_vulns = 0
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            for report_file in reports[-5:]:  # Last 5 reports
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                        for finding in data.get("findings", []):
                            total_vulns += 1
                            severity = finding.get("severity", "MEDIUM").upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                except:
                    pass
            
            return {
                "total_scans": len(reports),
                "total_vulnerabilities": total_vulns,
                "by_severity": severity_counts
            }
        except:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "by_severity": {}
            }
    
    def get_vulnerability_details(self, vuln_type: str) -> str:
        """Get details about a specific vulnerability type from scans"""
        try:
            reports = sorted(
                Path(self.report_dir).glob("report_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            for report_file in reports[:3]:  # Check last 3 reports
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    for finding in data.get("findings", []):
                        if vuln_type.lower() in finding.get("title", "").lower():
                            return json.dumps(finding, indent=2)
            
            return None
        except:
            return None


# Global instance
_context_instance = None

def get_chat_context(report_dir: str = "/reports") -> ChatContext:
    """Get or create context manager instance"""
    global _context_instance
    if _context_instance is None:
        _context_instance = ChatContext(report_dir)
    return _context_instance
