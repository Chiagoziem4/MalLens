"""
IOC (Indicators of Compromise) Extractor for MalLens.
Extracts and categorizes IOCs from static and dynamic analysis results.
"""
import re
from typing import List, Dict
from datetime import datetime


class IOCExtractor:
    """Extracts and categorizes Indicators of Compromise from analysis results."""

    def __init__(self, static_results: dict, dynamic_results: dict):
        self.static_results = static_results
        self.dynamic_results = dynamic_results
        self.iocs: List[Dict] = []

    async def extract(self) -> List[Dict]:
        """Extract all IOCs from analysis results."""
        self._extract_from_static()
        self._extract_from_dynamic()
        self._deduplicate()
        self._assign_severity()
        return self.iocs

    def _extract_from_static(self):
        """Extract IOCs from static analysis results."""
        # URLs
        for url in self.static_results.get("urls_found", []):
            self.iocs.append({
                "type": "url",
                "value": url,
                "source": "static_analysis",
                "context": "Found in file strings",
                "confidence": 0.7,
            })

        # IP addresses
        for ip in self.static_results.get("ips_found", []):
            if self._is_valid_public_ip(ip):
                self.iocs.append({
                    "type": "ip",
                    "value": ip,
                    "source": "static_analysis",
                    "context": "Found in file strings",
                    "confidence": 0.6,
                })

        # Email addresses
        for email in self.static_results.get("emails_found", []):
            self.iocs.append({
                "type": "email",
                "value": email,
                "source": "static_analysis",
                "context": "Found in file strings",
                "confidence": 0.5,
            })

        # File hashes
        hashes = self.static_results.get("hashes", {})
        if hashes.get("sha256"):
            self.iocs.append({
                "type": "hash_sha256",
                "value": hashes["sha256"],
                "source": "static_analysis",
                "context": "Sample file hash",
                "confidence": 1.0,
            })
        if hashes.get("md5"):
            self.iocs.append({
                "type": "hash_md5",
                "value": hashes["md5"],
                "source": "static_analysis",
                "context": "Sample file hash",
                "confidence": 1.0,
            })

        # YARA matches
        for match in self.static_results.get("yara_matches", []):
            self.iocs.append({
                "type": "signature",
                "value": match.get("rule", "unknown"),
                "source": "yara",
                "context": f"YARA rule match: {match.get('namespace', '')}",
                "confidence": 0.9,
            })

    def _extract_from_dynamic(self):
        """Extract IOCs from dynamic analysis results."""
        # DNS queries
        for dns in self.dynamic_results.get("dns_queries", []):
            domain = dns.get("domain", "")
            if domain and not self._is_benign_domain(domain):
                self.iocs.append({
                    "type": "domain",
                    "value": domain,
                    "source": "dynamic_analysis",
                    "context": f"DNS query resolved to {dns.get('resolved_ip', 'unknown')}",
                    "confidence": 0.8,
                })

            resolved_ip = dns.get("resolved_ip", "")
            if resolved_ip and self._is_valid_public_ip(resolved_ip):
                self.iocs.append({
                    "type": "ip",
                    "value": resolved_ip,
                    "source": "dynamic_analysis",
                    "context": f"Resolved from {domain}",
                    "confidence": 0.8,
                })

        # HTTP requests
        for req in self.dynamic_results.get("http_requests", []):
            url = req.get("url", "")
            if url:
                self.iocs.append({
                    "type": "url",
                    "value": url,
                    "source": "dynamic_analysis",
                    "context": f"HTTP {req.get('method', 'GET')} request during execution",
                    "confidence": 0.9,
                })

        # TCP connections
        for conn in self.dynamic_results.get("tcp_connections", []):
            ip = conn.get("dst_ip", "")
            if ip and self._is_valid_public_ip(ip):
                self.iocs.append({
                    "type": "ip",
                    "value": ip,
                    "source": "dynamic_analysis",
                    "context": f"TCP connection to port {conn.get('dst_port', 'unknown')}",
                    "confidence": 0.85,
                })

        # Registry persistence
        for reg in self.dynamic_results.get("registry_keys_created", []):
            key = reg.get("key", "")
            if "Run" in key or "Services" in key:
                self.iocs.append({
                    "type": "registry",
                    "value": key,
                    "source": "dynamic_analysis",
                    "context": f"Persistence mechanism: {reg.get('value', '')}",
                    "confidence": 0.9,
                })

        # Dropped files
        for file in self.dynamic_results.get("files_created", []):
            path = file.get("path", "")
            if path and (".exe" in path.lower() or ".dll" in path.lower() or ".bat" in path.lower()):
                self.iocs.append({
                    "type": "file_path",
                    "value": path,
                    "source": "dynamic_analysis",
                    "context": "Dropped executable file",
                    "confidence": 0.85,
                })

        # Mutexes (from behavior tags)
        for tag in self.dynamic_results.get("behavior_tags", []):
            if tag not in ["benign", "no_suspicious_activity"]:
                self.iocs.append({
                    "type": "behavior",
                    "value": tag,
                    "source": "dynamic_analysis",
                    "context": "Behavioral indicator",
                    "confidence": 0.7,
                })

    def _deduplicate(self):
        """Remove duplicate IOCs."""
        seen = set()
        unique_iocs = []
        for ioc in self.iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        self.iocs = unique_iocs

    def _assign_severity(self):
        """Assign severity levels to IOCs."""
        for ioc in self.iocs:
            if ioc["type"] in ["url", "domain"] and ioc["source"] == "dynamic_analysis":
                ioc["severity"] = "high"
            elif ioc["type"] == "ip" and ioc["source"] == "dynamic_analysis":
                ioc["severity"] = "high"
            elif ioc["type"] == "registry":
                ioc["severity"] = "high"
            elif ioc["type"] == "file_path":
                ioc["severity"] = "medium"
            elif ioc["type"] == "behavior":
                ioc["severity"] = "medium"
            elif ioc["type"] in ["hash_sha256", "hash_md5"]:
                ioc["severity"] = "info"
            elif ioc["type"] == "signature":
                ioc["severity"] = "critical"
            else:
                ioc["severity"] = "low"

    @staticmethod
    def _is_valid_public_ip(ip: str) -> bool:
        """Check if IP is a valid public (non-private) address."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            octets = [int(p) for p in parts]
            if any(o < 0 or o > 255 for o in octets):
                return False
            # Filter private/reserved ranges
            if octets[0] == 10:
                return False
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return False
            if octets[0] == 192 and octets[1] == 168:
                return False
            if octets[0] == 127:
                return False
            if octets[0] == 0 or octets[0] == 255:
                return False
            return True
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _is_benign_domain(domain: str) -> bool:
        """Check if domain is likely benign."""
        benign_patterns = [
            "microsoft.com", "windows.com", "google.com", "googleapis.com",
            "gstatic.com", "cloudflare.com", "amazonaws.com", "azure.com",
            "windowsupdate.com", "digicert.com", "verisign.com",
        ]
        return any(domain.endswith(p) for p in benign_patterns)
