"""
Dynamic Analysis Engine for MalLens.
Simulates sandbox execution and behavioral analysis.
In production, this would interface with Cuckoo Sandbox or similar VM-based systems.
For the demo, it generates realistic behavioral data based on static analysis findings.
"""
import asyncio
import random
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import settings


# MITRE ATT&CK technique mappings
MITRE_TECHNIQUES = {
    "process_injection": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "registry_persistence": {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
    "scheduled_task": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
    "file_deletion": {"id": "T1070.004", "name": "File Deletion", "tactic": "Defense Evasion"},
    "command_execution": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "network_connection": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "data_encryption": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "credential_access": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "discovery": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "lateral_movement": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "dll_sideloading": {"id": "T1574.002", "name": "DLL Side-Loading", "tactic": "Defense Evasion"},
    "obfuscation": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "keylogging": {"id": "T1056.001", "name": "Keylogging", "tactic": "Collection"},
    "screen_capture": {"id": "T1113", "name": "Screen Capture", "tactic": "Collection"},
}

# Behavioral signatures
BEHAVIOR_SIGNATURES = [
    {"name": "Anti-VM Detection", "description": "Checks for virtual machine artifacts", "severity": "medium"},
    {"name": "Anti-Debug Techniques", "description": "Uses anti-debugging methods to evade analysis", "severity": "medium"},
    {"name": "Process Hollowing", "description": "Creates a process in suspended state and replaces its memory", "severity": "high"},
    {"name": "Code Injection", "description": "Injects code into another process's address space", "severity": "high"},
    {"name": "Persistence Mechanism", "description": "Installs itself for automatic execution on boot", "severity": "high"},
    {"name": "Network Communication", "description": "Establishes outbound network connections", "severity": "medium"},
    {"name": "File Encryption", "description": "Encrypts files on the system (ransomware behavior)", "severity": "critical"},
    {"name": "Credential Harvesting", "description": "Attempts to access stored credentials", "severity": "high"},
    {"name": "System Discovery", "description": "Enumerates system information and configuration", "severity": "low"},
    {"name": "Data Exfiltration", "description": "Attempts to send collected data to external server", "severity": "critical"},
]


class DynamicAnalyzer:
    """
    Simulates dynamic/behavioral analysis of malware samples.
    In production, this would interface with a real sandbox (Cuckoo, CAPE, etc.)
    """

    def __init__(self, file_path: str, static_results: dict = None):
        self.file_path = file_path
        self.static_results = static_results or {}
        self.results = {}

    async def analyze(self) -> dict:
        """Run dynamic analysis simulation."""
        # Simulate analysis time
        await asyncio.sleep(random.uniform(2, 5))

        # Determine threat profile based on static analysis
        threat_profile = self._determine_threat_profile()

        # Generate behavioral data
        self.results = {
            "processes_created": self._simulate_processes(threat_profile),
            "process_tree": self._simulate_process_tree(threat_profile),
            "files_created": self._simulate_file_activity("created", threat_profile),
            "files_modified": self._simulate_file_activity("modified", threat_profile),
            "files_deleted": self._simulate_file_activity("deleted", threat_profile),
            "registry_keys_created": self._simulate_registry("created", threat_profile),
            "registry_keys_modified": self._simulate_registry("modified", threat_profile),
            "registry_keys_deleted": self._simulate_registry("deleted", threat_profile),
            "dns_queries": self._simulate_dns(threat_profile),
            "http_requests": self._simulate_http(threat_profile),
            "tcp_connections": self._simulate_tcp(threat_profile),
            "udp_connections": self._simulate_udp(threat_profile),
            "behavior_tags": self._generate_behavior_tags(threat_profile),
            "mitre_techniques": self._map_mitre_techniques(threat_profile),
            "signatures_matched": self._match_signatures(threat_profile),
            "behavior_timeline": self._generate_timeline(threat_profile),
            "execution_duration": random.uniform(30, 180),
            "sandbox_type": "simulated",
        }

        return self.results

    def _determine_threat_profile(self) -> dict:
        """Determine the threat profile based on static analysis."""
        profile = {
            "is_malicious": False,
            "malware_type": "unknown",
            "severity": "low",
            "behaviors": [],
        }

        suspicious_imports = self.static_results.get("suspicious_imports", [])
        entropy = self.static_results.get("entropy", {}).get("overall", 0)
        urls = self.static_results.get("urls_found", [])
        is_packed = self.static_results.get("is_packed", False)

        # Score based on findings
        score = 0
        if len(suspicious_imports) > 5:
            score += 3
            profile["behaviors"].append("api_abuse")
        if len(suspicious_imports) > 2:
            score += 1
        if entropy > 7.0:
            score += 2
            profile["behaviors"].append("packed")
        if urls:
            score += 1
            profile["behaviors"].append("network_activity")
        if is_packed:
            score += 2
            profile["behaviors"].append("evasion")

        # Check for specific malware behaviors
        import_str = " ".join(suspicious_imports).lower()
        if "crypt" in import_str:
            profile["behaviors"].append("encryption")
            score += 2
        if "inject" in import_str or "remote" in import_str or "virtual" in import_str:
            profile["behaviors"].append("injection")
            score += 2
        if "hook" in import_str or "keystate" in import_str:
            profile["behaviors"].append("keylogging")
            score += 2
        if "reg" in import_str:
            profile["behaviors"].append("persistence")
            score += 1

        # Determine malware type
        if score >= 6:
            profile["is_malicious"] = True
            if "encryption" in profile["behaviors"] and "network_activity" in profile["behaviors"]:
                profile["malware_type"] = "ransomware"
                profile["severity"] = "critical"
            elif "injection" in profile["behaviors"]:
                profile["malware_type"] = "trojan"
                profile["severity"] = "high"
            elif "keylogging" in profile["behaviors"]:
                profile["malware_type"] = "spyware"
                profile["severity"] = "high"
            elif "network_activity" in profile["behaviors"]:
                profile["malware_type"] = "backdoor"
                profile["severity"] = "high"
            else:
                profile["malware_type"] = "generic_malware"
                profile["severity"] = "medium"
        elif score >= 3:
            profile["is_malicious"] = True
            profile["malware_type"] = "suspicious"
            profile["severity"] = "medium"

        return profile

    def _simulate_processes(self, profile: dict) -> list:
        """Simulate process creation events."""
        processes = [
            {
                "pid": random.randint(1000, 9999),
                "name": "sample.exe",
                "path": "C:\\Users\\sandbox\\Desktop\\sample.exe",
                "command_line": "sample.exe",
                "parent_pid": 4,
                "timestamp": "00:00:01",
            }
        ]

        if profile["is_malicious"]:
            malicious_processes = [
                {"name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami"},
                {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -enc BASE64STRING"},
                {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "command_line": "svchost.exe -k netsvcs"},
                {"name": "conhost.exe", "path": "C:\\Windows\\System32\\conhost.exe", "command_line": "conhost.exe 0x4"},
                {"name": "reg.exe", "path": "C:\\Windows\\System32\\reg.exe", "command_line": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater"},
            ]

            num_procs = min(len(malicious_processes), random.randint(2, 5))
            for i, proc in enumerate(random.sample(malicious_processes, num_procs)):
                proc["pid"] = random.randint(1000, 9999)
                proc["parent_pid"] = processes[0]["pid"]
                proc["timestamp"] = f"00:00:{(i+2):02d}"
                processes.append(proc)

        return processes

    def _simulate_process_tree(self, profile: dict) -> list:
        """Generate process tree structure."""
        tree = [{
            "pid": 4,
            "name": "System",
            "children": [{
                "pid": random.randint(1000, 9999),
                "name": "explorer.exe",
                "children": [{
                    "pid": random.randint(1000, 9999),
                    "name": "sample.exe",
                    "children": []
                }]
            }]
        }]

        if profile["is_malicious"]:
            sample_node = tree[0]["children"][0]["children"][0]
            child_processes = ["cmd.exe", "powershell.exe", "svchost.exe"]
            for proc in random.sample(child_processes, min(2, len(child_processes))):
                sample_node["children"].append({
                    "pid": random.randint(1000, 9999),
                    "name": proc,
                    "children": []
                })

        return tree

    def _simulate_file_activity(self, action: str, profile: dict) -> list:
        """Simulate file system activity."""
        activities = []

        if not profile["is_malicious"]:
            return activities

        if action == "created":
            files = [
                {"path": "C:\\Users\\sandbox\\AppData\\Local\\Temp\\tmp_payload.dll", "size": random.randint(10000, 500000)},
                {"path": "C:\\Users\\sandbox\\AppData\\Roaming\\Microsoft\\config.dat", "size": random.randint(100, 5000)},
                {"path": "C:\\Windows\\Temp\\svc_update.exe", "size": random.randint(50000, 200000)},
            ]
            if profile["malware_type"] == "ransomware":
                files.append({"path": "C:\\Users\\sandbox\\Desktop\\README_DECRYPT.txt", "size": 2048})
        elif action == "modified":
            files = [
                {"path": "C:\\Users\\sandbox\\Documents\\report.docx", "original_hash": hashlib.md5(b"original").hexdigest()},
                {"path": "C:\\Users\\sandbox\\Desktop\\photo.jpg", "original_hash": hashlib.md5(b"photo").hexdigest()},
            ]
        else:  # deleted
            files = [
                {"path": "C:\\Users\\sandbox\\AppData\\Local\\Temp\\tmp_payload.dll"},
                {"path": "C:\\Windows\\Prefetch\\SAMPLE.EXE-*.pf"},
            ]

        return random.sample(files, min(len(files), random.randint(1, len(files))))

    def _simulate_registry(self, action: str, profile: dict) -> list:
        """Simulate registry activity."""
        if not profile["is_malicious"]:
            return []

        if action == "created":
            keys = [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate", "value": "C:\\Users\\sandbox\\AppData\\Roaming\\update.exe"},
                {"key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MalService", "value": "C:\\Windows\\System32\\svc.exe"},
                {"key": "HKCU\\Software\\Classes\\CLSID\\{random-guid}", "value": "InprocServer32"},
            ]
        elif action == "modified":
            keys = [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden", "value": "0"},
                {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA", "value": "0"},
            ]
        else:
            keys = [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate"},
            ]

        return random.sample(keys, min(len(keys), random.randint(1, len(keys))))

    def _simulate_dns(self, profile: dict) -> list:
        """Simulate DNS queries."""
        if not profile["is_malicious"]:
            return []

        domains = [
            {"domain": "update-service.evil-domain.com", "resolved_ip": "185.24.98.12", "type": "A"},
            {"domain": "c2-server.malware-infra.net", "resolved_ip": "91.234.56.78", "type": "A"},
            {"domain": "exfil.darknet-proxy.org", "resolved_ip": "45.67.89.101", "type": "A"},
            {"domain": "cdn-payload.suspicious-host.io", "resolved_ip": "103.45.67.89", "type": "A"},
            {"domain": "api.legitimate-looking.com", "resolved_ip": "172.16.45.1", "type": "A"},
        ]

        return random.sample(domains, min(len(domains), random.randint(2, 4)))

    def _simulate_http(self, profile: dict) -> list:
        """Simulate HTTP requests."""
        if not profile["is_malicious"]:
            return []

        requests = [
            {"method": "POST", "url": "http://c2-server.malware-infra.net/gate.php", "status": 200, "body_size": 4096},
            {"method": "GET", "url": "http://cdn-payload.suspicious-host.io/payload.bin", "status": 200, "body_size": 524288},
            {"method": "POST", "url": "https://api.legitimate-looking.com/api/v1/data", "status": 200, "body_size": 1024},
            {"method": "GET", "url": "http://update-service.evil-domain.com/config.json", "status": 200, "body_size": 256},
        ]

        return random.sample(requests, min(len(requests), random.randint(1, 3)))

    def _simulate_tcp(self, profile: dict) -> list:
        """Simulate TCP connections."""
        if not profile["is_malicious"]:
            return []

        connections = [
            {"src_port": random.randint(49152, 65535), "dst_ip": "185.24.98.12", "dst_port": 443, "protocol": "TLS"},
            {"src_port": random.randint(49152, 65535), "dst_ip": "91.234.56.78", "dst_port": 8080, "protocol": "HTTP"},
            {"src_port": random.randint(49152, 65535), "dst_ip": "45.67.89.101", "dst_port": 4444, "protocol": "RAW"},
            {"src_port": random.randint(49152, 65535), "dst_ip": "103.45.67.89", "dst_port": 80, "protocol": "HTTP"},
        ]

        return random.sample(connections, min(len(connections), random.randint(2, 4)))

    def _simulate_udp(self, profile: dict) -> list:
        """Simulate UDP connections."""
        if not profile["is_malicious"]:
            return []

        return [
            {"src_port": random.randint(49152, 65535), "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "DNS"},
            {"src_port": random.randint(49152, 65535), "dst_ip": "1.1.1.1", "dst_port": 53, "protocol": "DNS"},
        ]

    def _generate_behavior_tags(self, profile: dict) -> list:
        """Generate behavior classification tags."""
        tags = []

        if not profile["is_malicious"]:
            return ["benign", "no_suspicious_activity"]

        tag_map = {
            "injection": ["process_injection", "code_injection", "memory_manipulation"],
            "persistence": ["registry_persistence", "autostart", "service_creation"],
            "network_activity": ["c2_communication", "data_exfiltration", "dns_tunneling"],
            "encryption": ["file_encryption", "crypto_operations"],
            "keylogging": ["input_capture", "keylogging", "clipboard_monitoring"],
            "packed": ["packed_binary", "obfuscated", "anti_analysis"],
            "evasion": ["anti_vm", "anti_debug", "sandbox_detection"],
        }

        for behavior in profile["behaviors"]:
            if behavior in tag_map:
                tags.extend(random.sample(tag_map[behavior], min(2, len(tag_map[behavior]))))

        return list(set(tags))

    def _map_mitre_techniques(self, profile: dict) -> list:
        """Map observed behaviors to MITRE ATT&CK techniques."""
        techniques = []

        technique_map = {
            "injection": ["process_injection"],
            "persistence": ["registry_persistence", "scheduled_task"],
            "network_activity": ["network_connection", "exfiltration"],
            "encryption": ["data_encryption"],
            "keylogging": ["keylogging", "screen_capture"],
            "packed": ["obfuscation"],
            "evasion": ["dll_sideloading", "obfuscation"],
            "api_abuse": ["command_execution", "discovery"],
        }

        for behavior in profile["behaviors"]:
            if behavior in technique_map:
                for tech_key in technique_map[behavior]:
                    if tech_key in MITRE_TECHNIQUES:
                        techniques.append(MITRE_TECHNIQUES[tech_key])

        return list({t["id"]: t for t in techniques}.values())

    def _match_signatures(self, profile: dict) -> list:
        """Match behavioral signatures."""
        if not profile["is_malicious"]:
            return []

        matched = []
        for sig in BEHAVIOR_SIGNATURES:
            # Match based on behaviors
            if sig["severity"] == "critical" and profile["severity"] in ["critical", "high"]:
                if random.random() > 0.5:
                    matched.append(sig)
            elif sig["severity"] == "high" and profile["severity"] in ["critical", "high", "medium"]:
                if random.random() > 0.4:
                    matched.append(sig)
            elif sig["severity"] == "medium":
                if random.random() > 0.5:
                    matched.append(sig)
            elif sig["severity"] == "low":
                if random.random() > 0.3:
                    matched.append(sig)

        return matched[:6]

    def _generate_timeline(self, profile: dict) -> list:
        """Generate a behavioral timeline."""
        timeline = []
        base_time = datetime.utcnow()

        events = [
            {"offset": 0, "event": "Process started", "detail": "sample.exe launched by explorer.exe", "category": "process"},
            {"offset": 1, "event": "System discovery", "detail": "Queried system information (OS version, hostname)", "category": "discovery"},
        ]

        if profile["is_malicious"]:
            malicious_events = [
                {"offset": 3, "event": "File dropped", "detail": "Created payload in AppData\\Local\\Temp", "category": "file"},
                {"offset": 5, "event": "Process injection", "detail": "Injected code into svchost.exe", "category": "process"},
                {"offset": 7, "event": "Registry modified", "detail": "Added persistence key to HKCU\\...\\Run", "category": "registry"},
                {"offset": 10, "event": "Network connection", "detail": "Connected to C2 server at 185.24.98.12:443", "category": "network"},
                {"offset": 15, "event": "Data collection", "detail": "Accessed browser credential stores", "category": "credential"},
                {"offset": 20, "event": "Data exfiltration", "detail": "Sent encrypted data to external server", "category": "network"},
                {"offset": 25, "event": "Anti-forensics", "detail": "Deleted temporary files and cleared event logs", "category": "evasion"},
            ]

            num_events = random.randint(3, len(malicious_events))
            events.extend(sorted(random.sample(malicious_events, num_events), key=lambda x: x["offset"]))

        for event in events:
            event_time = base_time + timedelta(seconds=event["offset"])
            timeline.append({
                "timestamp": event_time.strftime("%H:%M:%S"),
                "seconds_offset": event["offset"],
                "event": event["event"],
                "detail": event["detail"],
                "category": event["category"],
            })

        return timeline
