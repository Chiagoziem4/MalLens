"""
Static Analysis Engine for MalLens.
Performs file hashing, string extraction, PE parsing, entropy calculation,
and YARA signature matching.
"""
import hashlib
import math
import re
import os
import struct
from pathlib import Path
from typing import Optional
from collections import Counter

from app.core.config import settings


# Suspicious Windows API imports that indicate malicious behavior
SUSPICIOUS_APIS = [
    "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "NtWriteVirtualMemory",
    "CreateProcess", "WinExec", "ShellExecute", "ShellExecuteEx",
    "URLDownloadToFile", "InternetOpen", "InternetConnect", "HttpOpenRequest",
    "InternetReadFile", "WinHttpOpen", "WinHttpConnect",
    "RegSetValueEx", "RegCreateKeyEx", "RegDeleteKey",
    "OpenProcess", "TerminateProcess", "CreateToolhelp32Snapshot",
    "Process32First", "Process32Next",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter",
    "LoadLibrary", "GetProcAddress", "LdrLoadDll",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "CreateService", "StartService", "OpenSCManager",
    "socket", "connect", "send", "recv", "bind", "listen", "accept",
    "WSAStartup", "WSASocket",
]

# Suspicious string patterns
SUSPICIOUS_PATTERNS = {
    "urls": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    "ips": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "emails": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "registry_keys": re.compile(r'(HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s]+', re.IGNORECASE),
    "file_paths": re.compile(r'[A-Z]:\\[^\s<>"{}|\\^`\[\]]*\\[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    "crypto_wallets": re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b'),
    "base64_strings": re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
}


class StaticAnalyzer:
    """Performs static analysis on uploaded files."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_data = b""
        self.results = {}

    async def analyze(self) -> dict:
        """Run full static analysis pipeline."""
        with open(self.file_path, "rb") as f:
            self.file_data = f.read()

        self.results = {
            "hashes": self._compute_hashes(),
            "file_info": self._get_file_info(),
            "entropy": self._calculate_entropy(),
            "sections": [],
            "imports": [],
            "exports": [],
            "suspicious_imports": [],
            "strings": self._extract_strings(),
            "urls_found": [],
            "ips_found": [],
            "emails_found": [],
            "yara_matches": [],
            "is_packed": False,
            "packer": None,
        }

        # Extract patterns from strings
        self._extract_patterns()

        # Detect file type and parse accordingly
        file_type = self._detect_file_type()
        self.results["file_info"]["detected_type"] = file_type

        if file_type == "PE":
            self._analyze_pe()
        elif file_type == "ELF":
            self._analyze_elf()
        elif file_type == "PDF":
            self._analyze_pdf()
        elif file_type == "Office":
            self._analyze_office()

        # Check if packed
        if self.results["entropy"]["overall"] > 7.0:
            self.results["is_packed"] = True
            self.results["packer"] = "High entropy detected (possible packing/encryption)"

        # Run YARA if available
        self._run_yara()

        return self.results

    def _compute_hashes(self) -> dict:
        """Compute MD5, SHA1, SHA256 hashes."""
        return {
            "md5": hashlib.md5(self.file_data).hexdigest(),
            "sha1": hashlib.sha1(self.file_data).hexdigest(),
            "sha256": hashlib.sha256(self.file_data).hexdigest(),
            "ssdeep": self._compute_ssdeep(),
        }

    def _compute_ssdeep(self) -> str:
        """Compute fuzzy hash (simplified)."""
        # Simplified fuzzy hash representation
        block_size = max(3, len(self.file_data) // 64)
        chunks = [self.file_data[i:i+block_size] for i in range(0, len(self.file_data), block_size)]
        hash_parts = [hashlib.md5(chunk).hexdigest()[:2] for chunk in chunks[:32]]
        return f"{block_size}:{''.join(hash_parts)}"

    def _get_file_info(self) -> dict:
        """Get basic file information."""
        file_path = Path(self.file_path)
        return {
            "name": file_path.name,
            "size": len(self.file_data),
            "extension": file_path.suffix.lower(),
            "magic_bytes": self.file_data[:16].hex() if len(self.file_data) >= 16 else self.file_data.hex(),
        }

    def _calculate_entropy(self) -> dict:
        """Calculate Shannon entropy of the file and sections."""
        def shannon_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            counter = Counter(data)
            length = len(data)
            entropy = -sum(
                (count / length) * math.log2(count / length)
                for count in counter.values()
            )
            return round(entropy, 4)

        overall = shannon_entropy(self.file_data)

        # Calculate entropy for chunks
        chunk_size = max(256, len(self.file_data) // 16)
        chunks = []
        for i in range(0, len(self.file_data), chunk_size):
            chunk = self.file_data[i:i+chunk_size]
            chunks.append({
                "offset": i,
                "size": len(chunk),
                "entropy": shannon_entropy(chunk)
            })

        return {
            "overall": overall,
            "chunks": chunks[:16],  # Limit to 16 chunks for display
            "max_entropy": 8.0,
            "assessment": self._entropy_assessment(overall),
        }

    def _entropy_assessment(self, entropy: float) -> str:
        """Assess entropy level."""
        if entropy < 1.0:
            return "Very low - likely empty or uniform data"
        elif entropy < 4.0:
            return "Low - typical for text or simple data"
        elif entropy < 6.0:
            return "Normal - typical for compiled code"
        elif entropy < 7.0:
            return "Elevated - may contain compressed data"
        elif entropy < 7.5:
            return "High - likely packed or encrypted"
        else:
            return "Very high - strongly suggests encryption or packing"

    def _extract_strings(self) -> dict:
        """Extract ASCII and Unicode strings."""
        # ASCII strings (min length 4)
        ascii_pattern = re.compile(rb'[\x20-\x7e]{4,}')
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_pattern.findall(self.file_data)]

        # Unicode strings (min length 4)
        unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
        unicode_strings = [s.decode('utf-16-le', errors='ignore') for s in unicode_pattern.findall(self.file_data)]

        all_strings = list(set(ascii_strings + unicode_strings))

        # Filter interesting strings
        interesting = []
        for s in all_strings:
            if any(api.lower() in s.lower() for api in SUSPICIOUS_APIS[:20]):
                interesting.append({"value": s, "category": "suspicious_api"})
            elif re.search(r'https?://', s, re.IGNORECASE):
                interesting.append({"value": s, "category": "url"})
            elif re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
                interesting.append({"value": s, "category": "ip_address"})
            elif re.search(r'password|passwd|secret|token|key|crypt', s, re.IGNORECASE):
                interesting.append({"value": s, "category": "credential_related"})
            elif re.search(r'\\\\|HKEY_|HKLM|HKCU', s, re.IGNORECASE):
                interesting.append({"value": s, "category": "system_path"})

        return {
            "total_count": len(all_strings),
            "ascii_count": len(ascii_strings),
            "unicode_count": len(unicode_strings),
            "interesting": interesting[:100],  # Limit
            "sample": all_strings[:50],  # First 50 for display
        }

    def _extract_patterns(self):
        """Extract URLs, IPs, emails from strings."""
        text = self.file_data.decode('ascii', errors='ignore')

        urls = list(set(SUSPICIOUS_PATTERNS["urls"].findall(text)))
        ips = list(set(SUSPICIOUS_PATTERNS["ips"].findall(text)))
        emails = list(set(SUSPICIOUS_PATTERNS["emails"].findall(text)))

        # Filter out common false positives for IPs
        ips = [ip for ip in ips if not ip.startswith("0.") and not ip.startswith("255.")]

        self.results["urls_found"] = urls[:50]
        self.results["ips_found"] = ips[:50]
        self.results["emails_found"] = emails[:20]

    def _detect_file_type(self) -> str:
        """Detect file type from magic bytes."""
        if self.file_data[:2] == b'MZ':
            return "PE"
        elif self.file_data[:4] == b'\x7fELF':
            return "ELF"
        elif self.file_data[:4] == b'%PDF':
            return "PDF"
        elif self.file_data[:4] in (b'\xd0\xcf\x11\xe0', b'PK\x03\x04'):
            return "Office"
        elif self.file_data[:2] == b'#!':
            return "Script"
        elif self.file_data[:4] == b'\xfe\xed\xfa\xce' or self.file_data[:4] == b'\xce\xfa\xed\xfe':
            return "MachO"
        elif self.file_data[:4] == b'\xca\xfe\xba\xbe':
            return "MachO_Universal"
        else:
            return "Unknown"

    def _analyze_pe(self):
        """Analyze PE (Windows executable) format."""
        try:
            # Parse PE header manually for basic info
            if len(self.file_data) < 64:
                return

            # Get PE offset
            pe_offset = struct.unpack_from('<I', self.file_data, 0x3C)[0]
            if pe_offset + 4 > len(self.file_data):
                return

            # Verify PE signature
            if self.file_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return

            # COFF header
            coff_offset = pe_offset + 4
            machine = struct.unpack_from('<H', self.file_data, coff_offset)[0]
            num_sections = struct.unpack_from('<H', self.file_data, coff_offset + 2)[0]
            timestamp = struct.unpack_from('<I', self.file_data, coff_offset + 4)[0]

            machines = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
            arch = machines.get(machine, f"Unknown (0x{machine:x})")

            self.results["file_info"]["architecture"] = arch
            self.results["file_info"]["pe_timestamp"] = timestamp
            self.results["file_info"]["num_sections"] = num_sections

            # Extract import-like strings from the binary
            text = self.file_data.decode('ascii', errors='ignore')
            found_imports = []
            for api in SUSPICIOUS_APIS:
                if api in text:
                    found_imports.append(api)

            self.results["suspicious_imports"] = found_imports

            # Common DLL names
            dll_pattern = re.compile(r'([a-zA-Z0-9_]+\.dll)', re.IGNORECASE)
            dlls = list(set(dll_pattern.findall(text)))
            self.results["imports"] = [{"dll": dll, "functions": []} for dll in dlls[:30]]

        except Exception:
            pass

    def _analyze_elf(self):
        """Analyze ELF (Linux executable) format."""
        try:
            if len(self.file_data) < 64:
                return

            # ELF class (32 or 64 bit)
            ei_class = self.file_data[4]
            arch = "64-bit" if ei_class == 2 else "32-bit"

            # Endianness
            ei_data = self.file_data[5]
            endian = "Little Endian" if ei_data == 1 else "Big Endian"

            # Machine type
            if ei_class == 2:
                e_machine = struct.unpack_from('<H', self.file_data, 18)[0]
            else:
                e_machine = struct.unpack_from('<H', self.file_data, 18)[0]

            machines = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64"}
            machine_name = machines.get(e_machine, f"Unknown (0x{e_machine:x})")

            self.results["file_info"]["architecture"] = f"{machine_name} ({arch}, {endian})"
            self.results["file_info"]["elf_type"] = "ELF"

        except Exception:
            pass

    def _analyze_pdf(self):
        """Analyze PDF for suspicious elements."""
        try:
            text = self.file_data.decode('latin-1', errors='ignore')

            suspicious_elements = []
            if '/JavaScript' in text or '/JS' in text:
                suspicious_elements.append("Contains JavaScript")
            if '/OpenAction' in text or '/AA' in text:
                suspicious_elements.append("Contains auto-action triggers")
            if '/Launch' in text:
                suspicious_elements.append("Contains launch action")
            if '/EmbeddedFile' in text:
                suspicious_elements.append("Contains embedded files")
            if '/URI' in text:
                suspicious_elements.append("Contains URI references")
            if '/RichMedia' in text:
                suspicious_elements.append("Contains rich media (Flash)")
            if '/XFA' in text:
                suspicious_elements.append("Contains XFA forms")

            self.results["file_info"]["pdf_suspicious"] = suspicious_elements
            if suspicious_elements:
                self.results["suspicious_imports"] = suspicious_elements

        except Exception:
            pass

    def _analyze_office(self):
        """Analyze Office documents for suspicious elements."""
        try:
            text = self.file_data.decode('latin-1', errors='ignore')

            suspicious_elements = []
            if 'VBA' in text or 'macro' in text.lower():
                suspicious_elements.append("Contains VBA macros")
            if 'AutoOpen' in text or 'Auto_Open' in text:
                suspicious_elements.append("Contains auto-open macro")
            if 'Shell' in text and ('cmd' in text.lower() or 'powershell' in text.lower()):
                suspicious_elements.append("Shell command execution detected")
            if 'WScript' in text or 'CreateObject' in text:
                suspicious_elements.append("ActiveX/COM object creation")
            if 'DDEAUTO' in text or 'DDE' in text:
                suspicious_elements.append("DDE (Dynamic Data Exchange) detected")

            self.results["file_info"]["office_suspicious"] = suspicious_elements
            if suspicious_elements:
                self.results["suspicious_imports"] = suspicious_elements

        except Exception:
            pass

    def _run_yara(self):
        """Run YARA rules against the file."""
        try:
            import yara
            rules_dir = Path(settings.YARA_RULES_DIR)
            if not rules_dir.exists():
                return

            for rule_file in rules_dir.glob("*.yar"):
                try:
                    rules = yara.compile(filepath=str(rule_file))
                    matches = rules.match(data=self.file_data)
                    for match in matches:
                        self.results["yara_matches"].append({
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": list(match.tags),
                            "meta": dict(match.meta) if match.meta else {},
                        })
                except Exception:
                    continue
        except ImportError:
            # YARA not installed, skip
            pass
