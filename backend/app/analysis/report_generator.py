"""
AI-Powered Report Generator for MalLens.
Generates comprehensive analysis reports using LLM or template-based approach.
"""
import json
from typing import Optional
from datetime import datetime

from app.core.config import settings


class ReportGenerator:
    """Generates human-readable analysis reports."""

    def __init__(self, analysis_data: dict, static_results: dict, dynamic_results: dict, iocs: list):
        self.analysis_data = analysis_data
        self.static_results = static_results
        self.dynamic_results = dynamic_results
        self.iocs = iocs

    async def generate(self) -> dict:
        """Generate a comprehensive report."""
        # Try AI-powered generation first, fall back to template
        if settings.OPENAI_API_KEY:
            try:
                return await self._generate_ai_report()
            except Exception:
                pass

        return self._generate_template_report()

    async def _generate_ai_report(self) -> dict:
        """Generate report using OpenAI API."""
        try:
            from openai import OpenAI

            client = OpenAI()

            # Prepare context
            context = self._prepare_context()

            prompt = f"""You are a malware analyst. Based on the following analysis data, generate a comprehensive malware analysis report.

ANALYSIS DATA:
{context}

Generate the report with these sections:
1. Executive Summary (2-3 paragraphs summarizing the threat)
2. Detailed Analysis (technical breakdown of behaviors observed)
3. Recommendations (actionable steps for defenders)
4. Risk Assessment (overall risk level and justification)

Be specific, technical, and actionable. Reference specific IOCs and behaviors found."""

            response = client.chat.completions.create(
                model=settings.AI_MODEL,
                messages=[
                    {"role": "system", "content": "You are an expert malware analyst writing a detailed technical report."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.3,
            )

            full_text = response.choices[0].message.content

            # Parse sections
            sections = self._parse_ai_response(full_text)
            sections["mitre_mapping"] = self.dynamic_results.get("mitre_techniques", [])
            sections["generator"] = "ai"

            return sections

        except Exception as e:
            return self._generate_template_report()

    def _generate_template_report(self) -> dict:
        """Generate report using templates (fallback)."""
        file_info = self.static_results.get("file_info", {})
        hashes = self.static_results.get("hashes", {})
        entropy = self.static_results.get("entropy", {})
        suspicious = self.static_results.get("suspicious_imports", [])
        behavior_tags = self.dynamic_results.get("behavior_tags", [])
        mitre = self.dynamic_results.get("mitre_techniques", [])
        signatures = self.dynamic_results.get("signatures_matched", [])
        timeline = self.dynamic_results.get("behavior_timeline", [])

        # Determine threat level
        threat_level = "Low"
        if len(signatures) >= 3 or any(s.get("severity") == "critical" for s in signatures):
            threat_level = "Critical"
        elif len(signatures) >= 2 or any(s.get("severity") == "high" for s in signatures):
            threat_level = "High"
        elif len(signatures) >= 1:
            threat_level = "Medium"

        # Executive Summary
        exec_summary = self._build_executive_summary(file_info, threat_level, behavior_tags, signatures)

        # Detailed Analysis
        detailed = self._build_detailed_analysis(file_info, hashes, entropy, suspicious, timeline, signatures)

        # Recommendations
        recommendations = self._build_recommendations(threat_level, behavior_tags, self.iocs)

        # Risk Assessment
        risk = self._build_risk_assessment(threat_level, signatures, mitre)

        return {
            "executive_summary": exec_summary,
            "detailed_analysis": detailed,
            "recommendations": recommendations,
            "risk_assessment": risk,
            "mitre_mapping": mitre,
            "generator": "template",
        }

    def _build_executive_summary(self, file_info: dict, threat_level: str, tags: list, signatures: list) -> str:
        """Build executive summary section."""
        file_name = file_info.get("name", "Unknown")
        file_type = file_info.get("detected_type", "Unknown")

        summary = f"## Executive Summary\n\n"
        summary += f"The analyzed sample **{file_name}** (type: {file_type}) has been classified as **{threat_level} Risk**. "

        if threat_level in ["High", "Critical"]:
            summary += "The analysis revealed multiple indicators of malicious behavior that pose a significant threat to system security. "
            if "process_injection" in tags or "code_injection" in tags:
                summary += "The sample demonstrates advanced evasion techniques including process injection, "
            if "c2_communication" in tags or "data_exfiltration" in tags:
                summary += "establishes communication with external command-and-control infrastructure, "
            if "registry_persistence" in tags or "autostart" in tags:
                summary += "installs persistence mechanisms to survive system reboots, "
            summary += "and exhibits behaviors consistent with sophisticated malware.\n\n"
        elif threat_level == "Medium":
            summary += "The analysis identified suspicious behaviors that warrant further investigation. "
            summary += "While not definitively malicious, the sample exhibits characteristics commonly associated with malware.\n\n"
        else:
            summary += "The analysis did not identify significant malicious indicators. "
            summary += "However, the sample should still be treated with caution in production environments.\n\n"

        if signatures:
            summary += f"**{len(signatures)} behavioral signatures** were triggered during dynamic analysis, "
            summary += f"and **{len(self.iocs)} indicators of compromise** were extracted.\n"

        return summary

    def _build_detailed_analysis(self, file_info: dict, hashes: dict, entropy: dict, suspicious: list, timeline: list, signatures: list) -> str:
        """Build detailed technical analysis section."""
        analysis = "## Detailed Technical Analysis\n\n"

        # File Properties
        analysis += "### File Properties\n"
        analysis += f"- **File Name:** {file_info.get('name', 'N/A')}\n"
        analysis += f"- **File Type:** {file_info.get('detected_type', 'N/A')}\n"
        analysis += f"- **File Size:** {file_info.get('size', 0):,} bytes\n"
        analysis += f"- **SHA-256:** `{hashes.get('sha256', 'N/A')}`\n"
        analysis += f"- **MD5:** `{hashes.get('md5', 'N/A')}`\n"
        analysis += f"- **Entropy:** {entropy.get('overall', 0):.4f} ({entropy.get('assessment', 'N/A')})\n\n"

        # Suspicious Indicators
        if suspicious:
            analysis += "### Suspicious API Imports\n"
            analysis += "The following suspicious Windows API functions were identified:\n"
            for api in suspicious[:10]:
                analysis += f"- `{api}`\n"
            analysis += "\n"

        # Behavioral Analysis
        if timeline:
            analysis += "### Behavioral Timeline\n"
            analysis += "Key events observed during dynamic execution:\n\n"
            for event in timeline:
                analysis += f"- **[{event.get('timestamp', '')}]** {event.get('event', '')}: {event.get('detail', '')}\n"
            analysis += "\n"

        # Signatures
        if signatures:
            analysis += "### Matched Behavioral Signatures\n"
            for sig in signatures:
                analysis += f"- **{sig.get('name', '')}** ({sig.get('severity', 'unknown')}): {sig.get('description', '')}\n"
            analysis += "\n"

        return analysis

    def _build_recommendations(self, threat_level: str, tags: list, iocs: list) -> str:
        """Build recommendations section."""
        recs = "## Recommendations\n\n"

        if threat_level in ["High", "Critical"]:
            recs += "### Immediate Actions Required\n"
            recs += "1. **Quarantine** the affected system(s) immediately\n"
            recs += "2. **Block** all identified IOCs at network perimeter (firewall, proxy, DNS)\n"
            recs += "3. **Scan** all endpoints for the identified file hashes\n"
            recs += "4. **Review** authentication logs for signs of lateral movement\n"
            recs += "5. **Preserve** forensic evidence before remediation\n\n"

            recs += "### Network-Level Mitigations\n"
            network_iocs = [i for i in iocs if i.get("type") in ["ip", "domain", "url"]]
            if network_iocs:
                recs += "Block the following at your network boundary:\n"
                for ioc in network_iocs[:10]:
                    recs += f"- {ioc['type'].upper()}: `{ioc['value']}`\n"
                recs += "\n"

        elif threat_level == "Medium":
            recs += "### Recommended Actions\n"
            recs += "1. **Monitor** systems where this file was observed\n"
            recs += "2. **Add** identified IOCs to watchlists\n"
            recs += "3. **Investigate** the source/delivery mechanism of this file\n"
            recs += "4. **Update** endpoint detection signatures\n\n"

        else:
            recs += "### Precautionary Measures\n"
            recs += "1. Continue monitoring with standard security controls\n"
            recs += "2. Maintain updated antivirus signatures\n"
            recs += "3. Ensure endpoint detection and response (EDR) is active\n\n"

        recs += "### Long-Term Improvements\n"
        recs += "- Review and strengthen email filtering rules\n"
        recs += "- Implement application whitelisting where feasible\n"
        recs += "- Conduct user awareness training on phishing and social engineering\n"
        recs += "- Ensure regular backup procedures are in place and tested\n"

        return recs

    def _build_risk_assessment(self, threat_level: str, signatures: list, mitre: list) -> str:
        """Build risk assessment section."""
        risk = "## Risk Assessment\n\n"
        risk += f"**Overall Threat Level: {threat_level}**\n\n"

        if mitre:
            risk += "### MITRE ATT&CK Coverage\n"
            risk += "The following techniques were observed:\n\n"
            risk += "| Technique ID | Name | Tactic |\n"
            risk += "|---|---|---|\n"
            for tech in mitre:
                risk += f"| {tech.get('id', '')} | {tech.get('name', '')} | {tech.get('tactic', '')} |\n"
            risk += "\n"

        risk += "### Risk Factors\n"
        factors = []
        if any(s.get("severity") == "critical" for s in signatures):
            factors.append("- Critical severity signatures matched (data destruction/exfiltration)")
        if any(s.get("severity") == "high" for s in signatures):
            factors.append("- High severity signatures matched (active exploitation)")
        if len(mitre) > 3:
            factors.append(f"- Multiple MITRE ATT&CK techniques observed ({len(mitre)} techniques)")
        if len(self.iocs) > 5:
            factors.append(f"- Numerous IOCs extracted ({len(self.iocs)} indicators)")

        if factors:
            risk += "\n".join(factors) + "\n"
        else:
            risk += "- No significant risk factors identified\n"

        return risk

    def _prepare_context(self) -> str:
        """Prepare analysis context for AI generation."""
        context = {
            "file_info": self.static_results.get("file_info", {}),
            "hashes": self.static_results.get("hashes", {}),
            "entropy": self.static_results.get("entropy", {}).get("overall", 0),
            "suspicious_imports": self.static_results.get("suspicious_imports", [])[:15],
            "behavior_tags": self.dynamic_results.get("behavior_tags", []),
            "mitre_techniques": self.dynamic_results.get("mitre_techniques", []),
            "signatures": self.dynamic_results.get("signatures_matched", []),
            "timeline": self.dynamic_results.get("behavior_timeline", []),
            "network_activity": {
                "dns": self.dynamic_results.get("dns_queries", []),
                "http": self.dynamic_results.get("http_requests", []),
            },
            "iocs_count": len(self.iocs),
            "iocs_sample": self.iocs[:10],
        }
        return json.dumps(context, indent=2, default=str)

    def _parse_ai_response(self, text: str) -> dict:
        """Parse AI response into sections."""
        sections = {
            "executive_summary": "",
            "detailed_analysis": "",
            "recommendations": "",
            "risk_assessment": "",
        }

        current_section = "executive_summary"
        lines = text.split("\n")

        for line in lines:
            lower = line.lower().strip()
            if "detailed analysis" in lower or "technical analysis" in lower:
                current_section = "detailed_analysis"
            elif "recommendation" in lower:
                current_section = "recommendations"
            elif "risk assessment" in lower or "risk level" in lower:
                current_section = "risk_assessment"

            sections[current_section] += line + "\n"

        return sections
