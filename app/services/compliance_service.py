"""
ComplianceService — maps scan findings to OWASP Top 10, PCI-DSS 4.0, and SOC2
control requirements, and generates a branded compliance PDF report.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

# ── Compliance mappings ───────────────────────────────────────────────────────

OWASP_TO_PCI: Dict[str, List[str]] = {
    "A01": ["PCI-DSS 7.1", "PCI-DSS 7.2", "PCI-DSS 8.2"],
    "A02": ["PCI-DSS 3.4", "PCI-DSS 3.5", "PCI-DSS 4.2"],
    "A03": ["PCI-DSS 6.2.4"],
    "A04": ["PCI-DSS 6.2.1", "PCI-DSS 6.2.2"],
    "A05": ["PCI-DSS 2.2", "PCI-DSS 2.3"],
    "A06": ["PCI-DSS 6.3.3"],
    "A07": ["PCI-DSS 8.2", "PCI-DSS 8.3", "PCI-DSS 8.4"],
    "A08": ["PCI-DSS 6.4.1", "PCI-DSS 6.4.2"],
    "A09": ["PCI-DSS 10.2", "PCI-DSS 10.3"],
    "A10": ["PCI-DSS 6.2.4", "PCI-DSS 1.3"],
}

OWASP_TO_SOC2: Dict[str, List[str]] = {
    "A01": ["CC6.1", "CC6.2", "CC6.3"],
    "A02": ["CC6.7", "CC9.2"],
    "A03": ["CC6.8", "CC7.1"],
    "A04": ["CC8.1"],
    "A05": ["CC7.1", "CC7.2"],
    "A06": ["CC7.1", "A1.2"],
    "A07": ["CC6.1", "CC6.2"],
    "A08": ["PI1.1", "CC6.8"],
    "A09": ["CC7.2", "CC7.3"],
    "A10": ["CC6.6", "CC6.7"],
}

OWASP_LABELS: Dict[str, str] = {
    "A01": "A01 – Broken Access Control",
    "A02": "A02 – Cryptographic Failures",
    "A03": "A03 – Injection",
    "A04": "A04 – Insecure Design",
    "A05": "A05 – Security Misconfiguration",
    "A06": "A06 – Vulnerable & Outdated Components",
    "A07": "A07 – Identification & Authentication Failures",
    "A08": "A08 – Software & Data Integrity Failures",
    "A09": "A09 – Security Logging & Monitoring Failures",
    "A10": "A10 – Server-Side Request Forgery",
}

PCI_REQUIREMENTS: Dict[str, str] = {
    "PCI-DSS 1.3":   "Restrict inbound and outbound network traffic",
    "PCI-DSS 2.2":   "Develop configuration standards for all system components",
    "PCI-DSS 2.3":   "Encrypt all non-console administrative access",
    "PCI-DSS 3.4":   "Render PAN unreadable anywhere it is stored",
    "PCI-DSS 3.5":   "Protect cryptographic keys",
    "PCI-DSS 4.2":   "Never send unprotected PANs by end-user messaging technologies",
    "PCI-DSS 6.2.1": "Bespoke and custom software developed securely",
    "PCI-DSS 6.2.2": "Software development personnel trained in security",
    "PCI-DSS 6.2.4": "Prevent common software attacks (injection, XSS, etc.)",
    "PCI-DSS 6.3.3": "All software components are protected from known vulnerabilities",
    "PCI-DSS 6.4.1": "Prevent web-facing apps from being compromised",
    "PCI-DSS 6.4.2": "Automated technical solution to detect and prevent attacks",
    "PCI-DSS 7.1":   "Limit access to system components to only those who need it",
    "PCI-DSS 7.2":   "Access control systems/processes prevent unauthorized access",
    "PCI-DSS 8.2":   "User IDs and authentication factors are managed",
    "PCI-DSS 8.3":   "User authentication for users and administrators is managed",
    "PCI-DSS 8.4":   "Multi-factor authentication implemented",
    "PCI-DSS 10.2":  "Audit logs capture all individual user access to cardholder data",
    "PCI-DSS 10.3":  "Audit logs are protected from destruction and unauthorized modifications",
}

SOC2_CRITERIA: Dict[str, str] = {
    "CC6.1":  "Logical and physical access controls — registration and authorization",
    "CC6.2":  "Prior to issuing system credentials, entity registers and authorizes new users",
    "CC6.3":  "Role-based access controls are implemented",
    "CC6.6":  "Logical access security measures restrict access from outside the boundaries",
    "CC6.7":  "Transmission of data is restricted to authorized users",
    "CC6.8":  "Controls prevent or detect unauthorized or malicious software",
    "CC7.1":  "Configuration management — detection of vulnerabilities in infrastructure",
    "CC7.2":  "Monitor system components for anomalies",
    "CC7.3":  "Evaluate the impact of anomalies and act to mitigate",
    "CC8.1":  "Change management controls — authorized, tested, and documented",
    "CC9.2":  "Risk mitigation activities — encryption and data protection",
    "A1.2":   "Environmental protections and recovery from disruptions",
    "PI1.1":  "Processing integrity — complete, valid, accurate, timely processing",
}


class ComplianceService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def get_compliance_data(
        self, scan_id: str, framework: str, user: dict
    ) -> Optional[Dict[str, Any]]:
        """Return structured compliance mapping for a scan."""
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return None

        vulns = scan.get("vulnerabilities", [])
        framework = framework.lower()

        if framework == "owasp":
            return self._map_owasp(scan_id, vulns, scan)
        elif framework == "pci-dss":
            return self._map_pci(scan_id, vulns, scan)
        elif framework == "soc2":
            return self._map_soc2(scan_id, vulns, scan)
        else:
            return None

    def _extract_owasp_category(self, vuln: dict) -> Optional[str]:
        owasp = vuln.get("owasp") or ""
        for key in OWASP_LABELS:
            if key in owasp:
                return key
        return None

    def _map_owasp(self, scan_id: str, vulns: list, scan: dict) -> dict:
        categories: Dict[str, dict] = {}
        for key, label in OWASP_LABELS.items():
            categories[key] = {
                "id": key, "label": label,
                "status": "PASS", "findings": [], "count": 0,
            }

        for v in vulns:
            cat = self._extract_owasp_category(v)
            if cat and cat in categories:
                categories[cat]["findings"].append({
                    "id":       v.get("id"),
                    "type":     v.get("type"),
                    "severity": v.get("severity"),
                    "file":     (v.get("location") or {}).get("file", ""),
                    "line":     (v.get("location") or {}).get("start_line", 0),
                })
                categories[cat]["count"] += 1
                sev = (v.get("severity") or "").lower()
                if sev in ("critical", "high"):
                    categories[cat]["status"] = "FAIL"
                elif categories[cat]["status"] == "PASS":
                    categories[cat]["status"] = "WARN"

        passed = sum(1 for c in categories.values() if c["status"] == "PASS")
        warnings = sum(1 for c in categories.values() if c["status"] == "WARN")
        total = len(categories)
        score = round((passed + warnings * 0.5) / total * 100) if total else 0
        return {
            "framework": "OWASP Top 10 2021",
            "scan_id": scan_id,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_controls": total,
                "passed": passed,
                "failed": sum(1 for c in categories.values() if c["status"] == "FAIL"),
                "warnings": warnings,
                "score": score,
            },
            "controls": list(categories.values()),
        }

    def _map_pci(self, scan_id: str, vulns: list, scan: dict) -> dict:
        req_hits: Dict[str, List[dict]] = {r: [] for r in PCI_REQUIREMENTS}

        for v in vulns:
            cat = self._extract_owasp_category(v)
            if not cat:
                continue
            for req in OWASP_TO_PCI.get(cat, []):
                if req in req_hits:
                    req_hits[req].append({
                        "id":       v.get("id"),
                        "type":     v.get("type"),
                        "severity": v.get("severity"),
                        "owasp":    cat,
                        "file":     (v.get("location") or {}).get("file", ""),
                    })

        controls = []
        for req, desc in PCI_REQUIREMENTS.items():
            findings = req_hits.get(req, [])
            has_critical = any(
                (f.get("severity") or "").lower() in ("critical", "high") for f in findings
            )
            controls.append({
                "id":          req,
                "description": desc,
                "status":      "FAIL" if has_critical else ("WARN" if findings else "PASS"),
                "findings":    findings,
                "count":       len(findings),
            })

        passed = sum(1 for c in controls if c["status"] == "PASS")
        warnings = sum(1 for c in controls if c["status"] == "WARN")
        total = len(controls)
        score = round((passed + warnings * 0.5) / total * 100) if total else 0
        return {
            "framework": "PCI-DSS 4.0",
            "scan_id": scan_id,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_controls": total,
                "passed": passed,
                "failed": sum(1 for c in controls if c["status"] == "FAIL"),
                "warnings": warnings,
                "score": score,
            },
            "controls": controls,
        }

    def _map_soc2(self, scan_id: str, vulns: list, scan: dict) -> dict:
        crit_hits: Dict[str, List[dict]] = {c: [] for c in SOC2_CRITERIA}

        for v in vulns:
            cat = self._extract_owasp_category(v)
            if not cat:
                continue
            for crit in OWASP_TO_SOC2.get(cat, []):
                if crit in crit_hits:
                    crit_hits[crit].append({
                        "id":       v.get("id"),
                        "type":     v.get("type"),
                        "severity": v.get("severity"),
                        "owasp":    cat,
                        "file":     (v.get("location") or {}).get("file", ""),
                    })

        controls = []
        for crit, desc in SOC2_CRITERIA.items():
            findings = crit_hits.get(crit, [])
            has_critical = any(
                (f.get("severity") or "").lower() in ("critical", "high") for f in findings
            )
            controls.append({
                "id":          crit,
                "description": desc,
                "status":      "FAIL" if has_critical else ("WARN" if findings else "PASS"),
                "findings":    findings,
                "count":       len(findings),
            })

        passed = sum(1 for c in controls if c["status"] == "PASS")
        warnings = sum(1 for c in controls if c["status"] == "WARN")
        total = len(controls)
        score = round((passed + warnings * 0.5) / total * 100) if total else 0
        return {
            "framework": "SOC2 Type II (Trust Service Criteria)",
            "scan_id": scan_id,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_controls": total,
                "passed": passed,
                "failed": sum(1 for c in controls if c["status"] == "FAIL"),
                "warnings": warnings,
                "score": score,
            },
            "controls": controls,
        }

    async def export_compliance_pdf(
        self, scan_id: str, framework: str, user: dict
    ) -> Optional[bytes]:
        """Generate a compliance PDF report using reportlab."""
        data = await self.get_compliance_data(scan_id, framework, user)
        if not data:
            return None
        try:
            return self._build_pdf(data)
        except Exception as exc:
            logger.error(f"Compliance PDF generation failed: {exc}")
            return None

    def _build_pdf(self, data: dict) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        CYAN   = colors.HexColor("#22d3ee")
        DARK   = colors.HexColor("#0f172a")
        FAIL   = colors.HexColor("#ef4444")
        WARN   = colors.HexColor("#f97316")
        PASS_C = colors.HexColor("#22c55e")
        GRAY   = colors.HexColor("#64748b")
        LIGHT  = colors.HexColor("#f1f5f9")

        title_style = ParagraphStyle("VTitle", parent=styles["Title"],
                                     textColor=CYAN, fontSize=22, spaceAfter=4)
        sub_style   = ParagraphStyle("VSub",   parent=styles["Normal"],
                                     textColor=GRAY, fontSize=10, spaceAfter=12)
        h2_style    = ParagraphStyle("VH2",    parent=styles["Heading2"],
                                     textColor=DARK, fontSize=13, spaceBefore=16, spaceAfter=6)
        body_style  = ParagraphStyle("VBody",  parent=styles["Normal"],
                                     fontSize=9, textColor=DARK)

        story = []

        # Header
        story.append(Paragraph("VULCAN", title_style))
        story.append(Paragraph(f"{data['framework']} Compliance Report", sub_style))
        story.append(Paragraph(f"Scan ID: {data['scan_id']}  |  Generated: {data['generated_at'][:19].replace('T', ' ')} UTC", body_style))
        story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=12))

        # Summary banner
        s = data["summary"]
        score_color = PASS_C if s["score"] >= 80 else (WARN if s["score"] >= 60 else FAIL)
        summary_data = [
            ["Compliance Score", "Controls Passed", "Failed", "Warnings"],
            [
                Paragraph(f'<font color="{score_color.hexval()}" size="16"><b>{s["score"]}%</b></font>', body_style),
                Paragraph(f'<font color="#22c55e"><b>{s["passed"]}</b></font>', body_style),
                Paragraph(f'<font color="#ef4444"><b>{s["failed"]}</b></font>', body_style),
                Paragraph(f'<font color="#f97316"><b>{s["warnings"]}</b></font>', body_style),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[4*cm, 4*cm, 3*cm, 3*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTSIZE",   (0, 0), (-1, 0), 10),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHT",  (0, 0), (-1, -1), 28),
            ("GRID",       (0, 0), (-1, -1), 0.5, GRAY),
            ("BACKGROUND", (0, 1), (-1, -1), LIGHT),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 16))

        # Controls table
        story.append(Paragraph("Control Assessment", h2_style))
        col_w = [2.5*cm, 9*cm, 2*cm, 2*cm]
        header_row = ["Control", "Description", "Status", "Findings"]
        rows = [header_row]
        for ctrl in data["controls"]:
            status = ctrl["status"]
            status_color = "#ef4444" if status == "FAIL" else ("#f97316" if status == "WARN" else "#22c55e")
            rows.append([
                Paragraph(f"<b>{ctrl['id']}</b>", body_style),
                Paragraph(ctrl.get("description", ctrl.get("label", "")), body_style),
                Paragraph(f'<font color="{status_color}"><b>{status}</b></font>', body_style),
                Paragraph(str(ctrl["count"]), body_style),
            ])

        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("GRID",       (0, 0), (-1, -1), 0.3, GRAY),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)

        # Findings detail for failed controls
        failed = [c for c in data["controls"] if c["status"] == "FAIL" and c.get("findings")]
        if failed:
            story.append(Spacer(1, 16))
            story.append(Paragraph("Failed Control Findings", h2_style))
            for ctrl in failed:
                story.append(Paragraph(f"<b>{ctrl['id']}</b>: {ctrl.get('description', ctrl.get('label', ''))}", body_style))
                for f in ctrl["findings"][:5]:
                    sev = (f.get("severity") or "").upper()
                    story.append(Paragraph(
                        f"  • [{sev}] {f.get('type', '')} — {f.get('file', '')}",
                        body_style
                    ))
                story.append(Spacer(1, 6))

        # Footer
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY, spaceBefore=16))
        story.append(Paragraph(
            "Generated by Vulcan Security Platform. This report is for internal security review only.",
            ParagraphStyle("footer", parent=body_style, textColor=GRAY, fontSize=7)
        ))

        doc.build(story)
        return buf.getvalue()
