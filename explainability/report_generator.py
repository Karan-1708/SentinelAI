"""
PDF incident report generator using ReportLab Platypus.

Why ReportLab over WeasyPrint/fpdf2:
  - Pure Python — no native library deps (libpango, libcairo, etc.)
  - Platypus flowable framework handles dynamic multi-page layout naturally
  - SHAP matplotlib figures embedded as Image flowables
  - Deterministic output on any OS

Report structure per incident:
  1. Header (severity badge, incident ID, timestamp)
  2. Summary table (label, confidence, anomaly score, source/dest IP)
  3. MITRE ATT&CK techniques section
  4. SHAP waterfall chart (matplotlib figure embedded)
  5. Remediation playbook (rule-based, 3-5 steps per threat label)

Security note:
  Every user-influenced string (labels, IPs, MITRE names/URLs) is escaped with
  ``xml.sax.saxutils.escape`` before being handed to Platypus ``Paragraph``.
  Platypus interprets `<` / `>` / `&` inside markup — without escaping, a
  crafted string ("<font color=red>x</font>") could inject styling, and a
  malformed one could break the entire flowable stream. IPs are validated
  through ``ipaddress`` so junk values are collapsed to "—".
"""

from __future__ import annotations

import io
import ipaddress
import logging
from datetime import datetime
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

logger = logging.getLogger(__name__)


class ReportRenderError(RuntimeError):
    """Raised when the SHAP chart or PDF assembly fails."""


# Rule-based remediation playbook — actionable steps per threat category
REMEDIATION_PLAYBOOK: dict[str, list[str]] = {
    "DDoS": [
        "Enable rate limiting on edge routers (max 10,000 PPS per source IP).",
        "Activate BGP Blackhole routing for confirmed attacking source IP ranges.",
        "Scale out load balancers horizontally and enable SYN cookies on all nodes.",
        "Contact upstream ISP for traffic scrubbing if attack sustains > 10 minutes.",
        "Review and harden firewall rules to block amplification vectors (DNS, NTP, SSDP).",
    ],
    "PortScan": [
        "Block source IP at perimeter firewall for 24 hours minimum.",
        "Audit firewall rules for unnecessarily exposed services and close unused ports.",
        "Enable port scan detection on IDS (Snort SID:1228, Suricata ET SCAN rules).",
        "Review service banners — disable version disclosure on SSH, HTTP, FTP.",
    ],
    "Brute Force": [
        "Lock source IP after 5 failed attempts for 30 minutes (fail2ban or equivalent).",
        "Enforce MFA on all externally accessible authentication endpoints immediately.",
        "Rotate credentials for the targeted account and audit recent login history.",
        "Disable password authentication on SSH — switch to key-based auth only.",
    ],
    "FTP-Patator": [
        "Block source IP at perimeter firewall.",
        "Disable FTP if not required — migrate to SFTP/SCP.",
        "Enforce account lockout after 3 failed FTP authentication attempts.",
        "Rotate FTP credentials for all accounts on affected server.",
    ],
    "SSH-Patator": [
        "Block source IP at perimeter firewall.",
        "Disable root login via SSH (PermitRootLogin no in sshd_config).",
        "Enforce SSH key-based authentication and disable password auth.",
        "Consider moving SSH to a non-standard port to reduce automated scanning.",
    ],
    "Botnet": [
        "Isolate affected host from network immediately — quarantine VLAN.",
        "Capture network traffic from host for forensic analysis before remediation.",
        "Identify and terminate C2 communication channels (check DNS queries, HTTP POSTs).",
        "Re-image compromised host from known-good baseline after evidence collection.",
        "Scan all hosts on same subnet for similar C2 traffic indicators.",
    ],
    "Bot": [
        "Isolate affected host from network immediately — quarantine VLAN.",
        "Capture network traffic from host for forensic analysis before remediation.",
        "Identify and terminate C2 communication channels.",
        "Re-image compromised host from known-good baseline.",
    ],
    "Web Attack": [
        "Review web application firewall (WAF) logs for request patterns.",
        "Block attacking source IP at WAF and perimeter firewall.",
        "Patch the targeted web application component to latest version.",
        "Enable strict input validation and parameterized queries to prevent SQL injection.",
        "Review and rotate application API keys and database credentials.",
    ],
    "Infiltration": [
        "Isolate affected system immediately — suspend network access.",
        "Initiate full forensic investigation — preserve disk image and memory dump.",
        "Audit all privileged account activity over the past 72 hours.",
        "Rotate all credentials that may have been accessible to the compromised process.",
        "Engage incident response team for full scope assessment.",
    ],
    "Heartbleed": [
        "Patch OpenSSL to version 1.0.1g or later IMMEDIATELY.",
        "Regenerate all TLS certificates and private keys on affected servers.",
        "Revoke and reissue compromised certificates with your CA.",
        "Rotate all passwords and session tokens that may have been leaked from memory.",
        "Audit access logs for exploitation attempts over past 30 days.",
    ],
    "DoS": [
        "Enable rate limiting on edge routers for the targeted service.",
        "Scale out affected service horizontally to absorb the load.",
        "Identify and block attacking source IP ranges at perimeter.",
        "Enable connection timeout reduction on affected service (shorter keepalive).",
    ],
    "BENIGN": [
        "No action required — traffic classified as benign.",
        "Continue monitoring for behavioral anomalies.",
    ],
}


def _safe(value: object) -> str:
    """Coerce ``value`` to a Platypus-safe string.

    XML-escape everything so `<script>` or stray ampersands cannot break the
    flowable or inject styling. Also collapse embedded control characters —
    those otherwise blow up ReportLab's paragraph parser.
    """
    if value is None:
        return "—"
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    return xml_escape(text)


def _safe_ip(value: object) -> str:
    """Render an IP if valid, otherwise "—". Guards against CRLF/table breaks."""
    if value in (None, ""):
        return "—"
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return "—"
    return _safe(str(ip))


def _safe_url(value: object) -> Optional[str]:
    """Return an escaped URL only if it is https and well-formed, else None."""
    if not value:
        return None
    text = str(value).strip()
    lower = text.lower()
    if not (lower.startswith("https://") or lower.startswith("http://")):
        return None
    return _safe(text)


class IncidentReportGenerator:
    """Generates PDF incident reports using ReportLab Platypus."""

    def generate(
        self,
        incident: dict,
        shap_data: dict,
        mitre_data: list[dict],
    ) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Image,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=20, spaceAfter=6)
        heading2_style = ParagraphStyle(
            "heading2", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6
        )
        normal_style = styles["Normal"]
        bullet_style = ParagraphStyle(
            "bullet", parent=styles["Normal"], leftIndent=16, spaceBefore=2
        )

        severity_colors = {
            "CRITICAL": colors.HexColor("#dc2626"),
            "HIGH": colors.HexColor("#ea580c"),
            "MEDIUM": colors.HexColor("#d97706"),
            "LOW": colors.HexColor("#2563eb"),
            "INFO": colors.HexColor("#16a34a"),
        }
        severity = str(incident.get("severity") or "UNKNOWN")
        sev_color = severity_colors.get(severity, colors.grey)

        story = []

        # ── Header ──────────────────────────────────────────────────────
        story.append(Paragraph("SentinelAI Incident Report", title_style))
        story.append(HRFlowable(width="100%", thickness=2, color=sev_color))
        story.append(Spacer(1, 0.3 * cm))

        created = incident.get("created_at")
        if isinstance(created, datetime):
            created_str = created.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            created_str = str(created) if created else "N/A"

        story.append(
            Paragraph(
                f"<b>Incident ID:</b> {_safe(incident.get('id', 'N/A'))} &nbsp;&nbsp; "
                f"<b>Generated:</b> {_safe(created_str)}",
                normal_style,
            )
        )
        story.append(Spacer(1, 0.5 * cm))

        # ── Summary Table ───────────────────────────────────────────────
        story.append(Paragraph("Incident Summary", heading2_style))

        try:
            confidence = float(incident.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        try:
            anomaly = float(incident.get("anomaly_score") or 0.0)
        except (TypeError, ValueError):
            anomaly = 0.0

        table_data = [
            ["Field", "Value"],
            ["Severity", _safe(severity)],
            ["Threat Classification", _safe(incident.get("threat_label", "N/A"))],
            ["Confidence", _safe(f"{confidence:.1%}")],
            ["Anomaly Score", _safe(f"{anomaly:.4f}")],
            ["Source IP", _safe_ip(incident.get("source_ip"))],
            ["Destination IP", _safe_ip(incident.get("dest_ip"))],
        ]

        table = Table(table_data, colWidths=[5 * cm, 11 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BACKGROUND", (0, 1), (-1, 1), sev_color),
            ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 2), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))

        # ── MITRE ATT&CK Section ────────────────────────────────────────
        if mitre_data:
            story.append(Paragraph("MITRE ATT&amp;CK Techniques", heading2_style))
            for ttp in mitre_data:
                tid = _safe(ttp.get("technique_id", "N/A"))
                name = _safe(ttp.get("technique_name", ttp.get("technique_id", "")))
                tactic = _safe(str(ttp.get("tactic", "unknown")).replace("-", " ").title())
                url = _safe_url(ttp.get("url"))
                line = f"&bull; <b>{tid}</b> — {name} &nbsp;<i>({tactic})</i>"
                if url:
                    line += f" <font color='blue'>[{url}]</font>"
                story.append(Paragraph(line, bullet_style))
            story.append(Spacer(1, 0.5 * cm))

        # ── SHAP Explanation ────────────────────────────────────────────
        contributions = shap_data.get("feature_contributions", [])
        if contributions:
            story.append(Paragraph("Feature Importance (SHAP Explanation)", heading2_style))
            story.append(
                Paragraph(
                    "The chart below shows which network features most influenced this "
                    "classification. Red bars push toward the predicted threat label; "
                    "blue bars push toward benign classification.",
                    normal_style,
                )
            )
            story.append(Spacer(1, 0.3 * cm))

            shap_img_bytes = self._render_shap_chart(contributions)
            if shap_img_bytes:
                story.append(Image(io.BytesIO(shap_img_bytes), width=14 * cm, height=7 * cm))
            story.append(Spacer(1, 0.5 * cm))

        # ── Remediation Playbook ────────────────────────────────────────
        story.append(Paragraph("Recommended Remediation Steps", heading2_style))
        label = str(incident.get("threat_label") or "BENIGN")
        steps = REMEDIATION_PLAYBOOK.get(label, REMEDIATION_PLAYBOOK.get("BENIGN", []))
        for i, step in enumerate(steps, 1):
            story.append(Paragraph(f"{i}. {_safe(step)}", bullet_style))
        story.append(Spacer(1, 0.5 * cm))

        # ── Footer ──────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                "Generated by SentinelAI — Autonomous Threat Intelligence Platform. "
                "This report was produced by an AI system. Verify findings before taking action.",
                ParagraphStyle("footer", parent=normal_style, fontSize=8, textColor=colors.grey),
            )
        )

        try:
            doc.build(story)
        except Exception as exc:
            logger.exception("Platypus doc.build failed")
            raise ReportRenderError("Failed to render PDF") from exc

        return buffer.getvalue()

    def _render_shap_chart(self, contributions: list[dict]) -> Optional[bytes]:
        """Render SHAP values as a horizontal bar chart. Raises on failure."""
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        sorted_contribs = sorted(
            contributions,
            key=lambda x: abs(x.get("shap_value", 0)),
            reverse=True,
        )[:15]

        if not sorted_contribs:
            return None

        try:
            features = [str(c["feature"]) for c in sorted_contribs]
            values = [float(c["shap_value"]) for c in sorted_contribs]
        except (KeyError, ValueError, TypeError) as exc:
            logger.exception("Malformed SHAP contributions payload")
            raise ReportRenderError("Malformed SHAP payload") from exc

        colors_list = ["#dc2626" if v > 0 else "#2563eb" for v in values]

        fig, ax = plt.subplots(figsize=(8, 5))
        try:
            ax.barh(range(len(features)), values, color=colors_list, height=0.6)
            ax.set_yticks(range(len(features)))
            ax.set_yticklabels(features, fontsize=9)
            ax.axvline(0, color="black", linewidth=0.8, linestyle="-")
            ax.set_xlabel("SHAP value (impact on prediction)")
            ax.set_title("Feature Contributions — SHAP Explanation")
            ax.invert_yaxis()
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
            buf.seek(0)
            return buf.read()
        finally:
            plt.close(fig)
