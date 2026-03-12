# report_generator.py
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# --- Color palette ---
DARK_BG = colors.HexColor("#0E1117")
ACCENT = colors.HexColor("#00C8FF")
WHITE = colors.white
GRAY = colors.HexColor("#94A3B8")
RED = colors.HexColor("#ef4444")
ORANGE = colors.HexColor("#f97316")
YELLOW = colors.HexColor("#eab308")
GREEN = colors.HexColor("#22c55e")
DARK_CARD = colors.HexColor("#1E293B")
BORDER = colors.HexColor("#334155")


def _verdict_color(verdict: str):
    mapping = {
        "CRITICAL": RED,
        "HIGH": ORANGE,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
        "CLEAN": GREEN,
    }
    return mapping.get(verdict.upper(), GRAY)


def generate_report(scan_data: dict) -> bytes:
    """
    Generate a professional PDF report from scan data.
    Returns PDF as bytes for Streamlit download button.
    
    scan_data keys:
        indicator, indicator_type, vt_result, abuseipdb_result,
        greynoise_result, shodan_result, threat_score, ai_summary
    """
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    styles = getSampleStyleSheet()

    # --- Custom styles ---
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Normal"],
        fontSize=22,
        textColor=WHITE,
        spaceAfter=4,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=GRAY,
        spaceAfter=2,
        fontName="Helvetica",
        alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Normal"],
        fontSize=13,
        textColor=ACCENT,
        spaceBefore=12,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        textColor=WHITE,
        spaceAfter=4,
        fontName="Helvetica",
        leading=14,
    )
    label_style = ParagraphStyle(
        "Label",
        parent=styles["Normal"],
        fontSize=9,
        textColor=GRAY,
        fontName="Helvetica",
    )
    value_style = ParagraphStyle(
        "Value",
        parent=styles["Normal"],
        fontSize=9,
        textColor=WHITE,
        fontName="Helvetica-Bold",
    )
    verdict_style = ParagraphStyle(
        "Verdict",
        parent=styles["Normal"],
        fontSize=28,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    score_style = ParagraphStyle(
        "Score",
        parent=styles["Normal"],
        fontSize=13,
        textColor=WHITE,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    )

    elements = []

    # =====================
    # HEADER
    # =====================
    elements.append(Spacer(1, 5*mm))
    elements.append(Paragraph("🛡️ Security Copilot", title_style))
    elements.append(Paragraph("Threat Intelligence Report", subtitle_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        subtitle_style
    ))
    elements.append(Spacer(1, 4*mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    elements.append(Spacer(1, 4*mm))

    # =====================
    # INDICATOR INFO
    # =====================
    indicator = scan_data.get("indicator", "Unknown")
    indicator_type = scan_data.get("indicator_type", "Unknown")

    elements.append(Paragraph("Investigation Target", section_style))

    info_data = [
        [Paragraph("Indicator", label_style), Paragraph(indicator, value_style)],
        [Paragraph("Type", label_style), Paragraph(indicator_type.upper(), value_style)],
        [Paragraph("Report Date", label_style), Paragraph(datetime.now().strftime("%B %d, %Y"), value_style)],
    ]

    info_table = Table(info_data, colWidths=[40*mm, 130*mm])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
        ("ROWBACKGROUND", (0, 0), (-1, -1), DARK_CARD),
        ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 4*mm))

    # =====================
    # THREAT VERDICT BOX
    # =====================
    threat_score = scan_data.get("threat_score", {})
    if threat_score:
        verdict = threat_score.get("verdict", "UNKNOWN")
        score = threat_score.get("score", 0)
        recommendation = threat_score.get("recommendation", "")
        evidence = threat_score.get("evidence", [])
        verdict_color = _verdict_color(verdict)

        elements.append(Paragraph("Threat Assessment", section_style))

        verdict_data = [
            [
                Paragraph(f'<font color="#{verdict_color.hexval()[2:]}">⬤</font> {verdict} — Threat Score: {score} / 100', score_style)
            ]
        ]

        verdict_table = Table(verdict_data, colWidths=[170*mm])
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("BOX", (0, 0), (-1, -1), 0, colors.transparent),
            ("PADDING", (0, 0), (-1, -1), 12),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(verdict_table)
        elements.append(Spacer(1, 3*mm))

        # Evidence table
        if evidence:
            elements.append(Paragraph("Scoring Evidence", section_style))
            ev_data = [[Paragraph(f"• {e}", body_style)] for e in evidence]
            ev_table = Table(ev_data, colWidths=[170*mm])
            ev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(ev_table)
            elements.append(Spacer(1, 3*mm))

        # Recommendation
        elements.append(Paragraph("Recommendation", section_style))
        rec_table = Table(
            [[Paragraph(recommendation, body_style)]],
            colWidths=[170*mm]
        )
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, verdict_color),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(rec_table)
        elements.append(Spacer(1, 4*mm))

    # =====================
    # TOOL RESULTS
    # =====================
    elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    elements.append(Paragraph("Intelligence Source Results", section_style))

    # VirusTotal
    vt = scan_data.get("vt_result")
    if vt and not vt.get("error"):
        elements.append(Paragraph("VirusTotal", section_style))
        stats = vt.get("stats", vt)
        vt_rows = [
            ["Malicious Detections", str(stats.get("malicious", 0))],
            ["Suspicious", str(stats.get("suspicious", 0))],
            ["Harmless", str(stats.get("harmless", 0))],
            ["Undetected", str(stats.get("undetected", 0))],
        ]
        if vt.get("reputation"):
            vt_rows.append(["Reputation Score", str(vt.get("reputation"))])
        if vt.get("country"):
            vt_rows.append(["Country", str(vt.get("country"))])
        if vt.get("as_owner"):
            vt_rows.append(["AS Owner", str(vt.get("as_owner"))])

        vt_data = [
            [Paragraph(r[0], label_style), Paragraph(r[1], value_style)]
            for r in vt_rows
        ]
        vt_table = Table(vt_data, colWidths=[60*mm, 110*mm])
        vt_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(vt_table)
        elements.append(Spacer(1, 3*mm))

    # AbuseIPDB
    abuse = scan_data.get("abuseipdb_result")
    if abuse and not abuse.get("error"):
        elements.append(Paragraph("AbuseIPDB", section_style))
        abuse_rows = [
            ["Confidence Score", f"{abuse.get('abuse_confidence_score', 0)}%"],
            ["Total Reports", str(abuse.get("total_reports", 0))],
            ["ISP", str(abuse.get("isp", "Unknown"))],
            ["Country", str(abuse.get("country_code", "Unknown"))],
            ["Usage Type", str(abuse.get("usage_type", "Unknown"))],
        ]
        abuse_data = [
            [Paragraph(r[0], label_style), Paragraph(r[1], value_style)]
            for r in abuse_rows
        ]
        abuse_table = Table(abuse_data, colWidths=[60*mm, 110*mm])
        abuse_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(abuse_table)
        elements.append(Spacer(1, 3*mm))

    # GreyNoise
    gn = scan_data.get("greynoise_result")
    if gn and not gn.get("error"):
        elements.append(Paragraph("GreyNoise", section_style))
        gn_rows = [
            ["Classification", str(gn.get("classification", "Unknown"))],
            ["Noise", "Yes" if gn.get("noise") else "No"],
            ["RIOT (Benign)", "Yes" if gn.get("riot") else "No"],
            ["Message", str(gn.get("message", "N/A"))],
        ]
        gn_data = [
            [Paragraph(r[0], label_style), Paragraph(r[1], value_style)]
            for r in gn_rows
        ]
        gn_table = Table(gn_data, colWidths=[60*mm, 110*mm])
        gn_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(gn_table)
        elements.append(Spacer(1, 3*mm))

    # Shodan
    shodan = scan_data.get("shodan_result")
    if shodan and not shodan.get("error"):
        elements.append(Paragraph("Shodan", section_style))
        ports = shodan.get("ports", [])
        vulns = shodan.get("vulns", [])
        shodan_rows = [
            ["Open Ports", ", ".join(str(p) for p in ports[:10]) or "None"],
            ["Vulnerabilities", ", ".join(list(vulns)[:5]) or "None"],
            ["Organization", str(shodan.get("org", "Unknown"))],
            ["OS", str(shodan.get("os", "Unknown"))],
        ]
        shodan_data = [
            [Paragraph(r[0], label_style), Paragraph(r[1], value_style)]
            for r in shodan_rows
        ]
        shodan_table = Table(shodan_data, colWidths=[60*mm, 110*mm])
        shodan_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(shodan_table)
        elements.append(Spacer(1, 3*mm))

    # =====================
    # AI SUMMARY
    # =====================
    ai_summary = scan_data.get("ai_summary", "")
    if ai_summary:
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Paragraph("AI Analysis Summary", section_style))
        # Clean markdown symbols for PDF
        clean_summary = ai_summary.replace("**", "").replace("##", "").replace("* ", "• ")
        summary_table = Table(
            [[Paragraph(clean_summary[:2000], body_style)]],
            colWidths=[170*mm]
        )
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_CARD),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(summary_table)

    # =====================
    # FOOTER
    # =====================
    elements.append(Spacer(1, 6*mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    elements.append(Spacer(1, 2*mm))
    elements.append(Paragraph(
        "Security Copilot — Threat Intelligence Report | Confidential",
        subtitle_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()