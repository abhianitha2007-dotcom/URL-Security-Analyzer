from datetime import datetime
from xml.sax.saxutils import escape
import os
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


PAGE_WIDTH, PAGE_HEIGHT = A4
REPORT_VERSION = "3.0"
ENGINE_NAME = "Multi-Layer URL Threat Detection Engine"

# Brand palette
NAVY = colors.HexColor("#07111F")
NAVY_2 = colors.HexColor("#0B1728")
NAVY_3 = colors.HexColor("#122238")
CYAN = colors.HexColor("#22D3EE")
CYAN_SOFT = colors.HexColor("#E6FAFD")
BLUE = colors.HexColor("#2563EB")
GREEN = colors.HexColor("#16A34A")
GREEN_SOFT = colors.HexColor("#ECFDF3")
AMBER = colors.HexColor("#D97706")
AMBER_SOFT = colors.HexColor("#FFF7E6")
RED = colors.HexColor("#DC2626")
RED_SOFT = colors.HexColor("#FEF2F2")
PURPLE = colors.HexColor("#7C3AED")
SLATE_900 = colors.HexColor("#0F172A")
SLATE_700 = colors.HexColor("#334155")
SLATE_600 = colors.HexColor("#475569")
SLATE_500 = colors.HexColor("#64748B")
SLATE_400 = colors.HexColor("#94A3B8")
SLATE_300 = colors.HexColor("#CBD5E1")
SLATE_200 = colors.HexColor("#E2E8F0")
SLATE_100 = colors.HexColor("#F1F5F9")
SLATE_50 = colors.HexColor("#F8FAFC")
WHITE = colors.white


# ==========================================================
# TEXT HELPERS
# ==========================================================

def remove_emoji(value):
    text = str(value)
    emoji_pattern = re.compile(
        "["
        "\U0001F300-\U0001F5FF"
        "\U0001F600-\U0001F64F"
        "\U0001F680-\U0001F6FF"
        "\U0001F700-\U0001F77F"
        "\U0001F780-\U0001F7FF"
        "\U0001F800-\U0001F8FF"
        "\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FAFF"
        "\u2600-\u26FF"
        "\u2700-\u27BF"
        "]+",
        flags=re.UNICODE,
    )
    return emoji_pattern.sub("", text).strip()


def safe_text(value):
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        if not value:
            return "None"
        return ", ".join(remove_emoji(item) for item in value)
    return remove_emoji(value)


def pdf_text(value):
    return escape(safe_text(value))


def format_list(values, empty="None"):
    if not values:
        return empty
    if not isinstance(values, (list, tuple, set)):
        return safe_text(values)
    return ", ".join(safe_text(value) for value in values)


def get_nested(data, section, field, default="Not Checked"):
    section_data = data.get(section, {}) if isinstance(data, dict) else {}
    if not isinstance(section_data, dict):
        return default
    return section_data.get(field, default)


def get_section(data, key):
    value = data.get(key, {}) if isinstance(data, dict) else {}
    return value if isinstance(value, dict) else {}


def simplify_whois_status(value):
    if not value:
        return "Unknown"
    text = safe_text(value)
    statuses = re.findall(
        r"\b(?:client|server)[A-Za-z]+Prohibited\b|\bok\b",
        text,
    )
    unique_statuses = list(dict.fromkeys(statuses))
    if unique_statuses:
        return ", ".join(unique_statuses)
    if len(text) > 320:
        return text[:317] + "..."
    return text


def format_dns_value(record_type, values):
    if not values:
        return "Not Available"
    if not isinstance(values, (list, tuple, set)):
        return safe_text(values)
    values = list(values)
    if record_type != "TXT":
        return format_list(values, "Not Available")
    shortened = []
    for value in values[:5]:
        text = safe_text(value)
        if len(text) > 135:
            text = text[:132] + "..."
        shortened.append(text)
    result = ", ".join(shortened)
    if len(values) > 5:
        result += f" ... and {len(values) - 5} more record(s)"
    return result


# ==========================================================
# RISK HELPERS
# ==========================================================

def normalize_score(value):
    try:
        return max(0, min(int(value), 100))
    except (TypeError, ValueError):
        return 0


def get_risk_details(score):
    score = normalize_score(score)
    if score > 75:
        return {
            "label": "CRITICAL",
            "color": RED,
            "soft": RED_SOFT,
            "recommendation": "Do not visit this website or provide any sensitive information.",
        }
    if score > 50:
        return {
            "label": "HIGH RISK",
            "color": RED,
            "soft": RED_SOFT,
            "recommendation": "Avoid credentials, payments and downloads until the URL is independently verified.",
        }
    if score > 30:
        return {
            "label": "MEDIUM RISK",
            "color": AMBER,
            "soft": AMBER_SOFT,
            "recommendation": "Proceed carefully and independently verify the domain and organization.",
        }
    if score > 15:
        return {
            "label": "LOW RISK",
            "color": BLUE,
            "soft": colors.HexColor("#EFF6FF"),
            "recommendation": "Only minor indicators were detected. Continue with normal caution.",
        }
    return {
        "label": "SAFE",
        "color": GREEN,
        "soft": GREEN_SOFT,
        "recommendation": "No major phishing indicators were detected by the completed checks.",
    }


def score_band(score):
    score = normalize_score(score)
    if score <= 15:
        return "Safe"
    if score <= 30:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


# ==========================================================
# STYLES
# ==========================================================

def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverEyebrow",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        tracking=0.8,
        textColor=CYAN,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=27,
        textColor=WHITE,
        spaceAfter=5,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=SLATE_300,
    ))

    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=SLATE_900,
        spaceBefore=3,
        spaceAfter=7,
    ))

    styles.add(ParagraphStyle(
        name="SectionKicker",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        tracking=0.7,
        textColor=CYAN,
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        name="Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=SLATE_700,
    ))

    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.2,
        textColor=SLATE_700,
    ))

    styles.add(ParagraphStyle(
        name="BodySmallBold",
        parent=styles["BodySmall"],
        fontName="Helvetica-Bold",
        textColor=SLATE_900,
    ))

    styles.add(ParagraphStyle(
        name="WhiteSmall",
        parent=styles["BodySmall"],
        textColor=WHITE,
    ))

    styles.add(ParagraphStyle(
        name="WhiteSmallBold",
        parent=styles["WhiteSmall"],
        fontName="Helvetica-Bold",
    ))

    styles.add(ParagraphStyle(
        name="Evidence",
        parent=styles["Body"],
        leftIndent=2,
        firstLineIndent=0,
        spaceAfter=3,
    ))

    styles.add(ParagraphStyle(
        name="Disclaimer",
        parent=styles["BodySmall"],
        fontSize=7,
        leading=9.5,
        textColor=SLATE_500,
    ))

    styles.add(ParagraphStyle(
        name="RiskScore",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=27,
        leading=29,
        alignment=TA_CENTER,
        textColor=SLATE_900,
    ))

    styles.add(ParagraphStyle(
        name="RiskLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=TA_CENTER,
        textColor=SLATE_600,
    ))

    styles.add(ParagraphStyle(
        name="MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=6.8,
        leading=8,
        textColor=SLATE_500,
    ))

    styles.add(ParagraphStyle(
        name="MetaValue",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=SLATE_900,
    ))

    return styles


# ==========================================================
# PAGE CHROME
# ==========================================================

def draw_page_layout(canvas, document):
    canvas.saveState()

    # slim top brand line
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_HEIGHT - 7 * mm, PAGE_WIDTH, 7 * mm, stroke=0, fill=1)
    canvas.setFillColor(CYAN)
    canvas.rect(0, PAGE_HEIGHT - 7 * mm, 44 * mm, 0.9 * mm, stroke=0, fill=1)

    canvas.setFont("Helvetica-Bold", 7.3)
    canvas.setFillColor(WHITE)
    canvas.drawString(15 * mm, PAGE_HEIGHT - 4.8 * mm, "URL SECURITY ANALYZER")

    canvas.setFont("Helvetica", 7.1)
    canvas.setFillColor(SLATE_300)
    canvas.drawRightString(PAGE_WIDTH - 15 * mm, PAGE_HEIGHT - 4.8 * mm, "Security Analysis Report")

    # footer
    canvas.setStrokeColor(SLATE_200)
    canvas.setLineWidth(0.45)
    canvas.line(15 * mm, 13 * mm, PAGE_WIDTH - 15 * mm, 13 * mm)

    canvas.setFont("Helvetica", 6.8)
    canvas.setFillColor(SLATE_500)
    canvas.drawString(15 * mm, 8.5 * mm, f"URL Security Analyzer v{REPORT_VERSION}")
    canvas.drawCentredString(PAGE_WIDTH / 2, 8.5 * mm, ENGINE_NAME)
    canvas.drawRightString(PAGE_WIDTH - 15 * mm, 8.5 * mm, f"Page {document.page}")

    canvas.restoreState()


# ==========================================================
# LAYOUT HELPERS
# ==========================================================

def add_section_title(story, title, styles, kicker=None):
    items = []
    if kicker:
        items.append(Paragraph(pdf_text(kicker.upper()), styles["SectionKicker"]))
    items.append(Paragraph(pdf_text(title), styles["SectionTitle"]))
    story.append(KeepTogether(items))


def add_information_table(story, rows, styles, label_width=52 * mm):
    if not rows:
        return

    formatted_rows = []
    for label, value in rows:
        formatted_rows.append([
            Paragraph(pdf_text(label), styles["BodySmallBold"]),
            Paragraph(pdf_text(value), styles["BodySmall"]),
        ])

    table = Table(
        formatted_rows,
        colWidths=[label_width, 180 * mm - label_width],
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), SLATE_100),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("BOX", (0, 0), (-1, -1), 0.55, SLATE_200),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, SLATE_200),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))


def add_detection_table(story, rows, styles):
    data = [[
        Paragraph("DETECTION MODULE", styles["WhiteSmallBold"]),
        Paragraph("RESULT", styles["WhiteSmallBold"]),
        Paragraph("CHECK SCORE", styles["WhiteSmallBold"]),
    ]]

    for name, result, score in rows:
        score_num = normalize_score(score)
        data.append([
            Paragraph(pdf_text(name), styles["BodySmallBold"]),
            Paragraph(pdf_text(result), styles["BodySmall"]),
            Paragraph(str(score_num), styles["BodySmallBold"]),
        ])

    table = Table(
        data,
        colWidths=[47 * mm, 113 * mm, 20 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )

    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("BOX", (0, 0), (-1, -1), 0.5, SLATE_300),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, SLATE_200),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (2, 1), (2, -1), "CENTER"),
    ]

    for row_index in range(1, len(data)):
        bg = WHITE if row_index % 2 else SLATE_50
        commands.append(("BACKGROUND", (0, row_index), (-1, row_index), bg))

    table.setStyle(TableStyle(commands))
    story.append(table)
    story.append(Spacer(1, 8))


def add_cover_header(story, url, generated_time, styles):
    header = Table(
        [[
            Paragraph(
                "SECURITY INTELLIGENCE REPORT",
                styles["CoverEyebrow"],
            ),
        ], [
            Paragraph("URL Security Analyzer", styles["ReportTitle"]),
        ], [
            Paragraph(
                "Comprehensive URL, domain, network, webpage and threat-intelligence analysis",
                styles["ReportSubtitle"],
            ),
        ], [
            Paragraph(
                f"<b>Target:</b> {pdf_text(url)}<br/><b>Generated:</b> {pdf_text(generated_time)}",
                styles["WhiteSmall"],
            ),
        ]],
        colWidths=[180 * mm],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.8, NAVY_3),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 1),
        ("TOPPADDING", (0, 2), (-1, 2), 0),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 9),
        ("TOPPADDING", (0, 3), (-1, 3), 8),
        ("BOTTOMPADDING", (0, 3), (-1, 3), 11),
        ("LINEABOVE", (0, 3), (-1, 3), 0.45, NAVY_3),
    ]))
    story.append(header)
    story.append(Spacer(1, 10))


def add_risk_dashboard(story, score, verdict, styles):
    details = get_risk_details(score)
    score = normalize_score(score)

    score_card = Table([
        [Paragraph("CALCULATED RISK", styles["RiskLabel"])],
        [Paragraph(f"{score}<font size='12'> / 100</font>", styles["RiskScore"])],
        [Paragraph(pdf_text(verdict), styles["RiskLabel"])],
    ], colWidths=[48 * mm], rowHeights=[10 * mm, 18 * mm, 9 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), details["soft"]),
        ("BOX", (0, 0), (-1, -1), 1, details["color"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    spectrum = Table([
        [
            Paragraph("SAFE", styles["MetaLabel"]),
            Paragraph("LOW", styles["MetaLabel"]),
            Paragraph("MEDIUM", styles["MetaLabel"]),
            Paragraph("HIGH", styles["MetaLabel"]),
            Paragraph("CRITICAL", styles["MetaLabel"]),
        ],
        ["", "", "", "", ""],
        [Paragraph(
            f"<b>Threat level:</b> {pdf_text(details['label'])}<br/>{pdf_text(details['recommendation'])}",
            styles["Body"],
        ), "", "", "", ""],
    ], colWidths=[26.4 * mm] * 5, rowHeights=[7 * mm, 5 * mm, 25 * mm])

    spectrum.setStyle(TableStyle([
        ("SPAN", (0, 2), (4, 2)),
        ("BACKGROUND", (0, 1), (0, 1), GREEN),
        ("BACKGROUND", (1, 1), (1, 1), BLUE),
        ("BACKGROUND", (2, 1), (2, 1), AMBER),
        ("BACKGROUND", (3, 1), (3, 1), colors.HexColor("#F97316")),
        ("BACKGROUND", (4, 1), (4, 1), RED),
        ("BACKGROUND", (0, 2), (4, 2), SLATE_50),
        ("BOX", (0, 0), (4, 2), 0.5, SLATE_200),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("LEFTPADDING", (0, 2), (4, 2), 8),
        ("RIGHTPADDING", (0, 2), (4, 2), 8),
    ]))

    dashboard = Table([[score_card, spectrum]], colWidths=[48 * mm, 132 * mm])
    dashboard.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(dashboard)
    story.append(Spacer(1, 10))


def add_summary_cards(story, report_data, analysis, styles):
    https_status = report_data.get("https_status", "Not Checked")
    tld = report_data.get("tld", "Unknown")
    subdomains = report_data.get("subdomain_count", 0)
    threat = get_section(analysis, "threat_intelligence")
    vt_malicious = threat.get("malicious", 0)

    cards = []
    for label, value in [
        ("HTTPS", https_status),
        ("TOP-LEVEL DOMAIN", tld),
        ("SUBDOMAINS", subdomains),
        ("VT MALICIOUS", vt_malicious),
    ]:
        card = Table([
            [Paragraph(pdf_text(label), styles["MetaLabel"])],
            [Paragraph(pdf_text(value), styles["MetaValue"])],
        ], colWidths=[43 * mm], rowHeights=[7 * mm, 12 * mm])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), WHITE),
            ("BOX", (0, 0), (-1, -1), 0.55, SLATE_200),
            ("LINEABOVE", (0, 0), (-1, 0), 2.0, CYAN),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        cards.append(card)

    row = Table([cards], colWidths=[45 * mm] * 4)
    row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 1),
        ("RIGHTPADDING", (0, 0), (-1, -1), 1),
    ]))
    story.append(row)
    story.append(Spacer(1, 10))


def add_evidence_summary(story, reasons, styles):
    add_section_title(story, "Evidence Summary", styles, "Decision Factors")
    reasons = reasons or ["No major suspicious indicators were detected."]
    data = []
    for reason in reasons:
        data.append([
            Paragraph("•", styles["BodySmallBold"]),
            Paragraph(pdf_text(reason), styles["Body"]),
        ])
    table = Table(data, colWidths=[7 * mm, 173 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SLATE_50),
        ("BOX", (0, 0), (-1, -1), 0.55, SLATE_200),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR", (0, 0), (0, -1), CYAN),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))


# ==========================================================
# DETECTION RESULTS
# ==========================================================

def build_detection_rows(analysis):
    keyword_data = get_section(analysis, "keywords")
    keyword_count = keyword_data.get("count", 0)
    keyword_matches = keyword_data.get("matches", [])
    if keyword_count:
        keyword_result = f"{keyword_count} suspicious keyword(s): {format_list(keyword_matches)}"
    else:
        keyword_result = "No suspicious keywords detected"

    domain_age = get_section(analysis, "domain_age")
    domain_age_result = domain_age.get("message") or domain_age.get("status") or "Not Checked"

    module_keys = [
        ("HTTPS", "https"),
        ("IP Address", "ip_address"),
        ("Suspicious Keywords", None),
        ("URL Length", "url_length"),
        ("Subdomains", "subdomains"),
        ("At Symbol", "at_symbol"),
        ("URL Shortener", "shortener"),
        ("Hyphens", "hyphens"),
        ("Top-Level Domain", "tld"),
        ("Domain Age", None),
        ("Domain Similarity", "domain_similarity"),
        ("Typosquatting", "typosquatting"),
        ("Homograph", "homograph"),
        ("Punycode", "punycode"),
        ("Domain Entropy", "entropy"),
        ("Port", "port"),
        ("Query Parameters", "query_parameters"),
        ("Email Address", "email_address"),
        ("File Extension", "file_extension"),
        ("Redirects", "redirects"),
        ("Security Headers", "security_headers"),
        ("JavaScript", "javascript"),
        ("Forms", "forms"),
        ("Page Content", "content"),
        ("Favicon", "favicon"),
        ("robots.txt", "robots"),
        ("Sitemap", "sitemap"),
        ("Response Headers", "response_headers"),
        ("Technology", "technology"),
        ("Sensitive File Exposure", "file_exposure"),
        ("HTTP Methods", "http_methods"),
        ("Cookie Security", "cookie_security"),
        ("CORS", "cors"),
        ("Mixed Content", "mixed_content"),
        ("Threat Intelligence", "threat_intelligence"),
    ]

    rows = []
    for label, key in module_keys:
        if label == "Suspicious Keywords":
            rows.append((label, keyword_result, keyword_data.get("score", 0)))
        elif label == "Domain Age":
            rows.append((label, domain_age_result, domain_age.get("score", 0)))
        else:
            section = get_section(analysis, key)
            rows.append((label, section.get("status", "Not Checked"), section.get("score", 0)))
    return rows


# ==========================================================
# RECOMMENDATIONS
# ==========================================================

def get_recommendations(score):
    score = normalize_score(score)
    if score > 75:
        return [
            "Do not open or continue using this website.",
            "Do not enter passwords, OTPs, banking or payment information.",
            "Do not download files or install applications from this URL.",
            "Report the URL to your browser, organization or security team.",
            "Use the organization's official website or mobile application instead.",
        ]
    if score > 50:
        return [
            "Avoid entering personal, financial or authentication information.",
            "Verify the registered domain and organization independently.",
            "Do not download unexpected files.",
            "Use an official bookmark, application or trusted search result.",
            "Consider a second reputation source before continuing.",
        ]
    if score > 30:
        return [
            "Proceed only after verifying the domain carefully.",
            "Check WHOIS, certificate and organization details.",
            "Avoid sharing credentials until legitimacy is confirmed.",
            "Confirm the link through an official source.",
            "Be cautious of redirects, login forms and payment requests.",
        ]
    if score > 15:
        return [
            "Only minor risk indicators were detected.",
            "Verify the URL spelling before entering sensitive information.",
            "Confirm that the website belongs to the expected organization.",
            "Avoid links received from unknown or unexpected senders.",
        ]
    return [
        "No major phishing indicators were detected by the completed checks.",
        "Always verify the URL before entering credentials.",
        "Use multi-factor authentication where available.",
        "Keep your browser and security software updated.",
        "Avoid sensitive actions after opening links from unknown senders.",
    ]


def add_recommendations(story, score, styles):
    add_section_title(story, "Security Recommendations", styles, "Action Guidance")
    recommendations = get_recommendations(score)
    data = []
    for index, recommendation in enumerate(recommendations, start=1):
        data.append([
            Paragraph(str(index), styles["WhiteSmallBold"]),
            Paragraph(pdf_text(recommendation), styles["Body"]),
        ])
    table = Table(data, colWidths=[9 * mm, 171 * mm])
    commands = [
        ("BOX", (0, 0), (-1, -1), 0.55, SLATE_200),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, SLATE_200),
        ("BACKGROUND", (1, 0), (1, -1), SLATE_50),
        ("BACKGROUND", (0, 0), (0, -1), NAVY_2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    table.setStyle(TableStyle(commands))
    story.append(table)
    story.append(Spacer(1, 8))


# ==========================================================
# MAIN PDF GENERATOR
# ==========================================================

def generate_pdf(report_data, output_path):
    output_directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_directory, exist_ok=True)

    styles = build_styles()
    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=13 * mm,
        bottomMargin=18 * mm,
        title="URL Security Analyzer Report",
        author="URL Security Analyzer",
        subject="URL and phishing risk analysis",
    )

    story = []
    risk_score = normalize_score(report_data.get("risk_score", 0))
    verdict = report_data.get("verdict", "Unknown")
    analysis = report_data.get("analysis_results", {})
    generated_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    url = report_data.get("url", "Unknown")

    # PAGE 1 - EXECUTIVE OVERVIEW
    add_cover_header(story, url, generated_time, styles)
    add_risk_dashboard(story, risk_score, verdict, styles)
    add_summary_cards(story, report_data, analysis, styles)

    add_section_title(story, "Executive Summary", styles, "Assessment")
    add_information_table(story, [
        ["Analyzed URL", url],
        ["Risk Score", f"{risk_score}/100"],
        ["Final Verdict", verdict],
        ["Threat Band", score_band(risk_score)],
        ["Report Generated", generated_time],
        ["Scanner Version", REPORT_VERSION],
        ["Detection Engine", ENGINE_NAME],
    ], styles)
    add_evidence_summary(story, report_data.get("reasons", []), styles)
    story.append(PageBreak())

    # PAGE 2 - URL AND DOMAIN
    add_section_title(story, "URL Structure Analysis", styles, "Surface Indicators")
    add_information_table(story, [
        ["HTTPS", report_data.get("https_status", "Not Checked")],
        ["IP Address", report_data.get("ip_status", "Not Checked")],
        ["Suspicious Keywords", f"{report_data.get('keyword_count', 0)} detected - {format_list(report_data.get('keywords', []))}"],
        ["URL Length", f"{report_data.get('url_length', 'Unknown')} characters - {report_data.get('length_category', 'Unknown')}"],
        ["Subdomains", f"{report_data.get('subdomain_count', 0)} - {report_data.get('subdomain_status', 'Unknown')}"],
        ["At Symbol", report_data.get("at_status", "Not Checked")],
        ["URL Shortener", report_data.get("shortener_status", "Not Checked")],
        ["Hyphens", f"{report_data.get('hyphen_count', 0)} - {report_data.get('hyphen_status', 'Unknown')}"],
        ["Top-Level Domain", f"{report_data.get('tld', 'Unknown')} - {report_data.get('tld_status', 'Unknown')}"],
    ], styles)

    domain_age = report_data.get("domain_age", {})
    if not isinstance(domain_age, dict):
        domain_age = {}
    add_section_title(story, "Domain Age", styles, "Registration Context")
    add_information_table(story, [
        ["Age", domain_age.get("age", "Unknown")],
        ["Status", domain_age.get("message", "Unknown")],
        ["Confirmed New", domain_age.get("confirmed_new", False)],
    ], styles)

    if analysis:
        add_section_title(story, "Domain Identity Checks", styles, "Impersonation Signals")
        add_information_table(story, [
            ["Domain Similarity", get_nested(analysis, "domain_similarity", "status")],
            ["Similarity Matches", format_list(get_nested(analysis, "domain_similarity", "matches", []))],
            ["Typosquatting", get_nested(analysis, "typosquatting", "status")],
            ["Homograph", get_nested(analysis, "homograph", "status")],
            ["Punycode", get_nested(analysis, "punycode", "status")],
            ["Domain Entropy", get_nested(analysis, "entropy", "status")],
        ], styles)
    story.append(PageBreak())

    # PAGE 3 - WHOIS, SSL, DNS
    whois = report_data.get("whois", {})
    if not isinstance(whois, dict):
        whois = {}
    add_section_title(story, "WHOIS Information", styles, "Ownership & Registration")
    add_information_table(story, [
        ["Registrar", whois.get("registrar", "Unknown")],
        ["Organization", whois.get("organization", "Unknown")],
        ["Country", whois.get("country", "Unknown")],
        ["Creation Date", whois.get("creation_date", "Unknown")],
        ["Updated Date", whois.get("updated_date", "Unknown")],
        ["Expiration Date", whois.get("expiration_date", "Unknown")],
        ["Domain Status", simplify_whois_status(whois.get("status"))],
        ["Name Servers", format_list(whois.get("name_servers", []), "Unknown")],
    ], styles)

    ssl_info = report_data.get("ssl", {})
    if not isinstance(ssl_info, dict):
        ssl_info = {}
    add_section_title(story, "SSL Certificate", styles, "Transport Security")
    add_information_table(story, [
        ["Status", ssl_info.get("status", "Not Checked")],
        ["Issuer", ssl_info.get("issuer", "Unknown")],
        ["Protocol", ssl_info.get("protocol", "Unknown")],
        ["Cipher", ssl_info.get("cipher", "Unknown")],
        ["Valid From", ssl_info.get("valid_from", ssl_info.get("not_before", "Unknown"))],
        ["Valid Until", ssl_info.get("valid_until", ssl_info.get("not_after", "Unknown"))],
        ["Days Remaining", ssl_info.get("days_remaining", "Unknown")],
    ], styles)

    dns_records = report_data.get("dns", {})
    if not isinstance(dns_records, dict):
        dns_records = {}
    add_section_title(story, "DNS Records", styles, "Infrastructure")
    add_information_table(story, [
        ["A", format_dns_value("A", dns_records.get("A", []))],
        ["AAAA", format_dns_value("AAAA", dns_records.get("AAAA", []))],
        ["MX", format_dns_value("MX", dns_records.get("MX", []))],
        ["NS", format_dns_value("NS", dns_records.get("NS", []))],
        ["CNAME", format_dns_value("CNAME", dns_records.get("CNAME", []))],
        ["TXT", format_dns_value("TXT", dns_records.get("TXT", []))],
    ], styles)
    story.append(PageBreak())

    # PAGES 4-5 - ALL DETECTION RESULTS
    add_section_title(story, "Complete Detection Results", styles, "Module Output")
    detection_rows = build_detection_rows(analysis)
    add_detection_table(story, detection_rows, styles)
    story.append(Paragraph(
        "Check scores shown above are raw module outputs. The final risk score applies category caps, weighting, corroboration and threat-intelligence rules, so module scores are not added directly.",
        styles["Disclaimer"],
    ))
    story.append(Spacer(1, 8))

    # PAGE 6 - WEBPAGE + SERVER
    redirects = get_section(analysis, "redirects")
    headers = get_section(analysis, "security_headers")
    javascript = get_section(analysis, "javascript")
    forms = get_section(analysis, "forms")
    content = get_section(analysis, "content")
    favicon = get_section(analysis, "favicon")
    query_parameters = get_section(analysis, "query_parameters")
    email_address = get_section(analysis, "email_address")

    add_section_title(story, "Webpage Behaviour", styles, "Runtime & Content")
    add_information_table(story, [
        ["Final Redirect URL", redirects.get("final_url", redirects.get("final_redirect_url", url))],
        ["Redirect Count", redirects.get("redirect_count", redirects.get("count", 0))],
        ["Missing Security Headers", format_list(headers.get("missing", headers.get("missing_headers", [])))],
        ["JavaScript Patterns", format_list(javascript.get("patterns", javascript.get("matches", [])))],
        ["Form Issues", format_list(forms.get("issues", forms.get("patterns", [])))],
        ["Content Patterns", format_list(content.get("patterns", content.get("matches", [])))],
        ["Favicon URL", favicon.get("url", favicon.get("favicon_url", "Unknown"))],
        ["Suspicious Query Parameters", format_list(query_parameters.get("matches", query_parameters.get("suspicious", [])))],
        ["Email Addresses in URL", format_list(email_address.get("matches", email_address.get("emails", [])))],
    ], styles)

    robots = get_section(analysis, "robots")
    sitemap = get_section(analysis, "sitemap")
    response_headers = get_section(analysis, "response_headers")
    technology = get_section(analysis, "technology")
    file_exposure = get_section(analysis, "file_exposure")
    http_methods = get_section(analysis, "http_methods")

    add_section_title(story, "Website and Server Intelligence", styles, "Exposure & Fingerprinting")
    add_information_table(story, [
        ["robots.txt", robots.get("status", "Not Checked")],
        ["robots.txt Disallow Entries", robots.get("disallow_count", len(robots.get("disallowed", [])) if isinstance(robots.get("disallowed", []), list) else "Unknown")],
        ["Sitemap", sitemap.get("status", "Not Checked")],
        ["Sitemap URL Count", sitemap.get("url_count", sitemap.get("count", "Unknown"))],
        ["Response Headers", response_headers.get("status", "Not Checked")],
        ["Server", response_headers.get("server", technology.get("server", "Unknown"))],
        ["Technology Detection", technology.get("status", "Not Checked")],
        ["Technologies", format_list(technology.get("technologies", technology.get("detected", [])))],
        ["Sensitive File Exposure", file_exposure.get("status", "Not Checked")],
        ["Exposed File Count", file_exposure.get("count", len(file_exposure.get("exposed", [])) if isinstance(file_exposure.get("exposed", []), list) else 0)],
        ["HTTP Methods", http_methods.get("status", "Not Checked")],
        ["Risky Methods", format_list(http_methods.get("risky_methods", http_methods.get("risky", [])))],
    ], styles)
    story.append(PageBreak())

    # PAGE 7 - ADVANCED SECURITY + VT
    cookie = get_section(analysis, "cookie_security")
    cors = get_section(analysis, "cors")
    mixed = get_section(analysis, "mixed_content")

    add_section_title(story, "Cookie Security", styles, "Advanced Web Security")
    add_information_table(story, [
        ["Status", cookie.get("status", "Not Checked")],
        ["Cookies Detected", cookie.get("total_cookies", cookie.get("cookies_detected", "Unknown"))],
        ["Secure Cookies", cookie.get("secure_cookies", "Unknown")],
        ["HttpOnly Cookies", cookie.get("httponly_cookies", cookie.get("http_only_cookies", "Unknown"))],
        ["SameSite Cookies", cookie.get("samesite_cookies", cookie.get("same_site_cookies", "Unknown"))],
        ["Observations", format_list(cookie.get("issues", cookie.get("observations", [])))],
    ], styles)

    add_section_title(story, "CORS Security", styles, "Cross-Origin Policy")
    add_information_table(story, [
        ["Status", cors.get("status", "Not Checked")],
        ["CORS Exposed", cors.get("exposed", cors.get("cors_exposed", "Unknown"))],
        ["Allowed Origin", cors.get("allowed_origin", "Not Set")],
        ["Credentials Allowed", cors.get("credentials_allowed", "Unknown")],
        ["Origin Reflection", cors.get("origin_reflection", "Unknown")],
        ["Allowed Methods", format_list(cors.get("allowed_methods", []))],
        ["Issues", format_list(cors.get("issues", []))],
    ], styles)

    add_section_title(story, "Mixed Content", styles, "Protocol Integrity")
    add_information_table(story, [
        ["Status", mixed.get("status", "Not Checked")],
        ["HTTPS Page", mixed.get("https_page", "Unknown")],
        ["Downgraded to HTTP", mixed.get("downgraded_to_http", "Unknown")],
        ["Active Mixed Resources", mixed.get("active_mixed_resources", mixed.get("active_count", 0))],
        ["Passive Mixed Resources", mixed.get("passive_mixed_resources", mixed.get("passive_count", 0))],
        ["Total Mixed Resources", mixed.get("total_mixed_resources", mixed.get("count", 0))],
        ["Issues", format_list(mixed.get("issues", []))],
    ], styles)

    threat = get_section(analysis, "threat_intelligence")
    add_section_title(story, "VirusTotal Threat Intelligence", styles, "Reputation")
    add_information_table(story, [
        ["Status", threat.get("status", "Not Checked")],
        ["Report Found", threat.get("report_found", False)],
        ["Submitted for Analysis", threat.get("submitted", False)],
        ["Malicious Detections", threat.get("malicious", 0)],
        ["Suspicious Detections", threat.get("suspicious", 0)],
        ["Harmless", threat.get("harmless", 0)],
        ["Undetected", threat.get("undetected", 0)],
        ["Total Engines", threat.get("total_engines", 0)],
        ["Reputation", threat.get("reputation", 0)],
        ["Categories", format_list(threat.get("categories", []))],
        ["Last Analysis", threat.get("last_analysis_date", "Unknown")],
    ], styles)
    story.append(Spacer(1, 8))

    # FINAL PAGE - GUIDANCE + DISCLAIMER
    add_section_title(story, "Final Assessment", styles, "Decision Support")
    add_risk_dashboard(story, risk_score, verdict, styles)
    add_evidence_summary(story, report_data.get("reasons", []), styles)
    add_recommendations(story, risk_score, styles)

    disclaimer = Table([[Paragraph(
        "<b>Important:</b> This report is generated using automated heuristics, technical checks and available threat-intelligence data. "
        "A low score does not guarantee that a website is safe, and an unavailable reputation result should not be treated as proof of safety. "
        "Use this report as supporting security evidence rather than an absolute guarantee.",
        styles["Disclaimer"],
    )]], colWidths=[180 * mm])
    disclaimer.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SLATE_50),
        ("BOX", (0, 0), (-1, -1), 0.55, SLATE_200),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(disclaimer)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<b>Generated by:</b> URL Security Analyzer &nbsp;&nbsp; "
        f"<b>Engine:</b> {pdf_text(ENGINE_NAME)} &nbsp;&nbsp; "
        f"<b>Version:</b> {REPORT_VERSION} &nbsp;&nbsp; "
        f"<b>Generated:</b> {pdf_text(generated_time)}",
        styles["Disclaimer"],
    ))

    document.build(
        story,
        onFirstPage=draw_page_layout,
        onLaterPages=draw_page_layout,
    )