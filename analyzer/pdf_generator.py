from datetime import datetime
from xml.sax.saxutils import escape
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle
)


PAGE_WIDTH, PAGE_HEIGHT = A4

REPORT_VERSION = "2.0"
ENGINE_NAME = "Multi-Layer URL Threat Detection Engine"


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
        flags=re.UNICODE
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

        return ", ".join(
            remove_emoji(item)
            for item in value
        )

    return remove_emoji(value)


def pdf_text(value):

    return escape(
        safe_text(value)
    )


def format_list(values, empty="None"):

    if not values:
        return empty

    return ", ".join(
        safe_text(value)
        for value in values
    )


def get_nested(
    data,
    section,
    field,
    default="Not Checked"
):

    section_data = data.get(
        section,
        {}
    )

    if not isinstance(section_data, dict):
        return default

    return section_data.get(
        field,
        default
    )


def simplify_whois_status(value):

    if not value:
        return "Unknown"

    text = safe_text(value)

    statuses = re.findall(
        r"\b(?:client|server)[A-Za-z]+Prohibited\b|\bok\b",
        text
    )

    unique_statuses = list(
        dict.fromkeys(statuses)
    )

    if unique_statuses:
        return ", ".join(unique_statuses)

    if len(text) > 300:
        return text[:297] + "..."

    return text


def format_dns_value(
    record_type,
    values
):

    if not values:
        return "Not Available"

    if record_type != "TXT":
        return format_list(
            values,
            "Not Available"
        )

    shortened_values = []

    for value in values[:5]:

        text = safe_text(value)

        if len(text) > 120:
            text = text[:117] + "..."

        shortened_values.append(text)

    result = ", ".join(
        shortened_values
    )

    if len(values) > 5:
        result += (
            f" ... and {len(values) - 5} more record(s)"
        )

    return result


# ==========================================================
# RISK HELPERS
# ==========================================================

def normalize_score(value):

    try:
        return max(
            0,
            min(
                int(value),
                100
            )
        )

    except (TypeError, ValueError):
        return 0


def get_risk_details(score):

    score = normalize_score(score)

    if score > 75:
        return {
            "label": "CRITICAL",
            "color": colors.HexColor("#991B1B"),
            "light": colors.HexColor("#FEE2E2"),
            "recommendation": (
                "Do not visit this website or provide any information."
            )
        }

    if score > 50:
        return {
            "label": "HIGH RISK",
            "color": colors.HexColor("#DC2626"),
            "light": colors.HexColor("#FEE2E2"),
            "recommendation": (
                "Avoid entering credentials, payment information "
                "or downloading files."
            )
        }

    if score > 30:
        return {
            "label": "MEDIUM RISK",
            "color": colors.HexColor("#D97706"),
            "light": colors.HexColor("#FEF3C7"),
            "recommendation": (
                "Proceed carefully and independently verify the domain."
            )
        }

    if score > 15:
        return {
            "label": "LOW RISK",
            "color": colors.HexColor("#0284C7"),
            "light": colors.HexColor("#E0F2FE"),
            "recommendation": (
                "Only minor indicators were detected. "
                "Continue with caution."
            )
        }

    return {
        "label": "SAFE",
        "color": colors.HexColor("#15803D"),
        "light": colors.HexColor("#DCFCE7"),
        "recommendation": (
            "No major suspicious indicators were detected."
        )
    }


# ==========================================================
# PDF STYLES
# ==========================================================

def build_styles():

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=10,
            spaceAfter=7
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155")
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodyNormalCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
    )

    styles.add(
        ParagraphStyle(
            name="Evidence",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            leftIndent=10,
            textColor=colors.HexColor("#334155")
        )
    )

    styles.add(
        ParagraphStyle(
            name="Disclaimer",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#64748B")
        )
    )

    styles.add(
        ParagraphStyle(
            name="WhiteTableText",
            parent=styles["BodySmall"],
            fontName="Helvetica-Bold",
            textColor=colors.white,
            alignment=TA_CENTER
        )
    )

    return styles


# ==========================================================
# PAGE HEADER AND FOOTER
# ==========================================================

def draw_page_layout(canvas, document):

    canvas.saveState()

    canvas.setStrokeColor(
        colors.HexColor("#CBD5E1")
    )

    canvas.setLineWidth(0.5)

    canvas.line(
        15 * mm,
        PAGE_HEIGHT - 12 * mm,
        PAGE_WIDTH - 15 * mm,
        PAGE_HEIGHT - 12 * mm
    )

    canvas.setFont(
        "Helvetica-Bold",
        8
    )

    canvas.setFillColor(
        colors.HexColor("#334155")
    )

    canvas.drawString(
        15 * mm,
        PAGE_HEIGHT - 9 * mm,
        "URL Security Analyzer"
    )

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.drawRightString(
        PAGE_WIDTH - 15 * mm,
        PAGE_HEIGHT - 9 * mm,
        "Security Analysis Report"
    )

    canvas.line(
        15 * mm,
        14 * mm,
        PAGE_WIDTH - 15 * mm,
        14 * mm
    )

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.setFillColor(
        colors.HexColor("#64748B")
    )

    canvas.drawString(
        15 * mm,
        9 * mm,
        f"URL Security Analyzer v{REPORT_VERSION}"
    )

    canvas.drawRightString(
        PAGE_WIDTH - 15 * mm,
        9 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# ==========================================================
# TABLE HELPERS
# ==========================================================

def add_section_title(
    story,
    title,
    styles
):

    story.append(
        Paragraph(
            pdf_text(title),
            styles["SectionTitle"]
        )
    )


def add_information_table(
    story,
    rows,
    styles,
    label_width=52 * mm
):

    if not rows:
        return

    formatted_rows = []

    for label, value in rows:

        formatted_rows.append([
            Paragraph(
                f"<b>{pdf_text(label)}</b>",
                styles["BodySmall"]
            ),
            Paragraph(
                pdf_text(value),
                styles["BodySmall"]
            )
        ])

    table = Table(
        formatted_rows,
        colWidths=[
            label_width,
            180 * mm - label_width
        ],
        hAlign="LEFT"
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#E2E8F0")
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                colors.HexColor("#F8FAFC")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#CBD5E1")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(table)


def add_detection_table(
    story,
    rows,
    styles
):

    table_data = [[
        Paragraph(
            "<b>Detection Module</b>",
            styles["WhiteTableText"]
        ),
        Paragraph(
            "<b>Result</b>",
            styles["WhiteTableText"]
        ),
        Paragraph(
            "<b>Score</b>",
            styles["WhiteTableText"]
        )
    ]]

    for name, status, score in rows:

        table_data.append([
            Paragraph(
                pdf_text(name),
                styles["BodySmall"]
            ),
            Paragraph(
                pdf_text(status),
                styles["BodySmall"]
            ),
            Paragraph(
                pdf_text(score),
                styles["BodySmall"]
            )
        ])

    table = Table(
        table_data,
        colWidths=[
            47 * mm,
            111 * mm,
            22 * mm
        ],
        repeatRows=1
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0F172A")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#CBD5E1")
            ),
            (
                "BACKGROUND",
                (0, 1),
                (-1, -1),
                colors.HexColor("#F8FAFC")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(table)


# ==========================================================
# RISK SUMMARY
# ==========================================================

def add_risk_meter(
    story,
    risk_score,
    verdict,
    styles
):

    score = normalize_score(
        risk_score
    )

    risk = get_risk_details(
        score
    )

    white_style = styles["WhiteTableText"]

    summary = Table(
        [[
            Paragraph(
                "Risk Score",
                white_style
            ),
            Paragraph(
                f"{score}/100",
                white_style
            ),
            Paragraph(
                "Verdict",
                white_style
            ),
            Paragraph(
                pdf_text(verdict),
                white_style
            ),
            Paragraph(
                "Threat Level",
                white_style
            ),
            Paragraph(
                risk["label"],
                white_style
            )
        ]],
        colWidths=[
            25 * mm,
            25 * mm,
            22 * mm,
            31 * mm,
            29 * mm,
            48 * mm
        ]
    )

    summary.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                risk["color"]
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.white
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )

    story.append(summary)

    story.append(
        Spacer(
            1,
            9
        )
    )

    filled_width = 170 * mm * score / 100
    empty_width = 170 * mm - filled_width

    if score == 0:

        meter = Table(
            [[""]],
            colWidths=[
                170 * mm
            ],
            rowHeights=[
                7 * mm
            ]
        )

        meter.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#E2E8F0")
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#94A3B8")
                )
            ])
        )

    elif score == 100:

        meter = Table(
            [[""]],
            colWidths=[
                170 * mm
            ],
            rowHeights=[
                7 * mm
            ]
        )

        meter.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    risk["color"]
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#94A3B8")
                )
            ])
        )

    else:

        meter = Table(
            [["", ""]],
            colWidths=[
                filled_width,
                empty_width
            ],
            rowHeights=[
                7 * mm
            ]
        )

        meter.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, 0),
                    risk["color"]
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, 0),
                    colors.HexColor("#E2E8F0")
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#94A3B8")
                )
            ])
        )

    story.append(meter)

    story.append(
        Spacer(
            1,
            8
        )
    )

    recommendation_box = Table(
        [[
            Paragraph(
                (
                    f"<b>Recommendation:</b> "
                    f"{pdf_text(risk['recommendation'])}"
                ),
                styles["BodyNormalCustom"]
            )
        ]],
        colWidths=[
            180 * mm
        ]
    )

    recommendation_box.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                risk["light"]
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                risk["color"]
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(
        recommendation_box
    )


def add_evidence_summary(
    story,
    reasons,
    styles
):

    add_section_title(
        story,
        "Evidence Summary",
        styles
    )

    if not reasons:
        reasons = [
            "No major suspicious indicators were detected."
        ]

    for reason in reasons:

        story.append(
            Paragraph(
                f"- {pdf_text(reason)}",
                styles["Evidence"]
            )
        )

        story.append(
            Spacer(
                1,
                2
            )
        )


# ==========================================================
# DETECTION RESULTS
# ==========================================================

def build_detection_rows(analysis):

    return [
        (
            "HTTPS",
            get_nested(
                analysis,
                "https",
                "status"
            ),
            0
        ),
        (
            "IP Address",
            get_nested(
                analysis,
                "ip_address",
                "status"
            ),
            0
        ),
        (
            "URL Length",
            get_nested(
                analysis,
                "url_length",
                "status"
            ),
            get_nested(
                analysis,
                "url_length",
                "score",
                0
            )
        ),
        (
            "Subdomains",
            get_nested(
                analysis,
                "subdomains",
                "status"
            ),
            get_nested(
                analysis,
                "subdomains",
                "score",
                0
            )
        ),
        (
            "At Symbol",
            get_nested(
                analysis,
                "at_symbol",
                "status"
            ),
            get_nested(
                analysis,
                "at_symbol",
                "score",
                0
            )
        ),
        (
            "URL Shortener",
            get_nested(
                analysis,
                "shortener",
                "status"
            ),
            get_nested(
                analysis,
                "shortener",
                "score",
                0
            )
        ),
        (
            "Hyphens",
            get_nested(
                analysis,
                "hyphens",
                "status"
            ),
            get_nested(
                analysis,
                "hyphens",
                "score",
                0
            )
        ),
        (
            "Top-Level Domain",
            get_nested(
                analysis,
                "tld",
                "status"
            ),
            get_nested(
                analysis,
                "tld",
                "score",
                0
            )
        ),
        (
            "Domain Similarity",
            get_nested(
                analysis,
                "domain_similarity",
                "status"
            ),
            get_nested(
                analysis,
                "domain_similarity",
                "score",
                0
            )
        ),
        (
            "Typosquatting",
            get_nested(
                analysis,
                "typosquatting",
                "status"
            ),
            get_nested(
                analysis,
                "typosquatting",
                "score",
                0
            )
        ),
        (
            "Homograph",
            get_nested(
                analysis,
                "homograph",
                "status"
            ),
            get_nested(
                analysis,
                "homograph",
                "score",
                0
            )
        ),
        (
            "Punycode",
            get_nested(
                analysis,
                "punycode",
                "status"
            ),
            get_nested(
                analysis,
                "punycode",
                "score",
                0
            )
        ),
        (
            "Domain Entropy",
            get_nested(
                analysis,
                "entropy",
                "status"
            ),
            get_nested(
                analysis,
                "entropy",
                "score",
                0
            )
        ),
        (
            "Port",
            get_nested(
                analysis,
                "port",
                "status"
            ),
            get_nested(
                analysis,
                "port",
                "score",
                0
            )
        ),
        (
            "Query Parameters",
            get_nested(
                analysis,
                "query_parameters",
                "status"
            ),
            get_nested(
                analysis,
                "query_parameters",
                "score",
                0
            )
        ),
        (
            "Email Address",
            get_nested(
                analysis,
                "email_address",
                "status"
            ),
            get_nested(
                analysis,
                "email_address",
                "score",
                0
            )
        ),
        (
            "File Extension",
            get_nested(
                analysis,
                "file_extension",
                "status"
            ),
            get_nested(
                analysis,
                "file_extension",
                "score",
                0
            )
        ),
        (
            "Redirects",
            get_nested(
                analysis,
                "redirects",
                "status"
            ),
            get_nested(
                analysis,
                "redirects",
                "score",
                0
            )
        ),
        (
            "Security Headers",
            get_nested(
                analysis,
                "security_headers",
                "status"
            ),
            get_nested(
                analysis,
                "security_headers",
                "score",
                0
            )
        ),
        (
            "JavaScript",
            get_nested(
                analysis,
                "javascript",
                "status"
            ),
            get_nested(
                analysis,
                "javascript",
                "score",
                0
            )
        ),
        (
            "Forms",
            get_nested(
                analysis,
                "forms",
                "status"
            ),
            get_nested(
                analysis,
                "forms",
                "score",
                0
            )
        ),
        (
            "Page Content",
            get_nested(
                analysis,
                "content",
                "status"
            ),
            get_nested(
                analysis,
                "content",
                "score",
                0
            )
        ),
        (
            "Favicon",
            get_nested(
                analysis,
                "favicon",
                "status"
            ),
            get_nested(
                analysis,
                "favicon",
                "score",
                0
            )
        )
    ]


def add_detection_statistics(
    story,
    rows,
    styles
):

    total_checks = len(rows)

    completed = sum(
        1
        for _, status, _ in rows
        if safe_text(status).lower() != "not checked"
    )

    flagged = sum(
        1
        for _, _, score in rows
        if normalize_score(score) > 0
    )

    clean = max(
        completed - flagged,
        0
    )

    stats_table = Table(
        [[
            Paragraph(
                f"<b>{total_checks}</b><br/>Total Modules",
                styles["BodyNormalCustom"]
            ),
            Paragraph(
                f"<b>{completed}</b><br/>Checks Completed",
                styles["BodyNormalCustom"]
            ),
            Paragraph(
                f"<b>{flagged}</b><br/>Flagged Checks",
                styles["BodyNormalCustom"]
            ),
            Paragraph(
                f"<b>{clean}</b><br/>Clean Checks",
                styles["BodyNormalCustom"]
            )
        ]],
        colWidths=[
            45 * mm,
            45 * mm,
            45 * mm,
            45 * mm
        ]
    )

    stats_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#E2E8F0")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#94A3B8")
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )
        ])
    )

    story.append(stats_table)


# ==========================================================
# RECOMMENDATIONS
# ==========================================================

def get_recommendations(score):

    score = normalize_score(
        score
    )

    if score > 75:
        return [
            "Do not open or continue using this website.",
            "Do not enter passwords, OTPs, banking or payment information.",
            "Do not download files or install applications.",
            "Report the URL to your browser, organization or security team.",
            "Use the organization's official website or mobile application."
        ]

    if score > 50:
        return [
            "Avoid entering personal, financial or authentication information.",
            "Verify the registered domain and organization independently.",
            "Do not download unexpected files.",
            "Use an official bookmark, application or trusted search result.",
            "Consider checking the URL with a reputation service."
        ]

    if score > 30:
        return [
            "Proceed only after verifying the domain carefully.",
            "Check WHOIS, certificate and organization details.",
            "Avoid sharing credentials until legitimacy is confirmed.",
            "Confirm the link through an official source.",
            "Be cautious of redirects and login requests."
        ]

    if score > 15:
        return [
            "Only minor risk indicators were detected.",
            "Verify the URL spelling before entering sensitive information.",
            "Confirm that the website belongs to the expected organization.",
            "Avoid links received from unknown senders."
        ]

    return [
        "No major phishing indicators were detected.",
        "Always verify the URL before entering credentials.",
        "Use multi-factor authentication where available.",
        "Keep your browser and security software updated.",
        "Avoid sensitive actions after opening links from unknown senders."
    ]


def add_recommendations(
    story,
    score,
    styles
):

    add_section_title(
        story,
        "Security Recommendations",
        styles
    )

    for recommendation in get_recommendations(score):

        story.append(
            Paragraph(
                f"- {pdf_text(recommendation)}",
                styles["Evidence"]
            )
        )

        story.append(
            Spacer(
                1,
                2
            )
        )


# ==========================================================
# MAIN PDF GENERATOR
# ==========================================================

def generate_pdf(
    report_data,
    output_path
):

    styles = build_styles()

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=17 * mm,
        bottomMargin=19 * mm,
        title="URL Security Analyzer Report",
        author="URL Security Analyzer",
        subject="URL and phishing risk analysis"
    )

    story = []

    risk_score = normalize_score(
        report_data.get(
            "risk_score",
            0
        )
    )

    verdict = report_data.get(
        "verdict",
        "Unknown"
    )

    analysis = report_data.get(
        "analysis_results",
        {}
    )

    generated_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    # ======================================================
    # PAGE 1 - EXECUTIVE SUMMARY
    # ======================================================

    story.append(
        Paragraph(
            "URL Security Analyzer",
            styles["ReportTitle"]
        )
    )

    story.append(
        Paragraph(
            (
                "Comprehensive URL, domain, network and "
                "webpage security analysis report"
            ),
            styles["ReportSubtitle"]
        )
    )

    add_risk_meter(
        story,
        risk_score,
        verdict,
        styles
    )

    story.append(
        Spacer(
            1,
            12
        )
    )

    add_section_title(
        story,
        "Executive Summary",
        styles
    )

    add_information_table(
        story,
        [
            [
                "Analyzed URL",
                report_data.get(
                    "url",
                    "Unknown"
                )
            ],
            [
                "Risk Score",
                f"{risk_score}/100"
            ],
            [
                "Final Verdict",
                verdict
            ],
            [
                "Report Generated",
                generated_time
            ],
            [
                "Scanner Version",
                REPORT_VERSION
            ],
            [
                "Detection Engine",
                ENGINE_NAME
            ]
        ],
        styles
    )

    add_evidence_summary(
        story,
        report_data.get(
            "reasons",
            []
        ),
        styles
    )

    if analysis:

        detection_rows = build_detection_rows(
            analysis
        )

        add_section_title(
            story,
            "Scan Statistics",
            styles
        )

        add_detection_statistics(
            story,
            detection_rows,
            styles
        )

    story.append(
        PageBreak()
    )

    # ======================================================
    # PAGE 2 - URL AND DOMAIN ANALYSIS
    # ======================================================

    add_section_title(
        story,
        "URL Structure Analysis",
        styles
    )

    add_information_table(
        story,
        [
            [
                "HTTPS",
                report_data.get(
                    "https_status",
                    "Not Checked"
                )
            ],
            [
                "IP Address",
                report_data.get(
                    "ip_status",
                    "Not Checked"
                )
            ],
            [
                "Suspicious Keywords",
                (
                    f"{report_data.get('keyword_count', 0)} detected - "
                    f"{format_list(report_data.get('keywords', []))}"
                )
            ],
            [
                "URL Length",
                (
                    f"{report_data.get('url_length', 'Unknown')} "
                    f"characters - "
                    f"{report_data.get('length_category', 'Unknown')}"
                )
            ],
            [
                "Subdomains",
                (
                    f"{report_data.get('subdomain_count', 0)} - "
                    f"{report_data.get('subdomain_status', 'Unknown')}"
                )
            ],
            [
                "At Symbol",
                report_data.get(
                    "at_status",
                    "Not Checked"
                )
            ],
            [
                "URL Shortener",
                report_data.get(
                    "shortener_status",
                    "Not Checked"
                )
            ],
            [
                "Hyphens",
                (
                    f"{report_data.get('hyphen_count', 0)} - "
                    f"{report_data.get('hyphen_status', 'Unknown')}"
                )
            ],
            [
                "Top-Level Domain",
                (
                    f"{report_data.get('tld', 'Unknown')} - "
                    f"{report_data.get('tld_status', 'Unknown')}"
                )
            ]
        ],
        styles
    )

    domain_age = report_data.get(
        "domain_age",
        {}
    )

    add_section_title(
        story,
        "Domain Age",
        styles
    )

    add_information_table(
        story,
        [
            [
                "Age",
                domain_age.get(
                    "age",
                    "Unknown"
                )
            ],
            [
                "Status",
                domain_age.get(
                    "message",
                    "Unknown"
                )
            ],
            [
                "Confirmed New",
                domain_age.get(
                    "confirmed_new",
                    False
                )
            ]
        ],
        styles
    )

    if analysis:

        add_section_title(
            story,
            "Domain Identity Checks",
            styles
        )

        add_information_table(
            story,
            [
                [
                    "Domain Similarity",
                    get_nested(
                        analysis,
                        "domain_similarity",
                        "status"
                    )
                ],
                [
                    "Similarity Matches",
                    format_list(
                        get_nested(
                            analysis,
                            "domain_similarity",
                            "matches",
                            []
                        )
                    )
                ],
                [
                    "Typosquatting",
                    get_nested(
                        analysis,
                        "typosquatting",
                        "status"
                    )
                ],
                [
                    "Homograph",
                    get_nested(
                        analysis,
                        "homograph",
                        "status"
                    )
                ],
                [
                    "Punycode",
                    get_nested(
                        analysis,
                        "punycode",
                        "status"
                    )
                ],
                [
                    "Domain Entropy",
                    get_nested(
                        analysis,
                        "entropy",
                        "status"
                    )
                ]
            ],
            styles
        )

    story.append(
        PageBreak()
    )

    # ======================================================
    # PAGE 3 - WHOIS, SSL AND DNS
    # ======================================================

    whois = report_data.get(
        "whois",
        {}
    )

    add_section_title(
        story,
        "WHOIS Information",
        styles
    )

    add_information_table(
        story,
        [
            [
                "Registrar",
                whois.get(
                    "registrar",
                    "Unknown"
                )
            ],
            [
                "Organization",
                whois.get(
                    "organization",
                    "Unknown"
                )
            ],
            [
                "Country",
                whois.get(
                    "country",
                    "Unknown"
                )
            ],
            [
                "Creation Date",
                whois.get(
                    "creation_date",
                    "Unknown"
                )
            ],
            [
                "Updated Date",
                whois.get(
                    "updated_date",
                    "Unknown"
                )
            ],
            [
                "Expiration Date",
                whois.get(
                    "expiration_date",
                    "Unknown"
                )
            ],
            [
                "Domain Status",
                simplify_whois_status(
                    whois.get(
                        "status"
                    )
                )
            ],
            [
                "Name Servers",
                whois.get(
                    "name_servers",
                    "Unknown"
                )
            ]
        ],
        styles
    )

    ssl_info = report_data.get(
        "ssl",
        {}
    )

    add_section_title(
        story,
        "SSL Certificate",
        styles
    )

    add_information_table(
        story,
        [
            [
                "Status",
                ssl_info.get(
                    "status",
                    "Unknown"
                )
            ],
            [
                "Issuer",
                ssl_info.get(
                    "issuer",
                    "Unknown"
                )
            ],
            [
                "Protocol",
                ssl_info.get(
                    "protocol",
                    "Unknown"
                )
            ],
            [
                "Cipher",
                ssl_info.get(
                    "cipher",
                    "Unknown"
                )
            ],
            [
                "Valid From",
                ssl_info.get(
                    "valid_from",
                    "Unknown"
                )
            ],
            [
                "Valid Until",
                ssl_info.get(
                    "valid_to",
                    "Unknown"
                )
            ],
            [
                "Days Remaining",
                ssl_info.get(
                    "days_remaining",
                    "Unknown"
                )
            ]
        ],
        styles
    )

    dns = report_data.get(
        "dns",
        {}
    )

    add_section_title(
        story,
        "DNS Records",
        styles
    )

    dns_rows = []

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME",
        "TXT"
    ]:

        values = dns.get(
            record_type,
            []
        )

        dns_rows.append([
            record_type,
            format_dns_value(
                record_type,
                values
            )
        ])

    add_information_table(
        story,
        dns_rows,
        styles
    )

    story.append(
        PageBreak()
    )

    # ======================================================
    # PAGE 4 - COMPLETE DETECTION RESULTS
    # ======================================================

    add_section_title(
        story,
        "Complete Detection Results",
        styles
    )

    if analysis:

        detection_rows = build_detection_rows(
            analysis
        )

        add_detection_table(
            story,
            detection_rows,
            styles
        )

    else:

        story.append(
            Paragraph(
                (
                    "Advanced detection results were not available "
                    "for this report."
                ),
                styles["BodyNormalCustom"]
            )
        )

    if analysis:

        story.append(
            Spacer(
                1,
                12
            )
        )

        add_section_title(
            story,
            "Detailed Webpage and Network Findings",
            styles
        )

        add_information_table(
            story,
            [
                [
                    "Final Redirect URL",
                    get_nested(
                        analysis,
                        "redirects",
                        "final_url",
                        "Not Available"
                    )
                ],
                [
                    "Redirect Count",
                    get_nested(
                        analysis,
                        "redirects",
                        "count",
                        0
                    )
                ],
                [
                    "Missing Security Headers",
                    format_list(
                        get_nested(
                            analysis,
                            "security_headers",
                            "missing",
                            []
                        )
                    )
                ],
                [
                    "JavaScript Patterns",
                    format_list(
                        get_nested(
                            analysis,
                            "javascript",
                            "patterns",
                            []
                        )
                    )
                ],
                [
                    "Form Issues",
                    format_list(
                        get_nested(
                            analysis,
                            "forms",
                            "issues",
                            []
                        )
                    )
                ],
                [
                    "Content Patterns",
                    format_list(
                        get_nested(
                            analysis,
                            "content",
                            "patterns",
                            []
                        )
                    )
                ],
                [
                    "Favicon URL",
                    get_nested(
                        analysis,
                        "favicon",
                        "url",
                        "Not Available"
                    )
                ],
                [
                    "Suspicious Query Parameters",
                    format_list(
                        get_nested(
                            analysis,
                            "query_parameters",
                            "matches",
                            []
                        )
                    )
                ],
                [
                    "Email Addresses in URL",
                    format_list(
                        get_nested(
                            analysis,
                            "email_address",
                            "matches",
                            []
                        )
                    )
                ]
            ],
            styles
        )

    add_recommendations(
        story,
        risk_score,
        styles
    )

    story.append(
        Spacer(
            1,
            14
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Important:</b> This report is generated using "
                "automated heuristics and technical checks. A low "
                "score does not guarantee that a website is safe. "
                "A high score should be verified using trusted "
                "threat-intelligence and reputation services."
            ),
            styles["Disclaimer"]
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    story.append(
        Paragraph(
            (
                f"<b>Generated by:</b> URL Security Analyzer<br/>"
                f"<b>Engine:</b> {ENGINE_NAME}<br/>"
                f"<b>Version:</b> {REPORT_VERSION}<br/>"
                f"<b>Generated:</b> {generated_time}"
            ),
            styles["BodySmall"]
        )
    )

    document.build(
        story,
        onFirstPage=draw_page_layout,
        onLaterPages=draw_page_layout
    )