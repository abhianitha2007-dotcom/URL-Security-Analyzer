from datetime import datetime
from xml.sax.saxutils import escape
import os
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle
)


PAGE_WIDTH, PAGE_HEIGHT = A4
CONTENT_WIDTH = 180 * mm

REPORT_VERSION = "2.2"
ENGINE_NAME = "Multi-Layer URL Threat Detection Engine"


def remove_emoji(value):
    pattern = re.compile(
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

    text = pattern.sub(
        "",
        str(value)
    ).strip()

    return (
        text
        .replace("—", "-")
        .replace("–", "-")
    )


def safe_text(value):
    if value is None:
        return "Unavailable"

    if isinstance(
        value,
        bool
    ):
        return (
            "Yes"
            if value
            else "No"
        )

    if isinstance(
        value,
        (
            list,
            tuple,
            set
        )
    ):
        if not value:
            return "None"

        return ", ".join(
            remove_emoji(item)
            for item in value
        )

    return remove_emoji(
        value
    )


def pdf_text(value):
    return escape(
        safe_text(
            value
        )
    )


def format_list(
    values,
    empty="None",
    limit=None
):
    if not values:
        return empty

    if isinstance(
        values,
        str
    ):
        return safe_text(
            values
        )

    items = list(
        values
    )

    shown = (
        items
        if limit is None
        else items[:limit]
    )

    text = ", ".join(
        safe_text(item)
        for item in shown
    )

    if (
        limit is not None
        and len(items) > limit
    ):
        text += (
            f" ... and "
            f"{len(items) - limit} more"
        )

    return text


def get_nested(
    data,
    section,
    field,
    default=None
):
    section_data = data.get(
        section,
        {}
    )

    if not isinstance(
        section_data,
        dict
    ):
        return default

    return section_data.get(
        field,
        default
    )


def clean_status(
    value,
    context="generic"
):
    text = safe_text(
        value
    ).strip()

    lower = text.lower()

    unavailable_values = {
        "",
        "none",
        "unknown",
        "n/a",
        "not available",
        "not checked",
        "unavailable"
    }

    if lower in unavailable_values:
        return {
            "ssl":
                "Certificate information unavailable",

            "dns":
                "DNS information unavailable",

            "whois":
                "Registration data unavailable",

            "robots":
                "Could not verify robots.txt",

            "sitemap":
                "Could not verify sitemap",

            "threat":
                "Reputation information unavailable",

            "favicon":
                "Favicon information unavailable",

            "file":
                "File exposure check unavailable"

        }.get(
            context,
            "Unavailable"
        )

    if "404" in lower:
        return {
            "robots":
                "No robots.txt found",

            "sitemap":
                "No sitemap found",

            "file":
                "Not exposed",

            "favicon":
                "No favicon found"

        }.get(
            context,
            "Requested resource not found"
        )

    if any(
        code in lower
        for code in (
            "502",
            "503",
            "504"
        )
    ):
        if context == "robots":
            return (
                "Could not verify robots.txt - "
                "website temporarily unavailable"
            )

        if context == "sitemap":
            return (
                "Could not verify sitemap - "
                "website temporarily unavailable"
            )

        return (
            "Could not verify - "
            "website temporarily unavailable"
        )

    if (
        "403" in lower
        and context == "robots"
    ):
        return (
            "robots.txt access restricted"
        )

    if "429" in lower:
        return (
            "Could not verify - "
            "request was rate limited"
        )

    if any(
        term in lower
        for term in (
            "timeout",
            "timed out",
            "did not respond"
        )
    ):
        if context == "robots":
            return (
                "Could not verify robots.txt - "
                "website did not respond"
            )

        return (
            "Could not verify - "
            "website did not respond"
        )

    if any(
        term in lower
        for term in (
            "request failed",
            "connection failed",
            "connection error",
            "website unavailable",
            "temporarily unavailable"
        )
    ):
        return (
            "Could not verify - "
            "website unavailable"
        )

    if lower.startswith(
        "not checked"
    ):
        return (
            "Could not verify"
        )

    return text


def simplify_whois_status(
    value
):
    text = clean_status(
        value,
        "whois"
    )

    if (
        text
        == "Registration data unavailable"
    ):
        return text

    statuses = re.findall(
        (
            r"\b(?:client|server)"
            r"[A-Za-z]+Prohibited\b"
            r"|\bok\b"
        ),
        text
    )

    unique = list(
        dict.fromkeys(
            statuses
        )
    )

    if unique:
        return ", ".join(
            unique
        )

    if len(text) > 260:
        return (
            text[:257]
            + "..."
        )

    return text


def format_dns_value(
    record_type,
    values
):
    if not values:
        return (
            "Not available"
        )

    if isinstance(
        values,
        str
    ):
        values = [
            values
        ]

    if (
        record_type
        != "TXT"
    ):
        return format_list(
            values,
            "Not available",
            limit=10
        )

    output = []

    for value in list(
        values
    )[:5]:
        text = safe_text(
            value
        )

        if len(text) > 110:
            text = (
                text[:107]
                + "..."
            )

        output.append(
            text
        )

    result = ", ".join(
        output
    )

    if len(values) > 5:
        result += (
            f" ... and "
            f"{len(values) - 5} "
            f"more record(s)"
        )

    return result


def normalize_score(
    value
):
    try:
        return max(
            0,
            min(
                int(value),
                100
            )
        )

    except (
        TypeError,
        ValueError
    ):
        return 0


def get_risk_details(
    score
):
    score = normalize_score(
        score
    )

    if score > 75:
        return (
            "CRITICAL",
            colors.HexColor(
                "#991B1B"
            ),
            colors.HexColor(
                "#FEE2E2"
            ),
            (
                "Do not visit this website "
                "or provide any information."
            )
        )

    if score > 50:
        return (
            "HIGH RISK",
            colors.HexColor(
                "#DC2626"
            ),
            colors.HexColor(
                "#FEE2E2"
            ),
            (
                "Avoid entering credentials, "
                "payment information or "
                "downloading files."
            )
        )

    if score > 30:
        return (
            "MEDIUM RISK",
            colors.HexColor(
                "#D97706"
            ),
            colors.HexColor(
                "#FEF3C7"
            ),
            (
                "Proceed carefully and "
                "independently verify the domain."
            )
        )

    if score > 15:
        return (
            "LOW RISK",
            colors.HexColor(
                "#0284C7"
            ),
            colors.HexColor(
                "#E0F2FE"
            ),
            (
                "Only minor indicators were "
                "detected. Continue with caution."
            )
        )

    return (
        "SAFE",
        colors.HexColor(
            "#15803D"
        ),
        colors.HexColor(
            "#DCFCE7"
        ),
        (
            "No major suspicious indicators "
            "were detected."
        )
    )


def build_styles():
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles[
                "Title"
            ],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=23,
            alignment=TA_CENTER,
            textColor=colors.HexColor(
                "#0F172A"
            ),
            spaceAfter=3
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles[
                "Normal"
            ],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor(
                "#475569"
            ),
            spaceAfter=6
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles[
                "Heading2"
            ],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            textColor=colors.HexColor(
                "#0F172A"
            ),
            spaceBefore=6,
            spaceAfter=3
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles[
                "BodyText"
            ],
            fontName="Helvetica",
            fontSize=7.4,
            leading=9.4,
            textColor=colors.HexColor(
                "#334155"
            ),
            spaceAfter=0
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodyNormalCustom",
            parent=styles[
                "BodyText"
            ],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.5,
            textColor=colors.HexColor(
                "#334155"
            ),
            spaceAfter=0
        )
    )

    styles.add(
        ParagraphStyle(
            name="Evidence",
            parent=styles[
                "BodyText"
            ],
            fontName="Helvetica",
            fontSize=8,
            leading=10.2,
            leftIndent=8,
            firstLineIndent=-5,
            textColor=colors.HexColor(
                "#334155"
            ),
            spaceAfter=1
        )
    )

    styles.add(
        ParagraphStyle(
            name="Disclaimer",
            parent=styles[
                "BodyText"
            ],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor(
                "#64748B"
            ),
            spaceBefore=4
        )
    )

    styles.add(
        ParagraphStyle(
            name="WhiteTableText",
            parent=styles[
                "BodySmall"
            ],
            fontName="Helvetica-Bold",
            textColor=colors.white,
            alignment=TA_CENTER
        )
    )

    return styles


def draw_page_layout(
    canvas,
    document
):
    canvas.saveState()

    canvas.setStrokeColor(
        colors.HexColor(
            "#CBD5E1"
        )
    )

    canvas.setLineWidth(
        0.45
    )

    canvas.line(
        15 * mm,
        PAGE_HEIGHT - 12 * mm,
        PAGE_WIDTH - 15 * mm,
        PAGE_HEIGHT - 12 * mm
    )

    canvas.line(
        15 * mm,
        14 * mm,
        PAGE_WIDTH - 15 * mm,
        14 * mm
    )

    canvas.setFillColor(
        colors.HexColor(
            "#334155"
        )
    )

    canvas.setFont(
        "Helvetica-Bold",
        7.5
    )

    canvas.drawString(
        15 * mm,
        PAGE_HEIGHT - 9 * mm,
        "URL Security Analyzer"
    )

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.drawRightString(
        PAGE_WIDTH - 15 * mm,
        PAGE_HEIGHT - 9 * mm,
        "Security Analysis Report"
    )

    canvas.setFillColor(
        colors.HexColor(
            "#64748B"
        )
    )

    canvas.setFont(
        "Helvetica",
        7
    )

    canvas.drawString(
        15 * mm,
        9 * mm,
        (
            f"URL Security Analyzer "
            f"v{REPORT_VERSION}"
        )
    )

    canvas.drawRightString(
        PAGE_WIDTH - 15 * mm,
        9 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


def add_section_title(
    story,
    title,
    styles
):
    story.append(
        Paragraph(
            pdf_text(
                title
            ),
            styles[
                "SectionTitle"
            ]
        )
    )


def add_information_table(
    story,
    rows,
    styles,
    label_width=48 * mm
):
    if not rows:
        return

    table_rows = []

    for label, value in rows:
        table_rows.append(
            [
                Paragraph(
                    (
                        f"<b>"
                        f"{pdf_text(label)}"
                        f"</b>"
                    ),
                    styles[
                        "BodySmall"
                    ]
                ),
                Paragraph(
                    pdf_text(
                        value
                    ),
                    styles[
                        "BodySmall"
                    ]
                )
            ]
        )

    table = LongTable(
        table_rows,
        colWidths=[
            label_width,
            (
                CONTENT_WIDTH
                - label_width
            )
        ],
        hAlign="LEFT",
        splitByRow=1
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#E2E8F0"
                    )
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    colors.HexColor(
                        "#F8FAFC"
                    )
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor(
                        "#CBD5E1"
                    )
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
                    4
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    3.5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    3.5
                )
            ]
        )
    )

    story.append(
        table
    )


def add_detection_table(
    story,
    rows,
    styles
):
    data = [
        [
            Paragraph(
                "<b>Detection Module</b>",
                styles[
                    "WhiteTableText"
                ]
            ),
            Paragraph(
                "<b>Result</b>",
                styles[
                    "WhiteTableText"
                ]
            )
        ]
    ]

    for name, status in rows:
        data.append(
            [
                Paragraph(
                    pdf_text(
                        name
                    ),
                    styles[
                        "BodySmall"
                    ]
                ),
                Paragraph(
                    pdf_text(
                        status
                    ),
                    styles[
                        "BodySmall"
                    ]
                )
            ]
        )

    table = LongTable(
        data,
        colWidths=[
            51 * mm,
            129 * mm
        ],
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#0F172A"
                    )
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.HexColor(
                        "#F8FAFC"
                    )
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor(
                        "#CBD5E1"
                    )
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
                    4
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    3
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    3
                )
            ]
        )
    )

    story.append(
        table
    )


def add_risk_meter(
    story,
    risk_score,
    verdict,
    styles
):
    score = normalize_score(
        risk_score
    )

    (
        label,
        color,
        light,
        recommendation
    ) = get_risk_details(
        score
    )

    white = styles[
        "WhiteTableText"
    ]

    summary = Table(
        [
            [
                Paragraph(
                    "Risk Score",
                    white
                ),
                Paragraph(
                    f"{score}/100",
                    white
                ),
                Paragraph(
                    "Verdict",
                    white
                ),
                Paragraph(
                    pdf_text(
                        verdict
                    ),
                    white
                ),
                Paragraph(
                    "Threat Level",
                    white
                ),
                Paragraph(
                    label,
                    white
                )
            ]
        ],
        colWidths=[
            24 * mm,
            23 * mm,
            21 * mm,
            35 * mm,
            27 * mm,
            50 * mm
        ]
    )

    summary.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    color
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
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
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ]
        )
    )

    story.append(
        summary
    )

    story.append(
        Spacer(
            1,
            4
        )
    )

    filled = (
        CONTENT_WIDTH
        * score
        / 100
    )

    empty = (
        CONTENT_WIDTH
        - filled
    )

    if score == 0:
        meter = Table(
            [[""]],
            colWidths=[
                CONTENT_WIDTH
            ],
            rowHeights=[
                3.5 * mm
            ]
        )

        meter_style = [
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor(
                    "#E2E8F0"
                )
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor(
                    "#94A3B8"
                )
            )
        ]

    elif score == 100:
        meter = Table(
            [[""]],
            colWidths=[
                CONTENT_WIDTH
            ],
            rowHeights=[
                3.5 * mm
            ]
        )

        meter_style = [
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                color
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor(
                    "#94A3B8"
                )
            )
        ]

    else:
        meter = Table(
            [
                [
                    "",
                    ""
                ]
            ],
            colWidths=[
                filled,
                empty
            ],
            rowHeights=[
                3.5 * mm
            ]
        )

        meter_style = [
            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                color
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, 0),
                colors.HexColor(
                    "#E2E8F0"
                )
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor(
                    "#94A3B8"
                )
            )
        ]

    meter.setStyle(
        TableStyle(
            meter_style
        )
    )

    story.append(
        meter
    )

    story.append(
        Spacer(
            1,
            4
        )
    )

    box = Table(
        [
            [
                Paragraph(
                    (
                        f"<b>Recommendation:</b> "
                        f"{pdf_text(recommendation)}"
                    ),
                    styles[
                        "BodyNormalCustom"
                    ]
                )
            ]
        ],
        colWidths=[
            CONTENT_WIDTH
        ]
    )

    box.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    light
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    color
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
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ]
        )
    )

    story.append(
        box
    )


def add_notice(
    story,
    title,
    message,
    styles,
    danger=False
):
    border = colors.HexColor(
        (
            "#DC2626"
            if danger
            else "#D97706"
        )
    )

    background = colors.HexColor(
        (
            "#FEE2E2"
            if danger
            else "#FEF3C7"
        )
    )

    box = Table(
        [
            [
                Paragraph(
                    (
                        f"<b>"
                        f"{pdf_text(title)}"
                        f"</b><br/>"
                        f"{pdf_text(message)}"
                    ),
                    styles[
                        "BodyNormalCustom"
                    ]
                )
            ]
        ],
        colWidths=[
            CONTENT_WIDTH
        ]
    )

    box.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    background
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    border
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
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ]
        )
    )

    story.append(
        Spacer(
            1,
            4
        )
    )

    story.append(
        box
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

    reasons = (
        reasons
        or [
            (
                "No major suspicious "
                "indicators were detected."
            )
        ]
    )

    for reason in reasons:
        story.append(
            Paragraph(
                (
                    f"&#8226; "
                    f"{pdf_text(reason)}"
                ),
                styles[
                    "Evidence"
                ]
            )
        )


def get_recommendations(
    score
):
    score = normalize_score(
        score
    )

    if score > 75:
        return [
            (
                "Do not open or continue "
                "using this website."
            ),
            (
                "Do not enter passwords, OTPs, "
                "banking or payment information."
            ),
            (
                "Do not download files "
                "or install applications."
            ),
            (
                "Use the organization's official "
                "website or mobile application."
            )
        ]

    if score > 50:
        return [
            (
                "Avoid entering personal, "
                "financial or authentication "
                "information."
            ),
            (
                "Verify the registered domain "
                "and organization independently."
            ),
            (
                "Do not download unexpected files."
            ),
            (
                "Use an official bookmark, "
                "application or trusted search result."
            )
        ]

    if score > 30:
        return [
            (
                "Proceed only after verifying "
                "the domain carefully."
            ),
            (
                "Check WHOIS, certificate and "
                "organization details."
            ),
            (
                "Avoid sharing credentials until "
                "legitimacy is confirmed."
            ),
            (
                "Be cautious of redirects "
                "and login requests."
            )
        ]

    if score > 15:
        return [
            (
                "Only minor risk indicators "
                "were detected."
            ),
            (
                "Verify the URL spelling before "
                "entering sensitive information."
            ),
            (
                "Confirm that the website belongs "
                "to the expected organization."
            ),
            (
                "Avoid links received "
                "from unknown senders."
            )
        ]

    return [
        (
            "No major phishing indicators "
            "were detected."
        ),
        (
            "Always verify the URL before "
            "entering credentials."
        ),
        (
            "Use multi-factor authentication "
            "where available."
        ),
        (
            "Avoid sensitive actions after "
            "opening links from unknown senders."
        )
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

    for item in get_recommendations(
        score
    ):
        story.append(
            Paragraph(
                (
                    f"&#8226; "
                    f"{pdf_text(item)}"
                ),
                styles[
                    "Evidence"
                ]
            )
        )


def build_detection_rows(
    analysis
):
    keyword_data = analysis.get(
        "keywords",
        {}
    )

    if not isinstance(
        keyword_data,
        dict
    ):
        keyword_data = {}

    count = keyword_data.get(
        "count",
        0
    )

    matches = keyword_data.get(
        "matches",
        []
    )

    if count:
        keyword_result = (
            f"{count} suspicious keyword(s): "
            f"{format_list(matches)}"
        )

    else:
        keyword_result = (
            "No suspicious keywords detected"
        )

    domain_age = analysis.get(
        "domain_age",
        {}
    )

    if isinstance(
        domain_age,
        dict
    ):
        domain_age_result = clean_status(
            (
                domain_age.get(
                    "message"
                )
                or domain_age.get(
                    "status"
                )
            ),
            "whois"
        )

    else:
        domain_age_result = (
            "Registration data unavailable"
        )

    rows = [
        (
            "HTTPS",
            get_nested(
                analysis,
                "https",
                "status"
            ),
            "generic"
        ),
        (
            "IP Address",
            get_nested(
                analysis,
                "ip_address",
                "status"
            ),
            "generic"
        ),
        (
            "Suspicious Keywords",
            keyword_result,
            "generic"
        ),
        (
            "URL Length",
            get_nested(
                analysis,
                "url_length",
                "status"
            ),
            "generic"
        ),
        (
            "Subdomains",
            get_nested(
                analysis,
                "subdomains",
                "status"
            ),
            "generic"
        ),
        (
            "At Symbol",
            get_nested(
                analysis,
                "at_symbol",
                "status"
            ),
            "generic"
        ),
        (
            "URL Shortener",
            get_nested(
                analysis,
                "shortener",
                "status"
            ),
            "generic"
        ),
        (
            "Hyphens",
            get_nested(
                analysis,
                "hyphens",
                "status"
            ),
            "generic"
        ),
        (
            "Top-Level Domain",
            get_nested(
                analysis,
                "tld",
                "status"
            ),
            "generic"
        ),
        (
            "Domain Age",
            domain_age_result,
            "generic"
        ),
        (
            "Domain Similarity",
            get_nested(
                analysis,
                "domain_similarity",
                "status"
            ),
            "generic"
        ),
        (
            "Typosquatting",
            get_nested(
                analysis,
                "typosquatting",
                "status"
            ),
            "generic"
        ),
        (
            "Homograph",
            get_nested(
                analysis,
                "homograph",
                "status"
            ),
            "generic"
        ),
        (
            "Punycode",
            get_nested(
                analysis,
                "punycode",
                "status"
            ),
            "generic"
        ),
        (
            "Domain Entropy",
            get_nested(
                analysis,
                "entropy",
                "status"
            ),
            "generic"
        ),
        (
            "Port",
            get_nested(
                analysis,
                "port",
                "status"
            ),
            "generic"
        ),
        (
            "Query Parameters",
            get_nested(
                analysis,
                "query_parameters",
                "status"
            ),
            "generic"
        ),
        (
            "Email Address",
            get_nested(
                analysis,
                "email_address",
                "status"
            ),
            "generic"
        ),
        (
            "File Extension",
            get_nested(
                analysis,
                "file_extension",
                "status"
            ),
            "generic"
        ),
        (
            "Redirects",
            get_nested(
                analysis,
                "redirects",
                "status"
            ),
            "generic"
        ),
        (
            "Security Headers",
            get_nested(
                analysis,
                "security_headers",
                "status"
            ),
            "generic"
        ),
        (
            "JavaScript",
            get_nested(
                analysis,
                "javascript",
                "status"
            ),
            "generic"
        ),
        (
            "Forms",
            get_nested(
                analysis,
                "forms",
                "status"
            ),
            "generic"
        ),
        (
            "Page Content",
            get_nested(
                analysis,
                "content",
                "status"
            ),
            "generic"
        ),
        (
            "Favicon",
            get_nested(
                analysis,
                "favicon",
                "status"
            ),
            "favicon"
        ),
        (
            "robots.txt",
            get_nested(
                analysis,
                "robots",
                "status"
            ),
            "robots"
        ),
        (
            "Sitemap",
            get_nested(
                analysis,
                "sitemap",
                "status"
            ),
            "sitemap"
        ),
        (
            "Response Headers",
            get_nested(
                analysis,
                "response_headers",
                "status"
            ),
            "generic"
        ),
        (
            "Technology",
            get_nested(
                analysis,
                "technology",
                "status"
            ),
            "generic"
        ),
        (
            "Sensitive File Exposure",
            get_nested(
                analysis,
                "file_exposure",
                "status"
            ),
            "file"
        ),
        (
            "HTTP Methods",
            get_nested(
                analysis,
                "http_methods",
                "status"
            ),
            "generic"
        ),
        (
            "Cookie Security",
            get_nested(
                analysis,
                "cookie_security",
                "status"
            ),
            "generic"
        ),
        (
            "CORS",
            get_nested(
                analysis,
                "cors",
                "status"
            ),
            "generic"
        ),
        (
            "Mixed Content",
            get_nested(
                analysis,
                "mixed_content",
                "status"
            ),
            "generic"
        ),
        (
            "Threat Intelligence",
            get_nested(
                analysis,
                "threat_intelligence",
                "status"
            ),
            "threat"
        )
    ]

    return [
        (
            name,
            clean_status(
                status,
                context
            )
        )
        for (
            name,
            status,
            context
        ) in rows
    ]


def get_scan_status(
    report_data,
    analysis
):
    status = report_data.get(
        "scan_status"
    )

    if not isinstance(
        status,
        dict
    ):
        status = (
            analysis.get(
                "scan_status",
                {}
            )
            if isinstance(
                analysis,
                dict
            )
            else {}
        )

    if not isinstance(
        status,
        dict
    ):
        status = {}

    return {
        "mode":
            status.get(
                "mode",
                "full"
            ),

        "label":
            status.get(
                "label",
                "Full Analysis"
            ),

        "message":
            status.get(
                "message",
                (
                    "Available security checks "
                    "were completed for this target."
                )
            )
    }


def get_content_warning(
    report_data,
    analysis
):
    warning = report_data.get(
        "content_warning"
    )

    if not isinstance(
        warning,
        dict
    ):
        warning = (
            analysis.get(
                "content_warning",
                {}
            )
            if isinstance(
                analysis,
                dict
            )
            else {}
        )

    if not isinstance(
        warning,
        dict
    ):
        return {}

    return warning


def add_section(
    story,
    title,
    rows,
    styles
):
    add_section_title(
        story,
        title,
        styles
    )

    add_information_table(
        story,
        rows,
        styles
    )


def generate_pdf(
    report_data,
    output_path
):
    os.makedirs(
        os.path.dirname(
            os.path.abspath(
                output_path
            )
        ),
        exist_ok=True
    )

    styles = build_styles()

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=(
            "URL Security Analyzer Report"
        ),
        author=(
            "URL Security Analyzer"
        ),
        subject=(
            "URL and phishing risk analysis"
        )
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

    if not isinstance(
        analysis,
        dict
    ):
        analysis = {}

    generated_time = (
        datetime.now().strftime(
            "%d-%m-%Y %H:%M:%S"
        )
    )

    scan_status = get_scan_status(
        report_data,
        analysis
    )

    warning = get_content_warning(
        report_data,
        analysis
    )

    story.append(
        Paragraph(
            "URL Security Analyzer",
            styles[
                "ReportTitle"
            ]
        )
    )

    story.append(
        Paragraph(
            (
                "URL, domain, network, webpage "
                "and threat-intelligence "
                "security report"
            ),
            styles[
                "ReportSubtitle"
            ]
        )
    )

    add_risk_meter(
        story,
        risk_score,
        verdict,
        styles
    )

    add_section(
        story,
        "Executive Summary",
        [
            (
                "Analyzed URL",
                report_data.get(
                    "url",
                    "Unavailable"
                )
            ),
            (
                "Analysis Coverage",
                scan_status[
                    "label"
                ]
            ),
            (
                "Risk Score",
                f"{risk_score}/100"
            ),
            (
                "Final Verdict",
                verdict
            ),
            (
                "Report Generated",
                generated_time
            ),
            (
                "Scanner Version",
                REPORT_VERSION
            ),
            (
                "Detection Engine",
                ENGINE_NAME
            )
        ],
        styles
    )

    if (
        scan_status[
            "mode"
        ]
        == "partial"
    ):
        add_notice(
            story,
            "Partial Analysis",
            (
                f"{scan_status['message']} "
                "Unavailable checks were not "
                "treated as safe results."
            ),
            styles
        )

    if warning.get(
        "show"
    ):
        add_notice(
            story,
            warning.get(
                "title",
                "Website Notice"
            ),
            warning.get(
                "message",
                (
                    "Additional caution "
                    "is recommended."
                )
            ),
            styles,
            danger=(
                warning.get(
                    "type"
                )
                in {
                    "adult",
                    "gambling"
                }
            )
        )

    add_evidence_summary(
        story,
        report_data.get(
            "reasons",
            []
        ),
        styles
    )

    add_section(
        story,
        "URL Structure Analysis",
        [
            (
                "HTTPS",
                clean_status(
                    report_data.get(
                        "https_status"
                    )
                )
            ),
            (
                "IP Address",
                clean_status(
                    report_data.get(
                        "ip_status"
                    )
                )
            ),
            (
                "Suspicious Keywords",
                (
                    f"{report_data.get('keyword_count', 0)} "
                    f"detected - "
                    f"{format_list(report_data.get('keywords', []))}"
                )
            ),
            (
                "URL Length",
                (
                    f"{report_data.get('url_length', 'Unavailable')} "
                    f"characters - "
                    f"{clean_status(report_data.get('length_category'))}"
                )
            ),
            (
                "Subdomains",
                (
                    f"{report_data.get('subdomain_count', 0)} - "
                    f"{clean_status(report_data.get('subdomain_status'))}"
                )
            ),
            (
                "At Symbol",
                clean_status(
                    report_data.get(
                        "at_status"
                    )
                )
            ),
            (
                "URL Shortener",
                clean_status(
                    report_data.get(
                        "shortener_status"
                    )
                )
            ),
            (
                "Hyphens",
                (
                    f"{report_data.get('hyphen_count', 0)} - "
                    f"{clean_status(report_data.get('hyphen_status'))}"
                )
            ),
            (
                "Top-Level Domain",
                (
                    f"{safe_text(report_data.get('tld', 'Unavailable'))} - "
                    f"{clean_status(report_data.get('tld_status'))}"
                )
            )
        ],
        styles
    )

    domain_age = report_data.get(
        "domain_age",
        {}
    )

    if not isinstance(
        domain_age,
        dict
    ):
        domain_age = {}

    add_section(
        story,
        "Domain Age",
        [
            (
                "Age",
                clean_status(
                    domain_age.get(
                        "age"
                    ),
                    "whois"
                )
            ),
            (
                "Status",
                clean_status(
                    (
                        domain_age.get(
                            "message"
                        )
                        or domain_age.get(
                            "status"
                        )
                    ),
                    "whois"
                )
            ),
            (
                "Confirmed New",
                domain_age.get(
                    "confirmed_new",
                    False
                )
            )
        ],
        styles
    )

    if analysis:
        add_section(
            story,
            "Domain Identity Checks",
            [
                (
                    "Domain Similarity",
                    clean_status(
                        get_nested(
                            analysis,
                            "domain_similarity",
                            "status"
                        )
                    )
                ),
                (
                    "Similarity Matches",
                    format_list(
                        get_nested(
                            analysis,
                            "domain_similarity",
                            "matches",
                            []
                        ),
                        limit=8
                    )
                ),
                (
                    "Typosquatting",
                    clean_status(
                        get_nested(
                            analysis,
                            "typosquatting",
                            "status"
                        )
                    )
                ),
                (
                    "Homograph",
                    clean_status(
                        get_nested(
                            analysis,
                            "homograph",
                            "status"
                        )
                    )
                ),
                (
                    "Punycode",
                    clean_status(
                        get_nested(
                            analysis,
                            "punycode",
                            "status"
                        )
                    )
                ),
                (
                    "Domain Entropy",
                    clean_status(
                        get_nested(
                            analysis,
                            "entropy",
                            "status"
                        )
                    )
                )
            ],
            styles
        )

    whois = report_data.get(
        "whois",
        {}
    )

    if not isinstance(
        whois,
        dict
    ):
        whois = {}

    add_section(
        story,
        "WHOIS Information",
        [
            (
                "Registrar",
                clean_status(
                    whois.get(
                        "registrar"
                    ),
                    "whois"
                )
            ),
            (
                "Organization",
                clean_status(
                    whois.get(
                        "organization"
                    ),
                    "whois"
                )
            ),
            (
                "Country",
                clean_status(
                    whois.get(
                        "country"
                    ),
                    "whois"
                )
            ),
            (
                "Creation Date",
                clean_status(
                    whois.get(
                        "creation_date"
                    ),
                    "whois"
                )
            ),
            (
                "Updated Date",
                clean_status(
                    whois.get(
                        "updated_date"
                    ),
                    "whois"
                )
            ),
            (
                "Expiration Date",
                clean_status(
                    whois.get(
                        "expiration_date"
                    ),
                    "whois"
                )
            ),
            (
                "Domain Status",
                simplify_whois_status(
                    whois.get(
                        "status"
                    )
                )
            ),
            (
                "Name Servers",
                format_list(
                    whois.get(
                        "name_servers",
                        []
                    ),
                    "Unavailable",
                    limit=8
                )
            )
        ],
        styles
    )

    ssl_info = report_data.get(
        "ssl",
        {}
    )

    if not isinstance(
        ssl_info,
        dict
    ):
        ssl_info = {}

    add_section(
        story,
        "SSL Certificate",
        [
            (
                "Status",
                clean_status(
                    ssl_info.get(
                        "status"
                    ),
                    "ssl"
                )
            ),
            (
                "Issuer",
                clean_status(
                    ssl_info.get(
                        "issuer"
                    ),
                    "ssl"
                )
            ),
            (
                "Subject",
                clean_status(
                    ssl_info.get(
                        "subject"
                    ),
                    "ssl"
                )
            ),
            (
                "Protocol",
                clean_status(
                    ssl_info.get(
                        "protocol"
                    ),
                    "ssl"
                )
            ),
            (
                "Cipher",
                clean_status(
                    ssl_info.get(
                        "cipher"
                    ),
                    "ssl"
                )
            ),
            (
                "Valid From",
                clean_status(
                    ssl_info.get(
                        "valid_from"
                    ),
                    "ssl"
                )
            ),
            (
                "Valid Until",
                clean_status(
                    ssl_info.get(
                        "valid_to"
                    ),
                    "ssl"
                )
            ),
            (
                "Days Remaining",
                clean_status(
                    ssl_info.get(
                        "days_remaining"
                    ),
                    "ssl"
                )
            )
        ],
        styles
    )

    dns_section = report_data.get(
        "dns",
        {}
    )

    if not isinstance(
        dns_section,
        dict
    ):
        dns_section = {}

    dns_records = dns_section.get(
        "records",
        dns_section
    )

    if not isinstance(
        dns_records,
        dict
    ):
        dns_records = {}

    add_section(
        story,
        "DNS Records",
        [
            (
                record_type,
                format_dns_value(
                    record_type,
                    dns_records.get(
                        record_type,
                        []
                    )
                )
            )
            for record_type in (
                "A",
                "AAAA",
                "MX",
                "NS",
                "CNAME",
                "TXT"
            )
        ],
        styles
    )

    add_section_title(
        story,
        "Complete Detection Results",
        styles
    )

    if analysis:
        add_detection_table(
            story,
            build_detection_rows(
                analysis
            ),
            styles
        )

    else:
        story.append(
            Paragraph(
                (
                    "Advanced detection results "
                    "were not available for "
                    "this report."
                ),
                styles[
                    "BodyNormalCustom"
                ]
            )
        )

    if analysis:
        add_section(
            story,
            "Webpage Behaviour",
            [
                (
                    "Redirect Status",
                    clean_status(
                        get_nested(
                            analysis,
                            "redirects",
                            "status"
                        )
                    )
                ),
                (
                    "Final Redirect URL",
                    clean_status(
                        get_nested(
                            analysis,
                            "redirects",
                            "final_url"
                        )
                    )
                ),
                (
                    "Redirect Count",
                    get_nested(
                        analysis,
                        "redirects",
                        "count",
                        0
                    )
                ),
                (
                    "JavaScript",
                    clean_status(
                        get_nested(
                            analysis,
                            "javascript",
                            "status"
                        )
                    )
                ),
                (
                    "JavaScript Patterns",
                    format_list(
                        get_nested(
                            analysis,
                            "javascript",
                            "patterns",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "Forms",
                    clean_status(
                        get_nested(
                            analysis,
                            "forms",
                            "status"
                        )
                    )
                ),
                (
                    "Form Issues",
                    format_list(
                        get_nested(
                            analysis,
                            "forms",
                            "issues",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "Page Content",
                    clean_status(
                        get_nested(
                            analysis,
                            "content",
                            "status"
                        )
                    )
                ),
                (
                    "Content Patterns",
                    format_list(
                        get_nested(
                            analysis,
                            "content",
                            "patterns",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "Favicon",
                    clean_status(
                        get_nested(
                            analysis,
                            "favicon",
                            "status"
                        ),
                        "favicon"
                    )
                )
            ],
            styles
        )

        add_section(
            story,
            "Server and Exposure Checks",
            [
                (
                    "Security Headers",
                    clean_status(
                        get_nested(
                            analysis,
                            "security_headers",
                            "status"
                        )
                    )
                ),
                (
                    "Missing Security Headers",
                    format_list(
                        get_nested(
                            analysis,
                            "security_headers",
                            "missing",
                            []
                        ),
                        limit=12
                    )
                ),
                (
                    "robots.txt",
                    clean_status(
                        get_nested(
                            analysis,
                            "robots",
                            "status"
                        ),
                        "robots"
                    )
                ),
                (
                    "Sitemap",
                    clean_status(
                        get_nested(
                            analysis,
                            "sitemap",
                            "status"
                        ),
                        "sitemap"
                    )
                ),
                (
                    "Technology Detection",
                    clean_status(
                        get_nested(
                            analysis,
                            "technology",
                            "status"
                        )
                    )
                ),
                (
                    "Technologies",
                    format_list(
                        get_nested(
                            analysis,
                            "technology",
                            "technologies",
                            []
                        ),
                        limit=12
                    )
                ),
                (
                    "Sensitive File Exposure",
                    clean_status(
                        get_nested(
                            analysis,
                            "file_exposure",
                            "status"
                        ),
                        "file"
                    )
                ),
                (
                    "Exposed Files",
                    format_list(
                        get_nested(
                            analysis,
                            "file_exposure",
                            "exposed_files",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "HTTP Methods",
                    clean_status(
                        get_nested(
                            analysis,
                            "http_methods",
                            "status"
                        )
                    )
                ),
                (
                    "Risky Methods",
                    format_list(
                        get_nested(
                            analysis,
                            "http_methods",
                            "risky_methods",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "Response Headers",
                    clean_status(
                        get_nested(
                            analysis,
                            "response_headers",
                            "status"
                        )
                    )
                )
            ],
            styles
        )

        cookie = analysis.get(
            "cookie_security",
            {}
        )

        cors = analysis.get(
            "cors",
            {}
        )

        mixed = analysis.get(
            "mixed_content",
            {}
        )

        threat = analysis.get(
            "threat_intelligence",
            {}
        )

        if not isinstance(
            cookie,
            dict
        ):
            cookie = {}

        if not isinstance(
            cors,
            dict
        ):
            cors = {}

        if not isinstance(
            mixed,
            dict
        ):
            mixed = {}

        if not isinstance(
            threat,
            dict
        ):
            threat = {}

        add_section(
            story,
            "Browser Security",
            [
                (
                    "Cookie Security",
                    clean_status(
                        cookie.get(
                            "status"
                        )
                    )
                ),
                (
                    "Cookies Detected",
                    cookie.get(
                        "cookie_count",
                        0
                    )
                ),
                (
                    "Secure Cookies",
                    cookie.get(
                        "secure_count",
                        0
                    )
                ),
                (
                    "HttpOnly Cookies",
                    cookie.get(
                        "httponly_count",
                        0
                    )
                ),
                (
                    "SameSite Cookies",
                    cookie.get(
                        "samesite_count",
                        0
                    )
                ),
                (
                    "Cookie Observations",
                    format_list(
                        cookie.get(
                            "issues",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "CORS Security",
                    clean_status(
                        cors.get(
                            "status"
                        )
                    )
                ),
                (
                    "Allowed Origin",
                    clean_status(
                        cors.get(
                            "allow_origin"
                        )
                    )
                ),
                (
                    "Credentials Allowed",
                    cors.get(
                        "allow_credentials",
                        False
                    )
                ),
                (
                    "Origin Reflection",
                    cors.get(
                        "origin_reflection",
                        False
                    )
                ),
                (
                    "CORS Issues",
                    format_list(
                        cors.get(
                            "issues",
                            []
                        ),
                        limit=10
                    )
                ),
                (
                    "Mixed Content",
                    clean_status(
                        mixed.get(
                            "status"
                        )
                    )
                ),
                (
                    "Active Mixed Resources",
                    mixed.get(
                        "active_count",
                        0
                    )
                ),
                (
                    "Passive Mixed Resources",
                    mixed.get(
                        "passive_count",
                        0
                    )
                )
            ],
            styles
        )

        add_section(
            story,
            "Threat Intelligence",
            [
                (
                    "Status",
                    clean_status(
                        threat.get(
                            "status"
                        ),
                        "threat"
                    )
                ),
                (
                    "Report Found",
                    threat.get(
                        "report_found",
                        False
                    )
                ),
                (
                    "Malicious Detections",
                    threat.get(
                        "malicious",
                        0
                    )
                ),
                (
                    "Suspicious Detections",
                    threat.get(
                        "suspicious",
                        0
                    )
                ),
                (
                    "Harmless",
                    threat.get(
                        "harmless",
                        0
                    )
                ),
                (
                    "Undetected",
                    threat.get(
                        "undetected",
                        0
                    )
                ),
                (
                    "Total Engines",
                    threat.get(
                        "total_engines",
                        0
                    )
                ),
                (
                    "Reputation",
                    threat.get(
                        "reputation",
                        0
                    )
                ),
                (
                    "Last Analysis",
                    clean_status(
                        threat.get(
                            "last_analysis_date"
                        ),
                        "threat"
                    )
                )
            ],
            styles
        )

    add_recommendations(
        story,
        risk_score,
        styles
    )

    story.append(
        Paragraph(
            (
                "<b>Important:</b> "
                "This report is generated using "
                "automated heuristics, technical checks "
                "and available threat-intelligence data. "
                "A low score does not guarantee that a "
                "website is safe. For Partial Analysis, "
                "unavailable checks are not treated as "
                "proof of safety."
            ),
            styles[
                "Disclaimer"
            ]
        )
    )

    story.append(
        Spacer(
            1,
            4
        )
    )

    story.append(
        Paragraph(
            (
                f"<b>Generated by:</b> "
                f"URL Security Analyzer "
                f"&nbsp;&nbsp; "

                f"<b>Engine:</b> "
                f"{pdf_text(ENGINE_NAME)} "
                f"&nbsp;&nbsp; "

                f"<b>Version:</b> "
                f"{REPORT_VERSION} "
                f"&nbsp;&nbsp; "

                f"<b>Generated:</b> "
                f"{generated_time}"
            ),
            styles[
                "BodySmall"
            ]
        )
    )

    document.build(
        story,
        onFirstPage=draw_page_layout,
        onLaterPages=draw_page_layout
    )