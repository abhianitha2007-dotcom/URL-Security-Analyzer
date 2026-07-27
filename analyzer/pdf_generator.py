from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)



def safe_text(value):

    """
    Prevents PDF errors
    """

    if value is None:
        return "Unknown"

    return str(value)





def add_section_title(story, title, styles):

    story.append(
        Spacer(1, 12)
    )

    story.append(
        Paragraph(
            f"<b>{title}</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(1, 6)
    )





def add_table(story, data):

    formatted = []


    for row in data:

        formatted.append(
            [
                safe_text(row[0]),
                Paragraph(
                    safe_text(row[1]),
                    getSampleStyleSheet()["BodyText"]
                )
            ]
        )


    table = Table(
        formatted,
        colWidths=[
            150,
            330
        ]
    )


    table.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            ),


            (
                "BACKGROUND",
                (0,0),
                (0,-1),
                colors.lightgrey
            ),


            (
                "VALIGN",
                (0,0),
                (-1,-1),
                "TOP"
            ),


            (
                "BOTTOMPADDING",
                (0,0),
                (-1,-1),
                8
            ),


            (
                "TOPPADDING",
                (0,0),
                (-1,-1),
                8
            )

        ])

    )


    story.append(table)





def generate_pdf(report_data, output_path):

    """
    Generates URL Security Analyzer PDF report.
    """

    styles = getSampleStyleSheet()


    doc = SimpleDocTemplate(

        output_path,

        pagesize=letter

    )


    story = []



    # Title

    story.append(

        Paragraph(

            "<b>URL Security Analyzer Report</b>",

            styles["Title"]

        )

    )


    story.append(
        Spacer(1,20)
    )



    story.append(

        Paragraph(

            f"Generated: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",

            styles["Normal"]

        )

    )




    # URL

    add_section_title(
        story,
        "Analyzed URL",
        styles
    )


    story.append(

        Paragraph(

            safe_text(
                report_data.get("url")
            ),

            styles["BodyText"]

        )

    )




    # Risk

    add_section_title(
        story,
        "Risk Summary",
        styles
    )


    add_table(

        story,

        [

            [
                "Risk Score",
                f"{report_data.get('risk_score',0)}/100"
            ],

            [
                "Verdict",
                report_data.get("verdict")
            ]

        ]

    )




    # Checks

    add_section_title(

        story,

        "Security Checks",

        styles

    )


    add_table(

        story,

        [

            [
                "HTTPS",
                report_data.get("https_status")
            ],

            [
                "IP Detection",
                report_data.get("ip_status")
            ],

            [
                "Keywords",
                report_data.get("keyword_count")
            ],

            [
                "URL Length",
                report_data.get("url_length")
            ],

            [
                "Subdomains",
                report_data.get("subdomain_count")
            ],

            [
                "@ Symbol",
                report_data.get("at_status")
            ],

            [
                "URL Shortener",
                report_data.get("shortener_status")
            ],

            [
                "Hyphens",
                report_data.get("hyphen_count")
            ],

            [
                "TLD",
                report_data.get("tld_status")
            ]

        ]

    )




    # WHOIS

    add_section_title(

        story,

        "WHOIS Information",

        styles

    )


    whois = report_data.get(
        "whois",
        {}
    )


    add_table(

        story,

        [

            [
                "Registrar",
                whois.get("registrar")
            ],

            [
                "Created",
                whois.get("creation_date")
            ],

            [
                "Expires",
                whois.get("expiration_date")
            ],

            [
                "Updated",
                whois.get("updated_date")
            ]

        ]

    )




    # SSL

    add_section_title(

        story,

        "SSL Certificate",

        styles

    )


    ssl = report_data.get(
        "ssl",
        {}
    )


    add_table(

        story,

        [

            [
                "Issuer",
                ssl.get("issuer")
            ],

            [
                "Status",
                ssl.get("status")
            ],

            [
                "Valid Until",
                ssl.get("valid_to")
            ],

            [
                "Days Remaining",
                ssl.get("days_remaining")
            ]

        ]

    )




    # DNS

    add_section_title(

        story,

        "DNS Records",

        styles

    )


    dns = report_data.get(
        "dns",
        {}
    )


    dns_rows = []


    for record, values in dns.items():

        if values:

            value = ", ".join(values)

        else:

            value = "None"


        dns_rows.append(

            [
                record,
                value
            ]

        )


    add_table(
        story,
        dns_rows
    )




    story.append(
        Spacer(1,20)
    )


    story.append(

        Paragraph(

            "<b>Generated by URL Security Analyzer</b>",

            styles["Normal"]

        )

    )


    doc.build(story)