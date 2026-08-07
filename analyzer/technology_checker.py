import re

import requests
from analyzer.safe_http import safe_requests
from bs4 import BeautifulSoup


TECHNOLOGY_PATTERNS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes"
    ],

    "Drupal": [
        r"/sites/default/",
        r"drupalSettings"
    ],

    "Joomla": [
        r"/media/system/js/",
        r"option=com_"
    ],

    "React": [
        r"react",
        r"__REACT_DEVTOOLS_GLOBAL_HOOK__"
    ],

    "Angular": [
        r"ng-version",
        r"angular"
    ],

    "Vue.js": [
        r"vue\.js",
        r"vue\.min\.js",
        r"__VUE__"
    ],

    "Next.js": [
        r"_next/static",
        r"__NEXT_DATA__"
    ],

    "jQuery": [
        r"jquery(?:\.min)?\.js"
    ],

    "Bootstrap": [
        r"bootstrap(?:\.min)?\.(?:css|js)"
    ],

    "Google Analytics": [
        r"googletagmanager\.com",
        r"google-analytics\.com",
        r"gtag\("
    ],

    "Cloudflare": [
        r"cdn-cgi",
        r"cloudflare"
    ]
}


HEADER_PATTERNS = {
    "Apache": [
        r"apache"
    ],

    "Nginx": [
        r"nginx"
    ],

    "Microsoft IIS": [
        r"microsoft-iis"
    ],

    "Google Web Server": [
        r"\bgws\b"
    ],

    "Cloudflare": [
        r"cloudflare"
    ],

    "PHP": [
        r"\bphp\b"
    ],

    "ASP.NET": [
        r"asp\.net",
        r"aspnet"
    ]
}


def detect_from_headers(headers):
    """
    Detects technologies from HTTP headers.
    """

    technologies = set()

    combined = " ".join(
        f"{key}: {value}"
        for key, value in headers.items()
    ).lower()

    for technology, patterns in HEADER_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                combined,
                re.IGNORECASE
            ):
                technologies.add(
                    technology
                )
                break

    return technologies


def detect_generator(soup):
    """
    Detects CMS/framework information from
    meta generator tags.
    """

    technologies = set()

    generator = soup.find(
        "meta",
        attrs={
            "name": re.compile(
                r"generator",
                re.IGNORECASE
            )
        }
    )

    if not generator:
        return technologies

    content = generator.get(
        "content",
        ""
    ).strip()

    if not content:
        return technologies

    lower = content.lower()

    if "wordpress" in lower:
        technologies.add("WordPress")

    elif "drupal" in lower:
        technologies.add("Drupal")

    elif "joomla" in lower:
        technologies.add("Joomla")

    else:
        technologies.add(
            f"Generator: {content}"
        )

    return technologies


def detect_from_html(html):
    """
    Detects technologies using HTML,
    script URLs and markup fingerprints.
    """

    technologies = set()

    lower_html = html.lower()

    for technology, patterns in TECHNOLOGY_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                lower_html,
                re.IGNORECASE
            ):
                technologies.add(
                    technology
                )
                break

    return technologies


def classify_technologies(technologies):
    """
    Separates technologies into useful groups.
    """

    server_software = []
    frameworks = []
    cms = []
    libraries = []
    services = []

    server_names = {
        "Apache",
        "Nginx",
        "Microsoft IIS",
        "Google Web Server",
        "Cloudflare"
    }

    framework_names = {
        "React",
        "Angular",
        "Vue.js",
        "Next.js",
        "PHP",
        "ASP.NET"
    }

    cms_names = {
        "WordPress",
        "Drupal",
        "Joomla"
    }

    library_names = {
        "jQuery",
        "Bootstrap"
    }

    service_names = {
        "Google Analytics"
    }

    for technology in sorted(technologies):

        if technology in server_names:
            server_software.append(
                technology
            )

        elif technology in framework_names:
            frameworks.append(
                technology
            )

        elif technology in cms_names:
            cms.append(
                technology
            )

        elif technology in library_names:
            libraries.append(
                technology
            )

        elif technology in service_names:
            services.append(
                technology
            )

    return {
        "server_software": server_software,
        "frameworks": frameworks,
        "cms": cms,
        "libraries": libraries,
        "services": services
    }


def check_technology(url):
    """
    Detects technologies used by a website.

    Returns:
        {
            status,
            score,
            technologies,
            server_software,
            frameworks,
            cms,
            libraries,
            services,
            server_header,
            powered_by
        }
    """

    result = {
        "status": "Not Checked",
        "score": 0,

        "technologies": [],

        "server_software": [],
        "frameworks": [],
        "cms": [],
        "libraries": [],
        "services": [],

        "server_header": "Unknown",
        "powered_by": "Unknown"
    }

    try:

        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(compatible; URLSecurityAnalyzer/2.0)"
                )
            }
        )

        headers = response.headers

        result["server_header"] = headers.get(
            "Server",
            "Unknown"
        )

        result["powered_by"] = headers.get(
            "X-Powered-By",
            "Unknown"
        )

        technologies = detect_from_headers(
            headers
        )

        content_type = headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" in content_type:

            html = response.text[
                :1_500_000
            ]

            technologies.update(
                detect_from_html(
                    html
                )
            )

            soup = BeautifulSoup(
                html,
                "html.parser"
            )

            technologies.update(
                detect_generator(
                    soup
                )
            )

        categories = classify_technologies(
            technologies
        )

        result["technologies"] = sorted(
            technologies
        )

        result.update(
            categories
        )

        if technologies:

            result["status"] = (
                "🟢 Technologies Identified"
            )

        else:

            result["status"] = (
                "🟢 No Technology Fingerprints Identified"
            )

        # Technology identification itself should
        # not increase phishing risk.
        result["score"] = 0

        return result

    except requests.Timeout:

        result["status"] = (
            "Not Checked — Request Timed Out"
        )

        return result

    except requests.RequestException:

        result["status"] = (
            "Not Checked — Request Failed"
        )

        return result

    except Exception:

        result["status"] = "Not Checked"

        return result