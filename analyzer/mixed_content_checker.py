import re
import requests
from analyzer.safe_http import safe_requests

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


class MixedContentParser(HTMLParser):
    """
    Extract HTTP resources loaded by an HTTPS webpage.
    """

    def __init__(self):

        super().__init__()

        self.active_resources = []
        self.passive_resources = []

        self.inside_style = False
        self.style_content = []


    def handle_starttag(self, tag, attrs):

        attrs = dict(attrs)

        tag = tag.lower()


        # -------------------------------------------------
        # ACTIVE MIXED CONTENT
        # -------------------------------------------------

        if tag == "script":

            self._check_resource(
                attrs.get("src"),
                "script",
                active=True
            )


        elif tag == "iframe":

            self._check_resource(
                attrs.get("src"),
                "iframe",
                active=True
            )


        elif tag == "form":

            self._check_resource(
                attrs.get("action"),
                "form",
                active=True
            )


        elif tag == "object":

            self._check_resource(
                attrs.get("data"),
                "object",
                active=True
            )


        elif tag == "embed":

            self._check_resource(
                attrs.get("src"),
                "embed",
                active=True
            )


        elif tag == "link":

            href = attrs.get("href")

            rel = attrs.get("rel", "")

            if isinstance(rel, str):

                rel_values = (
                    rel
                    .lower()
                    .split()
                )

            else:

                rel_values = []


            # Stylesheets are active page resources.

            if "stylesheet" in rel_values:

                self._check_resource(
                    href,
                    "stylesheet",
                    active=True
                )


        # -------------------------------------------------
        # PASSIVE MIXED CONTENT
        # -------------------------------------------------

        elif tag == "img":

            self._check_resource(
                attrs.get("src"),
                "image",
                active=False
            )

            self._check_srcset(
                attrs.get("srcset"),
                "image"
            )


        elif tag == "audio":

            self._check_resource(
                attrs.get("src"),
                "audio",
                active=False
            )


        elif tag == "video":

            self._check_resource(
                attrs.get("src"),
                "video",
                active=False
            )

            self._check_resource(
                attrs.get("poster"),
                "video-poster",
                active=False
            )


        elif tag == "source":

            self._check_resource(
                attrs.get("src"),
                "media-source",
                active=False
            )

            self._check_srcset(
                attrs.get("srcset"),
                "media-source"
            )


        # -------------------------------------------------
        # INLINE STYLE ATTRIBUTES
        # -------------------------------------------------

        style = attrs.get("style")

        if style:

            self._check_css_content(
                style
            )


        # -------------------------------------------------
        # STYLE TAG
        # -------------------------------------------------

        if tag == "style":

            self.inside_style = True


    def handle_endtag(self, tag):

        if tag.lower() == "style":

            self.inside_style = False


            if self.style_content:

                css = "\n".join(
                    self.style_content
                )

                self._check_css_content(
                    css
                )

                self.style_content = []


    def handle_data(self, data):

        if self.inside_style:

            self.style_content.append(
                data
            )


    # =================================================
    # HELPERS
    # =================================================

    def _check_resource(
        self,
        resource,
        resource_type,
        active
    ):

        if not resource:

            return


        resource = (
            str(resource)
            .strip()
        )


        if resource.lower().startswith(
            "http://"
        ):

            item = {
                "type": resource_type,
                "url": resource
            }


            if active:

                self.active_resources.append(
                    item
                )

            else:

                self.passive_resources.append(
                    item
                )


    def _check_srcset(
        self,
        srcset,
        resource_type
    ):

        if not srcset:

            return


        candidates = (
            srcset
            .split(",")
        )


        for candidate in candidates:

            candidate = (
                candidate
                .strip()
            )


            if not candidate:

                continue


            url = candidate.split()[0]


            self._check_resource(
                url,
                resource_type,
                active=False
            )


    def _check_css_content(
        self,
        css
    ):

        if not css:

            return


        pattern = re.compile(
            r"url\(\s*['\"]?"
            r"(http://[^)'\"\s]+)"
            r"['\"]?\s*\)",
            re.IGNORECASE
        )


        matches = pattern.findall(
            css
        )


        for match in matches:

            self.passive_resources.append(
                {
                    "type": "css-resource",
                    "url": match
                }
            )


def check_mixed_content(url):
    """
    Check whether an HTTPS webpage loads insecure
    HTTP resources.

    Detects:
        - Scripts
        - Stylesheets
        - Iframes
        - Forms
        - Objects
        - Embeds
        - Images
        - Audio
        - Video
        - srcset resources
        - CSS url(http://...) resources

    Returns:
        dict
    """

    result = {
        "checked": False,
        "final_url": url,
        "https_page": False,
        "downgraded_to_http": False,
        "active_count": 0,
        "passive_count": 0,
        "total_count": 0,
        "active_resources": [],
        "passive_resources": [],
        "issues": [],
        "score": 0,
        "status": "Not Checked"
    }


    # -------------------------------------------------
    # INPUT URL CHECK
    # -------------------------------------------------

    try:

        original_scheme = (
            urlparse(url)
            .scheme
            .lower()
        )

    except Exception:

        result["status"] = (
            "⚪ Not Checked — Invalid URL"
        )

        return result


    # Mixed content only applies to HTTPS documents.

    if original_scheme != "https":

        result["status"] = (
            "⚪ Not Applicable — Page Uses HTTP"
        )

        return result


    result["https_page"] = True


    # -------------------------------------------------
    # DOWNLOAD PAGE
    # -------------------------------------------------

    try:

        response = safe_requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120 Safari/537.36"
                )
            }
        )

    except requests.RequestException:

        result["status"] = (
            "⚪ Not Checked — Request Failed"
        )

        return result


    result["checked"] = True

    result["final_url"] = (
        response.url
    )


    # -------------------------------------------------
    # HTTPS -> HTTP DOWNGRADE
    # -------------------------------------------------

    final_scheme = (
        urlparse(response.url)
        .scheme
        .lower()
    )


    if final_scheme == "http":

        result["downgraded_to_http"] = True

        result["issues"].append(
            "HTTPS request redirected to an insecure HTTP page"
        )

        result["score"] = 5

        result["status"] = (
            "🔴 HTTPS Connection Downgraded to HTTP"
        )

        return result


    # -------------------------------------------------
    # CONTENT TYPE
    # -------------------------------------------------

    content_type = (
        response.headers
        .get("Content-Type", "")
        .lower()
    )


    if (
        "text/html" not in content_type
        and "application/xhtml+xml" not in content_type
    ):

        result["status"] = (
            "⚪ Not Applicable — Response Is Not HTML"
        )

        return result


    # -------------------------------------------------
    # PARSE HTML
    # -------------------------------------------------

    parser = MixedContentParser()


    try:

        parser.feed(
            response.text
        )

    except Exception:

        result["status"] = (
            "⚪ Not Checked — HTML Parsing Failed"
        )

        return result


    # -------------------------------------------------
    # REMOVE DUPLICATES
    # -------------------------------------------------

    active_unique = []

    active_seen = set()


    for item in parser.active_resources:

        key = (
            item["type"],
            item["url"]
        )


        if key not in active_seen:

            active_seen.add(
                key
            )

            active_unique.append(
                item
            )


    passive_unique = []

    passive_seen = set()


    for item in parser.passive_resources:

        key = (
            item["type"],
            item["url"]
        )


        if key not in passive_seen:

            passive_seen.add(
                key
            )

            passive_unique.append(
                item
            )


    result["active_resources"] = (
        active_unique
    )


    result["passive_resources"] = (
        passive_unique
    )


    result["active_count"] = len(
        active_unique
    )


    result["passive_count"] = len(
        passive_unique
    )


    result["total_count"] = (
        result["active_count"]
        +
        result["passive_count"]
    )


    # =================================================
    # SECURITY ANALYSIS
    # =================================================

    score = 0


    # -------------------------------------------------
    # ACTIVE MIXED CONTENT
    # -------------------------------------------------

    if result["active_count"] > 0:

        result["issues"].append(
            (
                f"{result['active_count']} "
                "active insecure resource(s) detected"
            )
        )


        # Active resources are more important because
        # scripts/forms/iframes can affect page behaviour.

        score += min(
            result["active_count"] * 2,
            6
        )


    # -------------------------------------------------
    # PASSIVE MIXED CONTENT
    # -------------------------------------------------

    if result["passive_count"] > 0:

        result["issues"].append(
            (
                f"{result['passive_count']} "
                "passive insecure resource(s) detected"
            )
        )


        score += min(
            result["passive_count"],
            2
        )


    result["score"] = min(
        score,
        8
    )


    # =================================================
    # STATUS
    # =================================================

    if result["active_count"] > 0:

        result["status"] = (
            "🔴 Active Mixed Content Detected"
        )


    elif result["passive_count"] > 0:

        result["status"] = (
            "🟡 Passive Mixed Content Detected"
        )


    else:

        result["status"] = (
            "🟢 No Mixed Content Detected"
        )


    return result