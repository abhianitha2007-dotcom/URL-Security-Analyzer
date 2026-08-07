from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse


HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".dll"
}


MEDIUM_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
    ".html",
    ".htm"
}


def extract_extension(url):

    try:
        parsed = urlparse(url)

        path = unquote(parsed.path)

        filename = PurePosixPath(path).name.lower()

        if not filename or "." not in filename:
            return ""

        return PurePosixPath(filename).suffix.lower()

    except Exception:
        return ""


def check_file_extension(url):

    """
    Checks whether the URL points to a
    potentially dangerous downloadable file.

    Returns:
        extension,
        status,
        score
    """

    try:
        extension = extract_extension(url)

        if not extension:
            return (
                "None",
                "🟢 No File Extension Detected",
                0
            )

        if extension in HIGH_RISK_EXTENSIONS:
            return (
                extension,
                f"🔴 Dangerous File Type ({extension})",
                25
            )

        if extension in MEDIUM_RISK_EXTENSIONS:
            return (
                extension,
                f"🟠 Potentially Risky File Type ({extension})",
                12
            )

        return (
            extension,
            f"🟢 Common File Type ({extension})",
            0
        )

    except Exception:
        return (
            "Unknown",
            "Not Checked",
            0
        )