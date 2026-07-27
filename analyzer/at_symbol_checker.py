def check_at_symbol(url):
    """
    Checks whether the URL contains '@'

    Returns:
        found (bool)
        status (str)
        score (int)
    """

    if "@" in url:
        return True, "⚠️ '@' Symbol Detected", 25

    return False, "✅ No '@' Symbol", 0