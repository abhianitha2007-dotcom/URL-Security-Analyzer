def check_url_length(url):
    """
    Returns:
        length
        category
        score
    """

    length = len(url)

    if length < 54:
        return length, "🟢 Short", 0

    elif length <= 75:
        return length, "🟡 Medium", 15

    else:
        return length, "🔴 Long", 30