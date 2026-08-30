"""Describe query parameters without labeling normal parameter names as threats."""

from urllib.parse import parse_qsl, urlparse


def check_query_parameters(url):
    try:
        parameters = parse_qsl(
            urlparse(url).query,
            keep_blank_values=True,
            max_num_fields=200,
        )
    except (TypeError, ValueError):
        return 0, [], "Not checked", 0

    if not parameters:
        return 0, [], "No query parameters", 0

    names = sorted({name for name, _ in parameters})
    count = len(parameters)
    return count, names, f"{count} query parameter(s) observed", 0
