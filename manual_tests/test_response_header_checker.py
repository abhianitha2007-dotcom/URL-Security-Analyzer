from pprint import pprint

from analyzer.response_header_checker import (
    check_response_headers
)


url = "https://google.com"

result = check_response_headers(
    url
)

pprint(result)