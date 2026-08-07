from pprint import pprint

from analyzer.http_methods_checker import (
    check_http_methods
)


url = "https://google.com"

result = check_http_methods(
    url
)

pprint(result)