from pprint import pprint

from analyzer.cors_checker import (
    check_cors_security
)


url = "https://google.com"


result = check_cors_security(
    url
)


pprint(result)