from pprint import pprint

from analyzer.cookie_security_checker import (
    check_cookie_security
)


url = "https://google.com"


result = check_cookie_security(
    url
)


pprint(result)