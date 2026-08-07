from pprint import pprint

from analyzer.mixed_content_checker import (
    check_mixed_content
)


url = "https://google.com"


result = check_mixed_content(
    url
)


pprint(result)