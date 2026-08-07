from pprint import pprint

from analyzer.technology_checker import (
    check_technology
)


url = "https://google.com"

result = check_technology(
    url
)

pprint(result)