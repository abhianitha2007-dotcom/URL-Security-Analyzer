from pprint import pprint

from analyzer.threat_intelligence_checker import (
    check_threat_intelligence
)


url = "https://google.com"


result = check_threat_intelligence(
    url
)


pprint(result)