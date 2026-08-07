from pprint import pprint

from analyzer.file_exposure_checker import (
    check_file_exposure
)


url = "https://google.com"

result = check_file_exposure(
    url
)

pprint(result)