from pprint import pprint

from analyzer.robots_checker import check_robots


url = "https://google.com"

result = check_robots(url)

pprint(result)