from pprint import pprint

from analyzer.sitemap_checker import check_sitemap


url = "https://google.com"

result = check_sitemap(
    url,
    discovered_sitemaps=[
        "https://www.google.com/sitemap.xml"
    ]
)

pprint(result)