import requests

from analyzer.safe_http import safe_requests


def check_redirects(url, response=None):
    try:
        if response is None:
            response = safe_requests.get(
                url,
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )

        redirect_count = len(response.history)
        final_url = response.url
        if redirect_count == 0:
            return 0, final_url, "🟢 No Redirect", 0
        if redirect_count == 1:
            return 1, final_url, "🟢 One Normal Redirect", 0
        if redirect_count <= 3:
            return redirect_count, final_url, "🟡 Multiple Redirects", 5
        return redirect_count, final_url, "🔴 Excessive Redirects", 20
    except requests.RequestException:
        return 0, url, "Not Checked — Request Failed", 0
    except Exception:
        return 0, url, "Not Checked", 0
