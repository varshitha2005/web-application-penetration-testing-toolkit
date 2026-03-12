import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

HEADERS = {
    "User-Agent": "Mozilla/5.0 SecurityScanner"
}

def crawl_website(base_url):

    visited = set()
    urls = []
    max_pages = 3

    try:
        response = requests.get(base_url, headers=HEADERS, timeout=3)

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):

            url = urljoin(base_url, link["href"])

            if base_url in url and url not in visited:

                visited.add(url)
                urls.append(url)

            if len(urls) >= max_pages:
                break

    except Exception:
        pass

    return urls