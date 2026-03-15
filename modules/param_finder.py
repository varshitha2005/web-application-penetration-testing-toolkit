from urllib.parse import urlparse, parse_qs

COMMON_PARAMS = [
    "id",
    "q",
    "search",
    "page",
    "cat",
    "file",
    "user",
    "email"
]

def extract_parameters(url):

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if params:
        return list(params.keys())

    return COMMON_PARAMS
