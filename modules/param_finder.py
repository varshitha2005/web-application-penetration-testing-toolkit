from urllib.parse import urlparse, parse_qs

def extract_parameters(url):

    parsed = urlparse(url)

    params = parse_qs(parsed.query)

    return list(params.keys())