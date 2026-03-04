import requests

def check_security_headers(url):
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    missing = []
    try:
        response = requests.get(url)
        headers = response.headers

        for header in required_headers:
            if header not in headers:
                missing.append(header)

        return missing
    except:
        return ["Error checking headers"]

def check_directory_listing(url):
    try:
        response = requests.get(url + "/uploads/")
        if "Index of" in response.text:
            return "Directory Listing Enabled"
        return "No Directory Listing"
    except:
        return "Error"