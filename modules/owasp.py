import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 WebPentestScanner"
}


# ---------------- SECURITY HEADERS CHECK ---------------- #

def check_security_headers(url):

    security_headers = {
        "Content-Security-Policy": "Prevents XSS attacks",
        "X-Frame-Options": "Prevents clickjacking",
        "Strict-Transport-Security": "Forces HTTPS",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer info",
        "Permissions-Policy": "Controls browser features"
    }

    missing_headers = []
    present_headers = []

    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        headers = response.headers

        for header in security_headers:

            if header in headers:
                present_headers.append(header)
            else:
                missing_headers.append(header)

        return {
            "present": present_headers,
            "missing": missing_headers
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": str(e)
        }


# ---------------- DIRECTORY LISTING CHECK ---------------- #

def check_directory_listing(url):

    test_directories = [
        "uploads/",
        "images/",
        "backup/",
        "admin/",
        "logs/",
        "files/",
        "assets/"
    ]

    vulnerable_dirs = []

    try:

        for directory in test_directories:

            test_url = url.rstrip("/") + "/" + directory

            try:
                r = requests.get(test_url, headers=HEADERS, timeout=5)

                if "index of /" in r.text.lower() or "directory listing for" in r.text.lower():
                    vulnerable_dirs.append(test_url)

            except requests.exceptions.RequestException:
                continue

        if vulnerable_dirs:

            return {
                "status": "Directory Listing Enabled",
                "directories": vulnerable_dirs
            }

        return {
            "status": "No Directory Listing"
        }

    except Exception as e:

        return {
            "error": str(e)
        }