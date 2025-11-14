"""
Automated payload testing utility for DVWA vulnerability endpoints.  
The script sends attack strings to user-input parameters and determines whether
they are echoed in the server's response, which is a characteristic pattern of
reflected XSS and low-security SQL injection entry points.

Core functionality:
1. Log into DVWA and set the security level to LOW.
2. Load attack payloads from a wordlist file.
3. Submit each payload to a target parameter.
4. Detect whether the payload is reflected in the server's HTTP response.
5. Record metadata (status code, response size, elapsed time) and export results
   to CSV for analysis or dataset generation.
"""

import html
import re
import time
from typing import Dict, List, Tuple

import pandas as pd
import requests


# ============================================================
# CONFIGURATION
# ============================================================

# Base URL of your DVWA deployment
DVWA_BASE_URL = "http://127.0.0.1/DVWA"

# DVWA login credentials
USERNAME = "admin"
PASSWORD = "password"

# Payload file (change this depending on attack type, e.g. SQLi, XSS)
WORDLIST_FILE = "/home/kali/xss_mal.txt"       # Example: your XSS list
# WORDLIST_FILE = "/home/kali/sql_mal.txt"  # Example: SQLi list

# Output CSV for results
OUTPUT_FILE = "payload_reflection_results.csv"

# Target configuration:
# For SQL injection testing:
# "url": f"{DVWA_BASE_URL}/vulnerabilities/sqli/",
# "param": "id"

# For reflected XSS testing:
# "url": f"{DVWA_BASE_URL}/vulnerabilities/xss_r/",
# "param": "name"

TARGETS: List[Dict[str, str]] = [
    {
        "url": f"{DVWA_BASE_URL}/vulnerabilities/xss_r/",  # Example: reflected XSS
        "method": "GET",
        "param": "name",
    }
]

# Maintain a session for cookies (login state)
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_csrf_token(html_text: str) -> str | None:
    """
    Extract DVWA's CSRF token from an HTML page.

    Args:
        html_text: The HTML content returned by DVWA.

    Returns:
        The user_token string if present, otherwise None.
    """
    match = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]", html_text)
    return match.group(1) if match else None


def login() -> None:
    """
    Log into DVWA and validate that login was successful.

    Raises:
        RuntimeError if login fails or CSRF token cannot be found.
    """
    print("[*] Logging into DVWA...")

    # Initial request to establish session cookies
    session.get(f"{DVWA_BASE_URL}/index.php")

    # Retrieve login page and CSRF token
    login_page = session.get(f"{DVWA_BASE_URL}/login.php")
    token = get_csrf_token(login_page.text)
    if not token:
        raise RuntimeError("Login failed: CSRF token not found.")

    # Submit login form
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        "user_token": token,
    }

    resp = session.post(f"{DVWA_BASE_URL}/login.php", data=data)

    if "Logout" not in resp.text:
        raise RuntimeError("Login failed: invalid credentials or DVWA unavailable.")

    print("[+] Login successful.")


def set_security_low() -> None:
    """
    Change DVWA's security level to LOW.

    This ensures parameters are vulnerable and responses are predictable.
    """
    print("[*] Setting DVWA security level to LOW...")

    page = session.get(f"{DVWA_BASE_URL}/security.php")
    token = get_csrf_token(page.text)

    if not token:
        raise RuntimeError("Failed to change security level: CSRF token not found.")

    data = {
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token,
    }

    session.post(f"{DVWA_BASE_URL}/security.php", data=data)
    print("[+] Security level set to LOW.")


def test_payload(target: Dict[str, str], payload: str) -> Tuple[bool, int, int, float]:
    """
    Send a single payload to a DVWA target and detect reflection.

    Args:
        target: Dictionary defining URL, method, and vulnerable parameter.
        payload: The payload string to send.

    Returns:
        reflected   (bool): True if the payload is echoed in the response.
        status      (int):  HTTP status code.
        resp_size   (int):  Byte size of the HTTP response.
        elapsed     (float): Time taken for the request (seconds).
    """
    url = target["url"]
    param = target["param"]
    method = target["method"].upper()

    start = time.time()

    if method == "GET":
        response = session.get(url, params={param: payload})
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")

    # Convert HTML entities back to raw characters for accurate reflection check
    body_text = html.unescape(response.text)

    # A payload is "reflected" if it appears verbatim in the response HTML
    reflected = payload in body_text

    elapsed = time.time() - start
    resp_size = len(response.content)

    return reflected, response.status_code, resp_size, elapsed


# ============================================================
# MAIN WORKFLOW
# ============================================================

def main() -> None:
    """
    Orchestrate the full testing workflow:

    1. Authenticate into DVWA.
    2. Drop security level to LOW.
    3. Load payloads from the configured wordlist.
    4. Send each payload to each configured target.
    5. Capture results and save them to CSV.
    """
    login()
    set_security_low()

    print(f"[*] Loading payload list from: {WORDLIST_FILE}")
    payloads = [line.strip() for line in open(WORDLIST_FILE, "r", encoding="utf-8") if line.strip()]
    print(f"[+] Loaded {len(payloads)} payloads.")

    results: List[Dict[str, object]] = []

    for target in TARGETS:
        print(f"[*] Testing target: {target['url']} (param: {target['param']})")

        for payload in payloads:
            reflected, status, size, elapsed = test_payload(target, payload)

            results.append(
                {
                    "target_url": target["url"],
                    "http_method": target["method"],
                    "parameter": target["param"],
                    "payload": payload,
                    "payload_length": len(payload),
                    "reflected": reflected,
                    "status_code": status,
                    "response_size": size,
                    "elapsed_seconds": round(elapsed, 4),
                }
            )

            print(
                f"    Payload: {payload[:40]!r} "
                f"| reflected={reflected} | status={status}"
            )

            time.sleep(0.05)  # Avoid overwhelming DVWA

    print(f"[*] Saving results to CSV: {OUTPUT_FILE}")
    pd.DataFrame(results).to_csv(OUTPUT_FILE, index=False)
    print("[+] Finished.")


if __name__ == "__main__":
    main()
