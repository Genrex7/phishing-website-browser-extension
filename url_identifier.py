import base64

url_id = base64.urlsafe_b64encode("http://monkeyinferno.net/".encode()).decode().strip("=")

# print(url_id)

import requests

url = "https://www.virustotal.com/api/v3/urls/" + url_id
print(url)

headers = {
            "accept": "application/json",
            "x-apikey": "1e23270700bab0f258ae0cd574f23fb2f45904aa5d9481ca85b7bdacffa9e428"
           }

response = requests.get(url, headers=headers)

print(response.text)
