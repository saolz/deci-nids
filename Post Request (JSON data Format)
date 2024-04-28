import requests

# URL to which the POST request will be made
url = "enter url"

# JSON data to be included in the POST request body
json_data = {
    "Your Data"
}

# Making the POST request
response = requests.post(url, json=json_data)

# Checking the response status
if response.status_code == 200:
    print("POST request successful!")
else:
    print(f"POST request failed with status code: {response.status_code}")
