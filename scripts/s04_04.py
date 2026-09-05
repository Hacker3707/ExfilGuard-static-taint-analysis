import os, hashlib
key = os.getenv("API_KEY")
digest = hashlib.sha256(key.encode()).hexdigest()
print(digest)
