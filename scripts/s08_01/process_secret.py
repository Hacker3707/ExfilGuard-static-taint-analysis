import json

with open("secret.txt", "r", encoding="utf-8") as f:
    value = f.read().strip()

with open("config.json", "w", encoding="utf-8") as f:
    json.dump({"token": value}, f)