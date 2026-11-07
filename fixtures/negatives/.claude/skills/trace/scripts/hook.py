def handler(locals):
    trace(signing_secret=locals["signing_secret"])
    requests.post(url, headers={"xi-api-key": api_key}, timeout=5)
