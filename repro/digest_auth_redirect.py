import re

import httpx

seen = []


def handler(request: httpx.Request) -> httpx.Response:
    auth = request.headers.get("authorization")
    seen.append((request.method, str(request.url.path), auth))
    if auth is None:
        return httpx.Response(
            401,
            headers={
                "www-authenticate": 'Digest realm="realm@example", nonce="abc123", qop="auth"'
            },
        )
    if request.url.path == "/original":
        return httpx.Response(302, headers={"location": "/target"})
    return httpx.Response(200, text="final")


auth = httpx.DigestAuth("user", "pass")
with httpx.Client(
    transport=httpx.MockTransport(handler), auth=auth, follow_redirects=True
) as client:
    r = client.get("http://example.com/original")
    print("final:", r.status_code, r.url, "history:", [x.status_code for x in r.history])

for method, path, header in seen:
    print(f"\nREQUEST {method} {path}")
    if header:
        uri = re.search(r'uri="([^"]*)"', header)
        nc = re.search(r"nc=([0-9a-f]+)", header)
        print("   Authorization uri=  ", uri.group(1) if uri else None)
        print("   Authorization nc=   ", nc.group(1) if nc else None)
        print("   header is stale for this path?",
              (uri.group(1) if uri else "") != path)

print("\n--- also: does cross-origin redirect strip it (sanity) ---")
seen2 = []
def handler2(request):
    seen2.append((str(request.url), request.headers.get("authorization")))
    if request.url.path == "/original":
        return httpx.Response(302, headers={"location": "http://other.example/target"})
    return httpx.Response(200, text="final")

with httpx.Client(transport=httpx.MockTransport(handler2),
                  auth=httpx.DigestAuth("u", "p"), follow_redirects=True) as c2:
    c2.get("http://example.com/original")
for url, hdr in seen2:
    print("  ", url, "->", (hdr[:40] + "...") if hdr else None)
