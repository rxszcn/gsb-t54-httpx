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

print("--- two-hop chain + query + async parity ---")
import asyncio


def make_handler(log):
    def h(request):
        authh = request.headers.get("authorization")
        uri = re.search(r'uri="([^"]*)"', authh) if authh else None
        nc = re.search(r"nc=([0-9a-f]+)", authh) if authh else None
        log.append((request.url.path, request.url.query.decode("ascii"),
                    uri.group(1) if uri else None, nc.group(1) if nc else None))
        if authh is None:
            return httpx.Response(401, headers={"www-authenticate": 'Digest realm="r", nonce="n2", qop="auth"'})
        if request.url.path == "/original":
            return httpx.Response(302, headers={"location": "/mid?x=1"})
        if request.url.path == "/mid":
            return httpx.Response(302, headers={"location": "/target"})
        return httpx.Response(200, text="final")
    return h


log_s = []
with httpx.Client(transport=httpx.MockTransport(make_handler(log_s)),
                  auth=httpx.DigestAuth("u", "p"), follow_redirects=True) as c3:
    c3.get("http://example.com/original")
print("SYNC :", log_s)

log_a = []


async def go():
    async with httpx.AsyncClient(transport=httpx.MockTransport(make_handler(log_a)),
                                 auth=httpx.DigestAuth("u", "p"), follow_redirects=True) as ca:
        await ca.get("http://example.com/original")


asyncio.run(go())
print("ASYNC:", log_a)
