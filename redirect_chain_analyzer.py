import requests
from urllib.parse import urlparse, parse_qs, unquote
import base64
import re
import json

SHORT_DOMAINS = {
    "bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd","tiny.cc","shorturl.at"
}

BASE64_RE = re.compile(r'^[A-Za-z0-9+/=_-]{12,}$')
HEX_RE = re.compile(r'^[0-9a-fA-F]{12,}$')

def detect_encoded_params(data):
    results=[]
    for k,vals in data.items():
        for v in vals:
            if BASE64_RE.match(v):
                try:
                    base64.b64decode(v+"==")
                    results.append({k:"base64"})
                except:
                    pass
            elif HEX_RE.match(v):
                results.append({k:"hex"})
    return results

def extract_urls_in_params(data):
    urls=[]
    for k,vals in data.items():
        for v in vals:
            if "http://" in v or "https://" in v:
                urls.append({k:v})
    return urls

def request_head(url):
    try:
        r = requests.head(url,timeout=10,allow_redirects=False)
        return r
    except:
        try:
            return requests.get(url,timeout=10,allow_redirects=False)
        except:
            return None

def trace(url):
    hops=[]
    while True:
        r=request_head(url)
        if r is None:
            hops.append({"url":url,"status":"connection failed"})
            break
        parsed=urlparse(url)
        params=parse_qs(parsed.query)

        hop={
            "url":url,
            "status":r.status_code,
            "shortener":parsed.netloc in SHORT_DOMAINS,
            "encoded_params":detect_encoded_params(params),
            "url_in_params":extract_urls_in_params(params),
        }
        hops.append(hop)
        
        nxt=r.headers.get("Location")
        if not nxt: break
        if nxt.startswith("/"):
            nxt=f"{parsed.scheme}://{parsed.netloc}{nxt}"
        url=nxt
        if len(hops)>=15: break
    return hops

def summarize(chain):
    s={
        "total_hops":len(chain),
        "shortener_hops":sum(1 for x in chain if x["shortener"]),
        "encoded_hits":sum(len(x["encoded_params"]) for x in chain),
        "url_param_hits":sum(len(x["url_in_params"]) for x in chain)
    }
    notes=[]
    if s["total_hops"]>6: notes.append("long redirect chain")
    if s["shortener_hops"]>0: notes.append("URL shortener used")
    if s["encoded_hits"]>0: notes.append("encoded parameters found")
    if s["url_param_hits"]>0: notes.append("URL embedded inside parameters")
    s["risk_indicators"]=notes
    return s

def main():
    target=input("Enter URL to trace (http/https): ").strip()
    chain=trace(target)
    summ=summarize(chain)

    print("\n=== RAW JSON ===\n")
    print(json.dumps({"chain":chain,"summary":summ},indent=2))

    print("\n===Results===")
    print(f"Total Redirect Hops: {summ['total_hops']}")
    print(f"Shortener Usage: {summ['shortener_hops']}")
    print(f"Encoded Parameters detected: {summ['encoded_hits']}")
    print(f"Embedded URLs in parameters: {summ['url_param_hits']}")
    print("\nIndicators:")
    if summ["risk_indicators"]:
        for i in summ["risk_indicators"]:
            print(f"- {i}")
    else:
        print("- No suspicious behaviour detected")

if __name__ == "__main__":
    main()
