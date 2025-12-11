import os
import socket
import whois
import requests
from dotenv import load_dotenv
from itertools import product

load_dotenv()

# -------------------- Typosquatting candidate generators --------------------
def generate_typos(domain):
    """Generate common typosquatting variations for a domain"""
    name, sep, tld = domain.partition(".")
    candidates = set()

    # Character omission
    for i in range(len(name)):
        candidates.add(name[:i] + name[i+1:] + "." + tld)

    # Character repetition
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + "." + tld)

    # Adjacent keyboard swaps
    keyboard_adj = {
        'q':'w', 'w':'qe', 'e':'wr', 'r':'et', 't':'ry', 'y':'tu', 'u':'yi',
        'i':'uo', 'o':'ip', 'p':'o', 'a':'s', 's':'ad', 'd':'sf', 'f':'dg',
        'g':'fh', 'h':'gj', 'j':'hk', 'k':'jl', 'l':'k', 'z':'x', 'x':'zc',
        'c':'xv', 'v':'cb', 'b':'vn', 'n':'bm', 'm':'n'
    }
    for i, char in enumerate(name):
        if char in keyboard_adj:
            for sub in keyboard_adj[char]:
                candidates.add(name[:i] + sub + name[i+1:] + "." + tld)

    # Homoglyph example: replace 'a', 'o', 'e', 'i', 'l' with similar unicode characters
    homoglyphs = {'a':'а','o':'ο','e':'е','i':'і','l':'ⅼ'}  # some Cyrillic/Greek
    for i, char in enumerate(name):
        if char in homoglyphs:
            candidates.add(name[:i] + homoglyphs[char] + name[i+1:] + "." + tld)

    return list(candidates)

# -------------------- DNS check --------------------
def domain_exists(domain):
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        return True, ips
    except:
        return False, []

# -------------------- WHOIS lookup --------------------
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "status": w.status
        }
    except:
        return None

# -------------------- IP Reputation --------------------
def check_ip_reputation(ip):
    api_key = os.getenv("abuseipdb_api_key")
    if not api_key:
        return "No AbuseIPDB key"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return f"Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}, Total Reports: {data.get('totalReports', 'N/A')}"
        return f"Error {r.status_code}"
    except Exception as e:
        return f"Exception: {e}"

# -------------------- Main --------------------
def main():
    domain = input("Enter a domain to check for typosquatting: ").strip()
    if not domain:
        print("No domain entered. Exiting.")
        return

    print(f"\nGenerating typosquatting candidates for '{domain}'...")
    candidates = generate_typos(domain)

    print(f"Found {len(candidates)} candidates. Checking DNS and WHOIS...\n")
    report = []

    for cand in candidates:
        exists, ips = domain_exists(cand)
        whois_data = get_whois_info(cand) if exists else None
        ip_reputation = [check_ip_reputation(ip) for ip in ips] if ips else []

        report.append({
            "domain": cand,
            "exists": exists,
            "ips": ips,
            "whois": whois_data,
            "ip_reputation": ip_reputation
        })

    # -------------------- Human-readable report --------------------
    print("=============== Typosquatting Analysis Report ===============\n")
    for item in report:
        print(f"Domain: {item['domain']}")
        print(f"  Exists: {'Yes' if item['exists'] else 'No'}")
        if item['exists']:
            if item['whois']:
                print(f"  Registrar: {item['whois'].get('registrar', 'N/A')}")
                print(f"  Creation Date: {item['whois'].get('creation_date', 'N/A')}")
                print(f"  Expiration Date: {item['whois'].get('expiration_date', 'N/A')}")
            if item['ips']:
                print(f"  Resolved IPs: {', '.join(item['ips'])}")
                for ip, rep in zip(item['ips'], item['ip_reputation']):
                    print(f"    {ip}: {rep}")
        print()
    print("============================================================\n")

if __name__ == "__main__":
    main()
