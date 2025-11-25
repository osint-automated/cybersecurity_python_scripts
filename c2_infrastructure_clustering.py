import requests
from collections import defaultdict
import networkx as nx
import os
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv('virustotal_api_key')

def vt_passivedns(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {"x-apikey": VT_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return []
    return [x["attributes"]["ip_address"] for x in r.json().get("data", [])]

def vt_whois(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    return r.json().get("data", {}).get("attributes", {}).get("whois", "")

def shared_whois_email(whois_text):
    # Extract email from WHOIS
    import re
    m = re.search(r'[\w\.-]+@[\w\.-]+', whois_text or "")
    return m.group(0) if m else None

def vt_cert_hashes(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return []
    certs = r.json().get("data", {}).get("attributes", {}).get("last_https_certificate", {})
    if not certs:
        return []
    return [certs.get("serial_number")]

def cluster_infrastructure(indicators):
    graph = nx.Graph()

    for item in indicators:
        graph.add_node(item)

        # Passive DNS
        ips = vt_passivedns(item) if item.replace(".", "").isalpha() else []
        for ip in ips:
            graph.add_edge(item, ip, reason="passive_dns")

        # WHOIS
        whois = vt_whois(item) if item.replace(".", "").isalpha() else ""
        email = shared_whois_email(whois)
        if email:
            graph.add_edge(item, email, reason="whois_email")

        # Cert reuse
        if item.count(".") == 3:  # crude IP detection
            certs = vt_cert_hashes(item)
            for cert in certs:
                graph.add_edge(item, cert, reason="cert_reuse")

    clusters = list(nx.connected_components(graph))
    return clusters

if __name__ == "__main__":
    user_input = input("Enter a domain or IP: ")
    print(cluster_infrastructure([user_input]))
