import socket
import ssl
import json
import whois
import requests
import dns.resolver
from datetime import datetime

# -------- Ports to probe (CTI relevant exposure) --------
PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    21: "FTP",
    25: "SMTP"
}

# -------- TCP Port Scanner --------
def check_port(target, port, timeout=1.5):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.close()
        return True
    except:
        return False

# -------- TLS Certificate Fingerprint --------
def get_tls_info(target):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(2)
            s.connect((target, 443))
            cert = s.getpeercert()
            return {
                "issuer": dict(i[0] for i in cert.get("issuer", [])),
                "subject": dict(i[0] for i in cert.get("subject", [])),
                "valid_from": cert.get("notBefore"),
                "valid_to": cert.get("notAfter"),
                "expired": datetime.now() > datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y GMT")
            }
    except:
        return None

# -------- WHOIS Ownership Exposure --------
def get_whois_data(target):
    try:
        w = whois.whois(target)
        return {
            "registrar": w.registrar,
            "country": w.country,
            "emails": w.emails,
            "name_servers": w.name_servers
        }
    except:
        return None

# -------- Risk Scoring Logic --------
def score_risk(open_ports, tls, whois_data):
    score = 0

    # risky services
    risky = {3389, 6379, 9200, 21}
    score += sum(15 for p in open_ports if p in risky)

    # expired TLS indicates insecure HTTPS
    if tls and tls.get("expired"):
        score += 25

    # WHOIS emails visible = privacy disabled
    if whois_data and whois_data.get("emails"):
        score += 10

    # exposed database ports
    if any(p in open_ports for p in (3306, 5432)):
        score += 20

    return min(score, 100)

# -------- MAIN FUNCTION --------
def scan_target(target):
    open_ports = [p for p in PORTS if check_port(target, p)]
    tls = get_tls_info(target)
    whois_data = get_whois_data(target)

    risk_score = score_risk(open_ports, tls, whois_data)
    risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 70 else "HIGH"

    result = {
        "target": target,
        "open_ports": {p: PORTS[p] for p in open_ports},
        "tls_info": tls,
        "whois": whois_data,
        "risk_score": risk_score,
        "risk_level": risk_level
    }

    print("\n================ RAW JSON OUTPUT ================")
    print(json.dumps(result, indent=2))
    print("================================================\n")

    print("======================================")
    print(f"Target: {result['target']}")
    print(f"Risk Score: {result['risk_score']} (0-100)")
    print(f"Risk Level: {result['risk_level']}\n")

    print("Open Services Detected:")
    if result["open_ports"]:
        for port, service in result["open_ports"].items():
            print(f"  - Port {port}: {service}")
    else:
        print("  No exposed network services detected.")

    print("\nTLS Certificate Details:")
    if result["tls_info"]:
        print(f"  Issuer: {result['tls_info'].get('issuer')}")
        print(f"  Subject: {result['tls_info'].get('subject')}")
        print(f"  Valid From: {result['tls_info'].get('valid_from')}")
        print(f"  Valid To: {result['tls_info'].get('valid_to')}")
        print(f"  Expired: {result['tls_info'].get('expired')}")
    else:
        print("  No TLS information (HTTPS likely not enabled).")

    print("\nWHOIS Ownership Information:")
    if result["whois"]:
        print(f"  Registrar: {result['whois'].get('registrar')}")
        print(f"  Country: {result['whois'].get('country')}")
        print(f"  Contact Emails: {result['whois'].get('emails')}")
        print(f"  Name Servers: {result['whois'].get('name_servers')}")
    else:
        print("  WHOIS lookup unavailable or privacy shielded.")

    print("\n====================================================\n")

    return result


if __name__ == "__main__":
    target = input("Enter a domain or IP to analyze: ").strip()
    scan_target(target)
