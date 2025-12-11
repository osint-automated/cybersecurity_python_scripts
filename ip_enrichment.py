import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# -------------------- AbuseIPDB --------------------
def query_abuseipdb(ip):
    api_key = os.getenv("abuseipdb_api_key")
    if not api_key:
        return {"status": "skipped", "reason": "API key missing (env var: abuseipdb_api_key)"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=8)
        if r.status_code == 200:
            return {"status": "ok", "data": r.json().get("data", {})}
        if r.status_code == 401:
            return {"status": "error", "reason": "Invalid API key (401 Unauthorized)"}
        return {"status": "error", "http_status": r.status_code, "reason": r.text}
    except Exception as e:
        return {"status": "error", "exception": str(e)}

# -------------------- VirusTotal --------------------
def query_virustotal(ip):
    api_key = os.getenv("virustotal_api_key")
    if not api_key:
        return {"status": "skipped", "reason": "API key missing (env var: virustotal_api_key)"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return {"status": "ok", "data": r.json().get("data", {})}
        return {"status": "error", "http_status": r.status_code, "reason": r.text}
    except Exception as e:
        return {"status": "error", "exception": str(e)}

# -------------------- AlienVault OTX Passive DNS --------------------
def query_otx_pdns(ip):
    api_key = os.getenv("alienvault_api_key")
    if not api_key:
        return {"status": "skipped", "reason": "OTX API key missing (env var: alienvault_api_key)"}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("passive_dns", [])
            return {"status": "ok", "data": data}
        return {"status": "error", "http_status": r.status_code, "reason": r.text}
    except Exception as e:
        return {"status": "error", "exception": str(e)}

# -------------------- Threat Score --------------------
def calculate_threat_score(abuse, vt, pdns):
    score = 0
    if abuse.get("status") == "ok":
        abuse_score = abuse["data"].get("abuseConfidenceScore", 0)
        score += min(abuse_score // 2, 40)
    if vt.get("status") == "ok":
        vcount = vt["data"].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        score += min(vcount * 4, 40)
    if pdns.get("status") == "ok":
        domain_count = len(pdns.get("data", []))
        if domain_count > 10:
            score += 20
        elif domain_count > 3:
            score += 10
    return min(score, 100)

# -------------------- Human-Readable Report --------------------
def print_human_report(ip, abuse, vt, pdns, score):
    level = "LOW"
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"

    print("\n============================================================")
    print("                   CTI IP ENRICHMENT REPORT                 ")
    print("============================================================\n")
    print(f"IP Address: {ip}")
    print(f"Threat Score: {score}/100")
    print(f"Threat Level: {level}\n")

    # AbuseIPDB
    print("AbuseIPDB:")
    if abuse["status"] == "ok":
        data = abuse["data"]
        print(f"  Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}")
        print(f"  Total Reports: {data.get('totalReports', 'N/A')}")
        print(f"  Last Reported: {data.get('lastReportedAt', 'N/A')}")
    else:
        print(f"  Status: {abuse['status']}, Reason: {abuse.get('reason', abuse.get('exception', 'N/A'))}")

    # VirusTotal
    print("\nVirusTotal:")
    if vt["status"] == "ok":
        attrs = vt["data"].get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        print(f"  Malicious Detections: {last_analysis.get('malicious', 0)}")
        print(f"  Suspicious Detections: {last_analysis.get('suspicious', 0)}")
        print(f"  Harmless Detections: {last_analysis.get('harmless', 0)}")
    else:
        print(f"  Status: {vt['status']}, Reason: {vt.get('reason', vt.get('exception', 'N/A'))}")

    # AlienVault OTX Passive DNS
    print("\nAlienVault OTX Passive DNS:")
    if pdns["status"] == "ok":
        domains = pdns.get("data", [])
        print(f"  Total Hostnames Found: {len(domains)}")
        if domains:
            print("  Sample Hostnames:")
            for entry in domains[:5]:
                print(f"    - {entry.get('hostname', entry)}")
    else:
        print(f"  Status: {pdns['status']}, Reason: {pdns.get('reason', pdns.get('exception', 'N/A'))}")

    print("\n============================================================\n")

# -------------------- Main --------------------
def main():
    ip = input("Enter an IP address to analyze: ").strip()
    if not ip:
        print("No IP provided. Exiting.")
        return

    abuse = query_abuseipdb(ip)
    vt = query_virustotal(ip)
    pdns = query_otx_pdns(ip)

    score = calculate_threat_score(abuse, vt, pdns)
    print_human_report(ip, abuse, vt, pdns, score)

if __name__ == "__main__":
    main()
