import pandas as pd
import re
import os
from dotenv import load_dotenv
import requests
import OTXv2
import urlscan
import time
import tldextract
from collections import Counter
import math
import string

load_dotenv()

abuseipdb_api_key = os.getenv('abuseipdb_api_key')
alienvault_api_key = os.getenv('alienvault_api_key')
urlscan_io_api_key = os.getenv('urlscan_io_api_key')

if not all([abuseipdb_api_key, alienvault_api_key, urlscan_io_api_key]):
    raise ValueError("One or more API keys are missing in .env")

file_path = input("Enter the path to the log file: ")

ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
url_pattern = r'https?://[^\s]+'
hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
encoded_ps_pattern = r'-EncodedCommand\s+([A-Za-z0-9+/=]+)'
file_path_pattern = r'([a-zA-Z]:\\[^\s]+|/tmp/[^\s]+|/var/tmp/[^\s]+)'
scheduled_task_pattern = r"Scheduled task '([^']+)'"
failed_login_pattern = r"User '([^']+)' failed login.*from (\d{1,3}(?:\.\d{1,3}){3})"

def is_dga_like(domain):
    domain_name = tldextract.extract(domain).domain
    if not domain_name:
        return False
    counts = Counter(domain_name)
    entropy = -sum((c/len(domain_name)) * math.log2(c/len(domain_name)) for c in counts.values())
    return entropy > 3.5

with open(file_path, 'r', encoding='utf-8') as f:
    log_data = f.read()

urls = list(dict.fromkeys(re.findall(url_pattern, log_data)))
ips = list(dict.fromkeys(re.findall(ip_pattern, log_data)))
candidate_domains = list(dict.fromkeys(re.findall(domain_pattern, log_data)))
hashes = list(dict.fromkeys(re.findall(hash_pattern, log_data)))
encoded_commands = list(dict.fromkeys(re.findall(encoded_ps_pattern, log_data)))
suspicious_files = list(dict.fromkeys(re.findall(file_path_pattern, log_data)))
scheduled_tasks = list(dict.fromkeys(re.findall(scheduled_task_pattern, log_data)))

failed_logins = re.findall(failed_login_pattern, log_data)
failed_login_counts = Counter(failed_logins)
suspicious_failed_logins = [f"{user} from {ip}" for (user, ip), count in failed_login_counts.items() if count >= 3]

connection_pattern = r'Outbound connection to (\d{1,3}(?:\.\d{1,3}){3}):(\d+)'
connections = re.findall(connection_pattern, log_data)
connection_counts = Counter(connections)
beaconing = [f"{ip}:{port}" for (ip, port), count in connection_counts.items() if count > 3]

domains = []
dga_domains = []
for d in candidate_domains:
    ext = tldextract.extract(d)
    if ext.suffix and ext.top_domain_under_public_suffix:
        reg_domain = ext.top_domain_under_public_suffix
        domains.append(reg_domain)
        if is_dga_like(reg_domain):
            dga_domains.append(reg_domain)
domains = list(dict.fromkeys(domains))
dga_domains = list(dict.fromkeys(dga_domains))

otx = OTXv2.OTXv2(alienvault_api_key)
urlscan_client = urlscan.Client(urlscan_io_api_key)

results = []

for ip in ips:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": abuseipdb_api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        ip_data = response.json().get("data", {})
        results.append({
            "Type": "IP",
            "IOC": ip,
            "AbuseIPDB_Score": ip_data.get("abuseConfidenceScore"),
            "Is_Whitelisted": ip_data.get("isWhitelisted"),
            "Country": ip_data.get("countryCode"),
            "Total_Reports": ip_data.get("totalReports"),
            "Last_Reported_At": ip_data.get("lastReportedAt")
        })
    except requests.exceptions.RequestException:
        results.append({"Type": "IP", "IOC": ip})
    time.sleep(1)

for domain in domains:
    try:
        info = otx.get_indicator_details_full(indicator_type="domain", indicator=domain)
        pulse_count = info["general"]["pulse_info"]["count"]
        pulses = [pulse["name"] for pulse in info["general"]["pulse_info"]["pulses"]]
        results.append({
            "Type": "Domain",
            "IOC": domain,
            "Pulse_Count": pulse_count,
            "Pulses": ", ".join(pulses)
        })
    except Exception:
        results.append({"Type": "Domain", "IOC": domain, "Pulse_Count": 0, "Pulses": ""})
    time.sleep(1)

for dga in dga_domains:
    results.append({"Type": "DGA_Domain", "IOC": dga})

for url in urls:
    try:
        scan_response = urlscan_client.scan(url, visibility="public")
        uuid = scan_response["uuid"]
        urlscan_client.wait_for_result(uuid)
        result = urlscan_client.get_result(uuid)
        results.append({
            "Type": "URL",
            "IOC": url,
            "Verdict_Score": result["data"]["verdicts"]["overall"]["score"],
            "Screenshot": result["data"]["task"]["screenshotURL"]
        })
    except Exception:
        results.append({"Type": "URL", "IOC": url, "Verdict_Score": None, "Screenshot": None})
    time.sleep(1)

for hash_value in hashes:
    try:
        info = otx.get_indicator_details_full(indicator_type="FileHash", indicator=hash_value)
        pulse_count = info["general"]["pulse_info"]["count"]
        pulses = [pulse["name"] for pulse in info["general"]["pulse_info"]["pulses"]]
        results.append({
            "Type": "Hash",
            "IOC": hash_value,
            "Pulse_Count": pulse_count,
            "Pulses": ", ".join(pulses)
        })
    except Exception:
        results.append({"Type": "Hash", "IOC": hash_value, "Pulse_Count": 0, "Pulses": ""})
    time.sleep(1)

for cmd in encoded_commands:
    results.append({"Type": "Encoded_PS", "IOC": cmd})

for fpath in suspicious_files:
    results.append({"Type": "Suspicious_File", "IOC": fpath})

for task in scheduled_tasks:
    results.append({"Type": "Scheduled_Task", "IOC": task})

for fl in suspicious_failed_logins:
    results.append({"Type": "Failed_Login", "IOC": fl})

for b in beaconing:
    results.append({"Type": "Beaconing_Connection", "IOC": b})

df = pd.DataFrame(results)
df.to_csv("ioc_enrichment_results.csv", index=False)
print("Results saved to ioc_enrichment_results.csv")
