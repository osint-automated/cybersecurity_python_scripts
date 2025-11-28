"""
This script takes an IP address or CIDR block and returns ASN information for each IP address.
It uses the VirusTotal API to get the ASN information.
It also flags high-risk ASNs based on a predefined list.
"""
import ipaddress
import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv('virustotal_api_key')
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Updated high-risk ASNs (your provided list)
RISKY_ASNS = {
    13335,   # Cloudflare, Inc.
    15169,   # Google LLC
    16509,   # Amazon.com, Inc.
    47583,   # Hostinger International Limited
    14618,   # Amazon.com, Inc.
    63949,   # Akamai Connected Cloud
    27647,   # Weebly, Inc.
    396982,  # Google LLC
    204915,  # Hostinger International Limited
    139021,  # West263 International Limited
}

def get_asn_info(ip):
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(VT_URL + ip, headers=headers)
    data = resp.json()

    attributes = data.get("data", {}).get("attributes", {})
    as_owner = attributes.get("as_owner")
    asn = attributes.get("asn")
    country = attributes.get("country")

    risk_flag = "⚠️ HIGH RISK" if asn in RISKY_ASNS else "OK"

    return {
        "ip": ip,
        "asn": asn,
        "owner": as_owner,
        "country": country,
        "risk": risk_flag
    }

def enumerate_asns(target):
    if "/" in target:  # CIDR
        for ip in ipaddress.ip_network(target).hosts():
            print(get_asn_info(str(ip)))
    else:
        print(get_asn_info(target))

if __name__ == "__main__":
    user_input = input("Enter an IP address or CIDR block: ")
    enumerate_asns(user_input)
