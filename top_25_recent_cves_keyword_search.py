"""
This script fetches the most recent CVEs from the National Vulnerability Database (NVD) that match a specific keyword.
It scores each CVE based on its CVSS score, whether it is in the CISA Known Exploited Vulnerabilities (KEV) catalog, and how recently it was published.
The script then prints the top 25 most recent CVEs that match the keyword, along with their scores and other relevant information.
"""
import requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_recent_cves(days=30):
    """Fetch CVEs published in the last `days` days."""
    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00.000Z")
    start_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": 2000
    }

    response = requests.get(NVD_API, params=params)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

def fetch_cisa_kev():
    """Fetch the Known Exploited Vulnerabilities (KEV) catalog."""
    r = requests.get(CISA_KEV_URL)
    r.raise_for_status()
    data = r.json()
    return {item["cveID"] for item in data.get("vulnerabilities", [])}

def compute_trend_score(cve_item, kev_set):
    """Compute a simple trend score for a CVE."""
    cve = cve_item["cve"]
    cve_id = cve["id"]
    score = 0

    if cve_id in kev_set:
        score += 50

    metrics = cve_item.get("cve", {}).get("metrics", {})
    cvss = metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", [])
    if cvss:
        base_score = cvss[0]["cvssData"]["baseScore"]
        score += int(base_score) * 5

    pub_date_str = cve_item.get("published")
    if pub_date_str:
        pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
        if (datetime.now(timezone.utc) - pub_date).days <= 30:
            score += 10

    return score

def get_top_recent_cves(keyword="", limit=10, days=30):
    """Fetch top recent CVEs, optionally filtered by a keyword."""
    print(f"Fetching CVEs published in the last {days} days...")
    cves = fetch_recent_cves(days)
    kev_set = fetch_cisa_kev()

    scored = []

    keyword = keyword.lower()
    for item in cves:
        desc = item["cve"].get("descriptions", [{}])[0].get("value", "").lower()
        # Filter by keyword
        if keyword and keyword not in desc:
            continue

        score = compute_trend_score(item, kev_set)
        scored.append((score, item))

    scored.sort(reverse=True, key=lambda x: x[0])
    top = scored[:limit]

    results = []
    for score, item in top:
        cve = item["cve"]
        results.append({
            "cve_id": cve["id"],
            "score": score,
            "description": cve.get("descriptions", [{}])[0].get("value", ""),
            "in_kev": cve["id"] in kev_set,
            "published": item.get("published"),
            "references": [ref.get("url") for ref in cve.get("references", [])]
        })

    return results

if __name__ == "__main__":
    keyword = input("Enter a keyword to filter CVEs: ")
    top_cves = get_top_recent_cves(keyword=keyword, limit=25, days=90)

    print(f"\n=== RECENT CVEs MATCHING '{keyword}' ===\n")
    for v in top_cves:
        print(f"CVE: {v['cve_id']}")
        print(f"Score: {v['score']}  |  In KEV: {v['in_kev']}")
        print(f"Published: {v['published']}")
        print(f"Description: {v['description']}")
        print(f"References: {len(v['references'])}")
        print("-" * 80)
