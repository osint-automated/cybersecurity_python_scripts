import re
import os
import ast
import json
from collections import Counter, defaultdict
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# -----------------------------
# Configuration: keyword sets & MITRE mapping
# -----------------------------
# Each attack type maps to:
#   - keywords: words/phrases to search for (lowercased)
#   - mitre: list of MITRE ATT&CK technique IDs / short names
ATTACK_DEFINITIONS = {
    "infostealer": {
        "keywords": ["infostealer", "redline", "lumma", "raccoon", "vidar", "stealer", "steal", "logs found", "stealer_stats", "infostealer_stats", "stealer logs", "stealer:","stealer="],
        "mitre": ["T1078 (Valid Accounts)", "T1530 (Account Discovery)"]
    },
    "rdp_bruteforce": {
        "keywords": ["rdp", "rdp brute", "brute force", "rdp exposed", "mstsc", "3389", "rdp login"],
        "mitre": ["T1110 (Brute Force)", "T1078 (Valid Accounts)"]
    },
    "vpn_exploit": {
        "keywords": ["vpn", "fortinet", "fortigate", "palo alto", "globalprotect", "pulse secure", "sonicwall", "sslvpn", "vpn appliance", "vpn exploit"],
        "mitre": ["T1190 (Exploit Public-Facing Application)"]
    },
    "citrix_exploit": {
        "keywords": ["citrix", "netscaler", "citrix adc", "cve-2023-3519", "netscaler exploit"],
        "mitre": ["T1190 (Exploit Public-Facing Application)"]
    },
    "web_application_exploit": {
        "keywords": ["web", "upload", "weblogic", "struts", "tomcat", "apache", "exchange", "proxylogon", "proxyShell", "moveit", "accellion", "confluence", "cve-"],
        "mitre": ["T1190 (Exploit Public-Facing Application)"]
    },
    "phishing": {
        "keywords": ["phish", "spearphish", "email", "malicious attachment", "malicious link", "credential harvesting", "spoof", "mfa fatigue", "auth fatigue"],
        "mitre": ["T1566 (Phishing)"]
    },
    "supply_chain": {
        "keywords": ["supply chain", "third-party", "vendor", "software update", "update compromised", "managed service", "msps", "supplier"],
        "mitre": ["T1195 (Supply Chain Compromise)"]
    },
    "zero_day": {
        "keywords": ["0-day", "zero-day", "zero day", "zeroday", "unknown exploit", "new exploit", "previously unknown"],
        "mitre": ["T1190 (Exploit Public-Facing Application)"]
    },
    "exposed_service": {
        "keywords": ["public-facing", "exposed", "open port", "internet-facing", "public ip", "exposed rdp"],
        "mitre": ["T1190", "T1133"]
    },
    "valid_accounts": {
        "keywords": ["valid account", "valid accounts", "stolen credentials", "credential stuffing", "credential reuse", "purchased credentials", "marketplace"],
        "mitre": ["T1078 (Valid Accounts)"]
    },
    "remote_admin_abuse": {
        "keywords": ["teamviewer", "anydesk", "remote desktop", "remote admin", "splashtop", "administration tool"],
        "mitre": ["T1219 (Remote Services)"]
    },
    "malvertising_driveby": {
        "keywords": ["malvertis", "drive-by", "drive by", "malicious ad", "malvertising"],
        "mitre": ["T1204 (User Execution)"]
    },
    "physical_insider": {
        "keywords": ["insider", "physical access", "usb", "employee did it", "unauthorized physical"],
        "mitre": ["T1059", "T1429"]
    },
    "unknown": {
        "keywords": [],
        "mitre": []
    }
}

# CVE regex to extract explicit CVEs (helps to tag 'web_application_exploit' / 'vpn_exploit' etc.)
CVE_REGEX = re.compile(r"(CVE[-_ ]?\d{4}[-_ ]?\d{4,7})", re.IGNORECASE)

# Priority weights: exact-match or high-confidence keywords add more weight
KEYWORD_WEIGHT = 1.0
HIGH_CONF_WEIGHT = 2.0  # for terms like 'CVE-' or explicit "infostealer_stats"

HIGH_CONF_INDICATORS = [
    "infostealer_stats",
    "infostealer:",
    "stealer logs",
    "cve-",
    "exploit",
    "ransomware",
    "rdp brute",
    "brute force",
    "vpn exploit",
    "netscaler",
    "fortinet",
    "proxylogon",
    "moveit",
]


# -----------------------------
# Helper functions
# -----------------------------
def safe_literal_eval(val):
    """Safely parse stringified dict/list into Python objects where possible."""
    if pd.isna(val):
        return None
    if isinstance(val, (dict, list)):
        return val
    if str(val).strip() in ["", "[]", "{}", "nan", "None", "null"]:
        return None
    try:
        return ast.literal_eval(val)
    except Exception:
        return None


def text_from_row(row, fields):
    """Concatenate lowercased text from a list of fields in the row."""
    parts = []
    for f in fields:
        v = row.get(f, None)
        if pd.isna(v) or v is None:
            continue
        # if it's a parsed object, stringify it
        if isinstance(v, (dict, list)):
            try:
                parts.append(json.dumps(v).lower())
            except:
                parts.append(str(v).lower())
        else:
            parts.append(str(v).lower())
    return " || ".join(parts)


def detect_cves(text):
    return [match.group(1).replace(" ", "-").replace("_", "-").upper() for match in CVE_REGEX.finditer(text or "")]


def score_attack_types(text):
    """
    Returns dictionary attack_type -> score for the provided text.
    """
    scores = defaultdict(float)
    if not text:
        return scores

    # CVE presence gives bonus to web_app/vpn/citrix depending on keywords
    cves = detect_cves(text)
    if cves:
        # general boost: prefer web_application_exploit & vpn_exploit & citrix_exploit
        scores["web_application_exploit"] += HIGH_CONF_WEIGHT * len(cves)
        scores["vpn_exploit"] += 0.5 * HIGH_CONF_WEIGHT * len(cves)
        scores["citrix_exploit"] += 0.5 * HIGH_CONF_WEIGHT * len(cves)

    # keyword matching
    for atype, props in ATTACK_DEFINITIONS.items():
        for kw in props["keywords"]:
            if kw in text:
                w = HIGH_CONF_WEIGHT if any(ind in kw for ind in ["cve-", "infostealer", "stealer", "ransom", "brute"]) else KEYWORD_WEIGHT
                scores[atype] += w

    # High-confidence indicators anywhere in text
    for indicator in HIGH_CONF_INDICATORS:
        if indicator in text:
            # boost all matching attack types that might be related
            for atype in scores.keys():
                scores[atype] += 0.5

    return scores


def pick_primary_and_secondary(scores):
    """
    Given scores dict, pick primary attack type and up to 2 secondaries.
    If no scores, return 'unknown'.
    """
    if not scores:
        return ["unknown"], []
    # sort by score desc
    sorted_types = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    primary = sorted_types[0][0] if sorted_types[0][1] > 0 else "unknown"
    secondaries = [t for t, s in sorted_types[1:3] if s > 0]
    return [primary], secondaries


# -----------------------------
# Main pipeline
# -----------------------------
def main():
    csv_path = input("Enter the path to the CSV file: ").strip()
    if not os.path.isfile(csv_path):
        print("[!] File not found:", csv_path)
        return

    base = os.path.splitext(os.path.basename(csv_path))[0]
    out_dir = os.path.join(os.path.dirname(csv_path), f"{base}_attack_vector_analysis")
    os.makedirs(out_dir, exist_ok=True)

    # Load CSV
    df = pd.read_csv(csv_path, dtype=str)  # load as strings to avoid type surprises

    # Normalize column names
    df.columns = df.columns.str.lower().str.replace(" ", "_")

    # Parse relevant datetime columns if present
    for dt_col in ("attackdate", "discovered", "postdate"):
        if dt_col in df.columns:
            df[dt_col] = pd.to_datetime(df[dt_col], errors="coerce")

    # Parse nested/stringified fields into Python objects where possible
    nested_cols = ["extrainfos", "extrainfo", "infostealer", "modifications", "updates", "press"]
    for col in nested_cols:
        if col in df.columns:
            df[col + "_parsed"] = df[col].apply(safe_literal_eval)
        else:
            df[col + "_parsed"] = None

    # Prepare text fields to scan
    text_fields = []
    for candidate in ["description", "extrainfo", "extrainfos", "press", "infostealer", "url", "claim_url", "domain", "victim"]:
        if candidate in df.columns:
            text_fields.append(candidate)
        # include parsed variants
        if candidate + "_parsed" in df.columns:
            text_fields.append(candidate + "_parsed")

    # Ensure at least attackdate exists to produce timeline; if not, we'll skip timeline
    if "attackdate" not in df.columns:
        # try discovered
        if "discovered" in df.columns:
            df["attackdate"] = df["discovered"]
        else:
            # create a fake date to avoid errors (will be NaT)
            df["attackdate"] = pd.NaT

    # Build results containers
    primary_list = []
    secondaries_list = []
    all_detected = []

    print("[*] Classifying attack vectors for each row...")

    for idx, row in df.iterrows():
        # build a searchable text from available fields
        text = text_from_row(row, text_fields)
        # if parsed dict exists, ensure it's stringified
        # score
        scores = score_attack_types(text)
        primary, secondaries = pick_primary_and_secondary(scores)

        # If primary is 'unknown' but infostealer_parsed exists -> force infostealer
        if primary == "unknown" and ("infostealer_parsed" in df.columns and row.get("infostealer_parsed")):
            primary = ["infostealer"]

        # If CVE explicitly points to product keywords, boost accordingly (heuristic)
        cves = detect_cves(text)
        if cves and primary == "unknown":
            primary = ["web_application_exploit"]

        primary_list.append(primary[0] if primary else "unknown")
        secondaries_list.append(secondaries)
        # store all positive types (score>0)
        positives = [k for k, v in scores.items() if v > 0]
        if not positives:
            positives = ["unknown"]
        all_detected.append(positives)

    # Add annotation columns
    df["attack_types"] = all_detected
    df["primary_attack_type"] = primary_list
    df["secondary_attack_types"] = secondaries_list

    # Map MITRE (take union of mitre for primary + secondaries)
    mitre_map = []
    for i, row in df.iterrows():
        types = [row["primary_attack_type"]] + (row["secondary_attack_types"] or [])
        mitres = []
        for t in types:
            if t in ATTACK_DEFINITIONS:
                mitres.extend(ATTACK_DEFINITIONS[t]["mitre"])
        mitre_map.append(sorted(set(mitres)))
    df["mitre_mapping"] = mitre_map

    # Save annotated CSV
    annotated_csv = os.path.join(out_dir, f"{base}_annotated_attack_vectors.csv")
    df.to_csv(annotated_csv, index=False)
    print(f"[+] Annotated CSV saved: {annotated_csv}")

    # -----------------------------
    # Summaries & Counts
    # -----------------------------
    # overall counts
    overall_counts = Counter(df["primary_attack_type"].fillna("unknown"))
    overall_df = pd.DataFrame.from_records(list(overall_counts.items()), columns=["attack_type", "count"])
    overall_df = overall_df.sort_values("count", ascending=False)
    overall_df.to_csv(os.path.join(out_dir, f"{base}_attack_type_counts_overall.csv"), index=False)

    # by group
    if "group" in df.columns:
        group_counts = df.groupby(["group", "primary_attack_type"]).size().unstack(fill_value=0)
        group_counts.to_csv(os.path.join(out_dir, f"{base}_attack_types_by_group.csv"))

    # by country
    if "country" in df.columns:
        df["country_clean"] = df["country"].fillna("Unknown").astype(str).str.upper()
        country_counts = df.groupby(["country_clean", "primary_attack_type"]).size().unstack(fill_value=0)
        country_counts.to_csv(os.path.join(out_dir, f"{base}_attack_types_by_country.csv"))

    # by industry/activity
    if "activity" in df.columns:
        activity_counts = df.groupby(["activity", "primary_attack_type"]).size().unstack(fill_value=0)
        activity_counts.to_csv(os.path.join(out_dir, f"{base}_attack_types_by_activity.csv"))

    # timeline (monthly)
    df["month"] = df["attackdate"].dt.to_period("M").astype(str)
    timeline = df.groupby(["month", "primary_attack_type"]).size().unstack(fill_value=0)
    timeline.to_csv(os.path.join(out_dir, f"{base}_attack_types_timeline_monthly.csv"))

    # -----------------------------
    # Charts: save to out_dir
    # -----------------------------
    sns.set(style="whitegrid")

    # 1) Pie chart overall (top N combined, rest as Other)
    pie_out = os.path.join(out_dir, f"{base}_attack_vector_pie.png")
    topN = 10
    overall_series = pd.Series(dict(overall_counts)).sort_values(ascending=False)
    if len(overall_series) > topN:
        top = overall_series.iloc[:topN]
        other = overall_series.iloc[topN:].sum()
        top["Other"] = other
    else:
        top = overall_series
    fig, ax = plt.subplots(figsize=(8, 8))
    top.plot.pie(ax=ax, autopct="%1.1f%%", startangle=140)
    ax.set_ylabel("")
    ax.set_title("Primary Attack Types (overall)")
    fig.savefig(pie_out, dpi=300, bbox_inches="tight")
    plt.close(fig)

    # 2) Bar chart overall
    bar_out = os.path.join(out_dir, f"{base}_attack_vector_bar.png")
    fig, ax = plt.subplots(figsize=(12, 6))
    overall_series.sort_values(ascending=True).plot.barh(ax=ax)
    ax.set_xlabel("Count")
    ax.set_title("Primary Attack Types (overall)")
    fig.savefig(bar_out, dpi=300, bbox_inches="tight")
    plt.close(fig)

    # 3) Stacked bar for top groups (by attack type) - pick top K groups
    stacked_out = os.path.join(out_dir, f"{base}_attack_vector_by_top_groups.png")
    if "group" in df.columns:
        top_groups = df["group"].value_counts().iloc[:8].index.tolist()
        stacked_df = df[df["group"].isin(top_groups)].groupby(["group", "primary_attack_type"]).size().unstack(fill_value=0)
        fig = stacked_df.plot(kind="bar", stacked=True, figsize=(14, 7)).get_figure()
        fig.suptitle("Primary Attack Types by Top Groups")
        fig.savefig(stacked_out, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # 4) Heatmap: group vs attack type (normalized)
    heatmap_out = os.path.join(out_dir, f"{base}_heatmap_groups_attack_types.png")
    if "group" in df.columns:
        heatmap_df = df.groupby(["group", "primary_attack_type"]).size().unstack(fill_value=0)
        # restrict to groups with > threshold attacks for readability
        groups_to_show = heatmap_df.sum(axis=1).sort_values(ascending=False).iloc[:25].index
        hm = heatmap_df.loc[groups_to_show]
        fig, ax = plt.subplots(figsize=(14, max(6, len(hm) * 0.25)))
        sns.heatmap(hm, cmap="YlGnBu", ax=ax)
        ax.set_title("Heatmap: Groups vs Primary Attack Types")
        fig.savefig(heatmap_out, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # 5) Timeline stacked area (monthly)
    timeline_out = os.path.join(out_dir, f"{base}_timeline_attack_types.png")
    if not timeline.empty:
        # keep most common attack types to reduce clutter
        top_types = timeline.sum().sort_values(ascending=False).iloc[:8].index.tolist()
        tdf = timeline[top_types]
        fig, ax = plt.subplots(figsize=(14, 7))
        tdf.plot.area(ax=ax)
        ax.set_title("Monthly Trend of Primary Attack Types (top types)")
        ax.set_xlabel("Month")
        ax.set_ylabel("Count")
        fig.savefig(timeline_out, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # 6) Save a short human-readable text summary
    summary_txt = os.path.join(out_dir, f"{base}_attack_vector_summary.txt")
    with open(summary_txt, "w", encoding="utf-8") as fh:
        fh.write(f"Attack Vector Analysis Summary for: {base}\n")
        fh.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        fh.write(f"Total rows analyzed: {len(df)}\n\n")
        fh.write("Top primary attack types (overall):\n")
        for k, v in overall_df.values:
            fh.write(f" - {k}: {v}\n")
        fh.write("\nTop groups by number of attacks (top 10):\n")
        if "group" in df.columns:
            for g, cnt in df["group"].value_counts().iloc[:10].items():
                fh.write(f" - {g}: {cnt}\n")
        fh.write("\nFiles generated in folder:\n")
        for f in sorted(os.listdir(out_dir)):
            fh.write(f" - {f}\n")
    print(f"[+] All charts and outputs saved in folder: {out_dir}")
    print(f"[+] Summary saved: {summary_txt}")


if __name__ == "__main__":
    main()
