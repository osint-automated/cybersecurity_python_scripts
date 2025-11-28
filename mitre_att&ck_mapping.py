"""
This script takes a text file containing a cyber threat intelligence report and maps the text to the MITRE ATT&CK framework.
It uses a combination of phrase matching and fuzzy string matching to identify techniques and tactics in the text.
The script downloads the latest MITRE ATT&CK enterprise matrix from the MITRE CTI repository.
The output is a CSV file containing a compact summary of the extracted TTPs, ordered by tactic.
"""
import os
import sys
import re
from collections import defaultdict
from typing import List, Dict, Tuple, Any, Set

import requests
import pandas as pd
import spacy
from spacy.matcher import PhraseMatcher
from rapidfuzz import process, fuzz

# ---------- Configuration ----------
ARTICLE_FILE = input('Enter PATH to txt file containing article text: ')
SUMMARY_CSV = "extracted_ttp_summary.csv"
MITRE_CTIS_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# ---------- Fetch & build mapping ----------

def download_mitre_cti_json(url: str = MITRE_CTIS_URL, timeout: int = 30) -> Dict[str, Any]:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def build_mapping_from_mitre_bundle(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse the MITRE bundle into list of entries:
      { "technique": <name>, "id": <ATT&CK id>, "tactic": <tactic>, "synonyms": [...] }
    Create one entry per (technique, tactic).
    """
    objects = bundle.get("objects", [])
    techniques = []
    for obj in objects:
        try:
            if obj.get("type") != "attack-pattern":
                continue
            name = obj.get("name")
            if not name:
                continue
            # external id
            ext_id = None
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            # kill chain phases -> tactics
            tactics = []
            for kcp in obj.get("kill_chain_phases", []) or []:
                phase = kcp.get("phase_name")
                if phase:
                    tactics.append(phase.replace("-", " ").title())
            if not tactics:
                continue
            aliases = obj.get("x_mitre_aliases") or []
            norm_aliases = []
            for a in aliases:
                if isinstance(a, str) and a.strip().lower() != name.strip().lower():
                    if a.strip() not in norm_aliases:
                        norm_aliases.append(a.strip())
            for tactic in tactics:
                techniques.append({
                    "technique": name.strip(),
                    "id": ext_id,
                    "tactic": tactic,
                    "synonyms": norm_aliases
                })
        except Exception:
            continue

    # dedupe by (technique, tactic)
    seen = {}
    dedup = []
    for e in techniques:
        key = (e["technique"].lower(), e["tactic"].lower())
        if key in seen:
            idx = seen[key]
            existing = dedup[idx]
            for s in e.get("synonyms", []):
                if s not in existing["synonyms"]:
                    existing["synonyms"].append(s)
            if not existing.get("id") and e.get("id"):
                existing["id"] = e.get("id")
        else:
            seen[key] = len(dedup)
            dedup.append({
                "technique": e["technique"],
                "id": e.get("id"),
                "tactic": e.get("tactic"),
                "synonyms": e.get("synonyms", []) or []
            })
    return dedup

def get_default_mapping() -> List[Dict[str, Any]]:
    """
    Download MITRE CTI JSON and build mapping.
    """
    print("Downloading MITRE ATT&CK Enterprise JSON...")
    bundle = download_mitre_cti_json()
    mapping = build_mapping_from_mitre_bundle(bundle)
    print(f"Built mapping with {len(mapping)} technique+tactic entries.")
    return mapping

# ---------- Text normalization & matcher ----------

def normalize_text(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[\u2018\u2019\u201c\u201d]", "'", t)
    t = re.sub(r"[^a-z0-9\s\-\_/]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t

def build_phrase_matcher(nlp, mapping: List[Dict[str, Any]]):
    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    phrase_to_info = {}
    patterns_by_label = defaultdict(list)

    for entry in mapping:
        canonical = entry["technique"]
        tid = entry.get("id") or canonical
        tactic = entry.get("tactic") or "Unknown"
        synonyms = entry.get("synonyms", []) or []
        forms = set([canonical] + synonyms)
        for form in forms:
            form_norm = form.strip()
            if not form_norm:
                continue
            label = tid
            doc = nlp.make_doc(form_norm)
            patterns_by_label[label].append(doc)
            phrase_to_info[form_norm.lower()] = {
                "technique": canonical,
                "id": entry.get("id"),
                "tactic": tactic
            }

    for label, patterns in patterns_by_label.items():
        try:
            matcher.add(label, patterns)
        except Exception:
            pass

    return matcher, phrase_to_info

# ---------- Matching logic ----------

def match_ttps_in_text(text: str, mapping: List[Dict[str, Any]],
                       nlp, fuzzy_threshold: int = 85) -> Dict[str, Set[Tuple[str,str]]]:
    """
    Returns dict: tactic -> set((technique, id))
    Uses phrase matching first, then fuzzy matching across n-gram windows.
    """
    doc = nlp(text)
    matcher, phrase_to_info = build_phrase_matcher(nlp, mapping)

    found = defaultdict(set)

    # Phrase matches
    matches = matcher(doc)
    for match_id, start, end in matches:
        span = doc[start:end]
        info = phrase_to_info.get(span.text.strip().lower())
        if info:
            found[info["tactic"]].add((info["technique"], info.get("id")))

    # Prepare candidate normalized forms for fuzzy matching
    candidate_forms = []
    candidate_map = {}
    for entry in mapping:
        canonical = entry["technique"]
        tid = entry.get("id")
        tactic = entry.get("tactic") or "Unknown"
        synonyms = entry.get("synonyms", []) or []
        forms = set([canonical] + synonyms)
        for f in forms:
            f_norm = normalize_text(f)
            candidate_forms.append(f_norm)
            candidate_map[f_norm] = {"technique": canonical, "id": tid, "tactic": tactic}
    unique_candidates = list(set(candidate_forms))

    # Build token windows from normalized text
    tok_text = normalize_text(text)
    tokens = tok_text.split()
    n = len(tokens)
    windows = set()
    max_len = 6
    for L in range(1, max_len + 1):
        for i in range(0, n - L + 1):
            windows.add(" ".join(tokens[i:i+L]).strip())

    for w in windows:
        if len(w) < 3:
            continue
        result = process.extractOne(w, unique_candidates, scorer=fuzz.token_sort_ratio)
        if result:
            match_str, score, _ = result
            if score >= fuzzy_threshold:
                info = candidate_map.get(match_str)
                if info:
                    found[info["tactic"]].add((info["technique"], info.get("id")))

    return found

# ---------- Output formatting (compact, shifted-up) ----------

def results_to_compact_dataframe(found: Dict[str, Set[Tuple[str,str]]]) -> pd.DataFrame:
    """
    Build compact DataFrame:
      - columns = tactics (TACTIC_ORDER)
      - entries for each column stacked top-to-bottom (no blank gaps)
    """
    col_data = {}
    max_len = 0
    for tactic in TACTIC_ORDER:
        techniques = sorted({t for t, _ in found.get(tactic, [])})
        col_data[tactic] = techniques
        if len(techniques) > max_len:
            max_len = len(techniques)

    # pad shorter columns
    for tactic in TACTIC_ORDER:
        col = col_data[tactic]
        padded = col + [""] * (max_len - len(col))
        col_data[tactic] = padded

    df = pd.DataFrame(col_data)
    return df

# ---------- Main ----------

def main():
    if not os.path.exists(ARTICLE_FILE):
        print(f"ERROR: '{ARTICLE_FILE}' not found. Create the file with your article text and re-run.")
        sys.exit(1)

    with open(ARTICLE_FILE, "r", encoding="utf-8") as f:
        article_text = f.read().strip()
    if not article_text:
        print(f"ERROR: '{ARTICLE_FILE}' is empty. Add text and re-run.")
        sys.exit(1)

    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        print("spaCy model 'en_core_web_sm' missing. Run: python -m spacy download en_core_web_sm")
        raise

    mapping = get_default_mapping() if (globals().get("get_default_mapping", None) is not None) else build_mapping_from_mitre_bundle(download_mitre_cti_json())
    # (explicit call to get_default_mapping is below to avoid NameError in some embedding contexts)
    # but ensure mapping is set:
    if not mapping:
        mapping = build_mapping_from_mitre_bundle(download_mitre_cti_json())

    # run matching
    print("Extracting TTPs (phrase + fuzzy matching)...")
    found = match_ttps_in_text(article_text, mapping, nlp, fuzzy_threshold=85)

    # produce compact CSV
    df_summary = results_to_compact_dataframe(found)
    df_summary.to_csv(SUMMARY_CSV, index=False)
    print(f"Saved compact summary to: {SUMMARY_CSV}")

    # print short summary
    print("\n=== Extracted TTPs by tactic ===\n")
    any_found = False
    for tactic in TACTIC_ORDER:
        techniques = sorted({t for t, _ in found.get(tactic, [])})
        if techniques:
            any_found = True
            print(tactic)
            for t in techniques:
                print(" -", t)
            print()
    if not any_found:
        print("No techniques found with current matching threshold.")

    print("Done.")

if __name__ == '__main__':
    # provide get_default_mapping here to call the cleaner function
    def get_default_mapping():
        bundle = download_mitre_cti_json()
        return build_mapping_from_mitre_bundle(bundle)
    main()
