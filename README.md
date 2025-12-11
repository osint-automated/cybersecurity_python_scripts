# CyberSecurity Python Scripts

This repository contains a collection of Python scripts for performing various cybersecurity analysis tasks, including Indicator of Compromise (IOC) extraction and enrichment, and mapping threat intelligence to the MITRE ATT&CK® framework.

## Setup and Installation

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Create a virtual environment:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Download spaCy model:**
    The MITRE mapping script requires a `spaCy` language model.

    ```bash
    python -m spacy download en_core_web_sm
    ```

5.  **Set up API Keys:**
    The IOC enrichment script requires API keys for several services. Create a `.env` file in the root of the project directory:
    ```
    abuseipdb_api_key="YOUR_ABUSEIPDB_API_KEY"
    alienvault_api_key="YOUR_ALIENVAULT_OTX_API_KEY"
    urlscan_io_api_key="YOUR_URLSCAN.IO_API_KEY"
    virustotal_api_key="YOUR_VIRUSTOTAL_API_KEY"
    ```

## Scripts

### 1. IOC Extraction and Enrichment (`ioc_extraction_and_enrichment.py`)

This script extracts various types of IOCs from a given log file, enriches them with threat intelligence from external services, and outputs the results to a CSV file.

**Features:**

- **IOC Extraction:** Extracts IPs, domains, URLs, file hashes (MD5, SHA1, SHA256), encoded PowerShell commands, suspicious file paths, scheduled tasks, and detects patterns of failed logins and network beaconing.
- **Domain Analysis:** Identifies potential Domain Generation Algorithm (DGA) domains using entropy analysis.
- **Threat Intelligence Enrichment:**
  - **IPs:** Checks IP reputation using [AbuseIPDB](https://www.abuseipdb.com/).
  - **Domains & Hashes:** Gathers intelligence from [AlienVault OTX](https://otx.alienvault.com/).
  - **URLs:** Submits URLs for scanning and retrieves verdicts from [urlscan.io](https://urlscan.io/).
- **Output:** Saves all findings into a structured CSV file (`ioc_enrichment_results.csv`).

### 2. MITRE ATT&CK Mapping (`mitre_att&ck_mapping.py`)

This script analyzes a text file (e.g., a threat intelligence report) and maps the content to specific tactics and techniques within the MITRE ATT&CK® Enterprise framework.

**Features:**

- **Dynamic ATT&CK Data:** Downloads the latest Enterprise ATT&CK matrix from MITRE's official CTI repository.
- **NLP-Powered Matching:** Uses `spaCy` for natural language processing and `rapidfuzz` for fuzzy string matching to identify techniques and their synonyms within the text.
- **Structured Output:** Generates a CSV file (`extracted_ttp_summary.csv`) that organizes the identified techniques under their respective ATT&CK tactics.
- **Console Summary:** Prints a clean summary of the findings directly to the console.

### 3. Ransomware.live Integration

These scripts leverage the [Ransomware.live](https://ransomware.live/) API to provide up-to-date information on ransomware groups, their victims, and related trends.

#### `ransomware_live_ransomware_group_search.py`

This script allows you to search for specific ransomware groups and retrieve detailed information about their operations, including their `post_title`, `group_name`, `country`, and `description`.

#### `ransomware_live_victim_search_by_group.py`

This script fetches and lists the recent victims of a specified ransomware group.

#### `ransomware_live_sector_country_search.py`

This script provides statistics on ransomware attacks, allowing you to query data by sector or country.

### 4. Top 25 Recent CVEs

#### `top_25_recent_cves.py`

This script fetches the 25 most recent CVEs from the National Vulnerability Database (NVD) and scores them based on CVSS score, presence in the CISA Known Exploited Vulnerabilities (KEV) catalog, and publication date.

#### `top_25_recent_cves_keyword_search.py`

This script fetches the 25 most recent CVEs that match a specific keyword. It scores each CVE based on its CVSS score, presence in the CISA KEV catalog, and publication date.

### 5. Infrastructure Analysis and Enumeration

#### `asn_enumeration.py`

This script enriches an IP address or CIDR block by providing ASN (Autonomous System Number) information from VirusTotal. It also flags IPs belonging to high-risk ASNs.

#### `c2_infrastructure_clustering.py`

This script attempts to find connections between different indicators of compromise (IOCs) by clustering them based on shared infrastructure attributes.

#### `ip_enrichment.py`

This script enriches an IP address with threat intelligence, providing details such as geolocation, ASN, and known malicious activities.

#### `redirect_chain_analyzer.py`

This script analyzes the redirect chain of a given URL and displays the full path of redirects.

### 6. Live Attack Surface Scanner (`live_attack_surface_scanner.py`)

This script performs a live scan of a target (domain or IP address) to identify exposed services, analyze TLS certificates, and gather WHOIS information, ultimately calculating a risk score for the target's attack surface.

### 7. CTI Reports and Visualization

#### `ransomware_group_attack_analysis_for_cti_report.py`

This script takes a CSV file of ransomware victims (generated from `ransomware_live_victim_search_by_group.py`) and generates a CTI (Cyber Threat Intelligence) report with statistics and visualizations.

#### `ransomware_sector_analysis_for_cti_report.py`

This script provides a more detailed analysis of ransomware attack data from a CSV file, focusing on sector and country-specific trends.

### 8. Threat Actor Analysis

#### `ransomware_attack_vector_analysis.py`

This script analyzes ransomware group descriptions to identify common attack vectors. It uses NLP to parse descriptions and extracts vectors like phishing, RDP compromise, and software vulnerabilities.

#### `ransomware_motivation_analysis.py`

This script analyzes the stated motivations of ransomware groups from their descriptions. It classifies motivations into categories like financial gain, data exfiltration, and disruption.

## Usage

Each script is designed to be run from the command line. For scripts that require arguments, you can typically use the `-h` or `--help` flag to see available options.

Example:
```bash
python ioc_extraction_and_enrichment.py
python mitre_att&ck_mapping.py
python ransomware_live_ransomware_group_search.py
python ip_enrichment.py
```