# CyberSecurity Python Scripts

This repository contains a collection of Python scripts for performing various cybersecurity analysis tasks, including Indicator of Compromise (IOC) extraction and enrichment, and mapping threat intelligence to the MITRE ATT&CK® framework.

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

**Features:**

- **Group Search:** Search for ransomware groups by name.
- **Detailed Output:** Displays comprehensive details about the group.

#### `ransomware_live_victim_search_by_group.py`

This script fetches and lists the recent victims of a specified ransomware group.

**Features:**

- **Victim Discovery:** Retrieve a list of victims for a given ransomware group.
- **Targeted Information:** Provides insights into the targets of specific threat actors.

#### `ransomwarelive_sector_country_search.py`

This script provides statistics on ransomware attacks, allowing you to query data by sector or country.

**Features:**

- **Statistical Analysis:** Get counts of ransomware incidents by industry sector or country.
- **Trend Analysis:** Helps in understanding the distribution and focus of ransomware attacks.

### 4. Top 25 Recent CVEs

#### `top_25_recent_cves.py`

This script fetches the 25 most recent CVEs from the National Vulnerability Database (NVD) and scores them based on CVSS score, presence in the CISA Known Exploited Vulnerabilities (KEV) catalog, and publication date.

**Features:**

- **Recent CVEs:** Fetches CVEs published in the last 30 days.
- **Scoring:** Ranks CVEs based on a trend score.
- **Output:** Prints the top 25 CVEs to the console.

#### `top_25_recent_cves_keyword_search.py`

This script fetches the 25 most recent CVEs that match a specific keyword. It scores each CVE based on its CVSS score, presence in the CISA KEV catalog, and publication date.

**Features:**

- **Keyword Search:** Filters CVEs by a user-provided keyword.
- **Scoring:** Ranks CVEs based on a trend score.
- **Output:** Prints the top 25 CVEs matching the keyword to the console.

### 5. Infrastructure Analysis and Enumeration

#### `asn_enumeration.py`

This script enriches an IP address or CIDR block by providing ASN (Autonomous System Number) information from VirusTotal. It also flags IPs belonging to high-risk ASNs.

**Features:**

- **ASN Enrichment:** Retrieves ASN details, owner, and country for a given IP.
- **High-Risk ASN Flagging:** Identifies IPs associated with commonly abused ASNs.
- **CIDR Support:** Can enumerate all IPs within a CIDR range.

#### `c2_infrastructure_clustering.py`

This script attempts to find connections between different indicators of compromise (IOCs) by clustering them based on shared infrastructure attributes.

**Features:**

- **Passive DNS:** Links domains to IPs they have resolved to.
- **WHOIS Correlation:** Connects domains that share the same registration email.
- **SSL/TLS Certificate Reuse:** Clusters IPs that have used the same SSL/TLS certificates.

### 6. CTI Reports and Visualization

#### `ransomware_group_attack_analysis_for_cti_report.py`

This script takes a CSV file of ransomware victims (generated from `ransomware_live_victim_search_by_group.py`) and generates a CTI (Cyber Threat Intelligence) report with statistics and visualizations.

**Features:**

- **Data Analysis:** Computes statistics on top ransomware groups, victim countries, and targeted industries.
- **Temporal Analysis:** Analyzes attack timelines and detection delays.
- **Visualization:** Creates and saves charts for attack trends, industry distribution, country distribution, group activity, and detection delay.

#### `ransomware_sector_analysis_for_cti_report.py`

This script provides a more detailed analysis of ransomware attack data from a CSV file, focusing on sector and country-specific trends.

**Features:**

- **In-depth Statistics:** Generates detailed metrics on attacks by group, country, and industry.
- **Timeline Heatmap:** Creates a heatmap to visualize ransomware group activity over time.
- **Customizable Plots:** Saves multiple plots for group, country, and industry distributions, as well as detection delay.

### 7. Threat Actor Analysis

#### `ransomware_attack_vector_analysis.py`

This script analyzes ransomware group descriptions to identify common attack vectors. It uses NLP to parse descriptions and extracts vectors like phishing, RDP compromise, and software vulnerabilities.

**Features:**

- **Attack Vector Extraction:** Identifies and categorizes common ransomware attack vectors.
- **Frequency Analysis:** Counts the occurrences of each attack vector.
- **CSV Output:** Saves the results to `attack_vectors.csv`.

#### `ransomware_motivation_analysis.py`

This script analyzes the stated motivations of ransomware groups from their descriptions. It classifies motivations into categories like financial gain, data exfiltration, and disruption.

**Features:**

- **Motivation Classification:** Categorizes group motivations based on description keywords.
- **Statistical Summary:** Provides a summary of the different motivations.
- **CSV Output:** Saves the analysis to `ransomware_motivations.csv`.

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

## Usage

### IOC Extraction and Enrichment

1.  Ensure your `.env` file is correctly configured with your API keys.
2.  Run the script from your terminal. It will prompt you to enter the path to your log file.
    ```bash
    python ioc_extraction_and_enrichment.py
    ```
3.  The script will process the file, perform the enrichment, and save the results in `ioc_enrichment_results.csv`.

### MITRE ATT&CK Mapping

1.  Create a file named `mitre.txt` in the project directory and paste the text you want to analyze into it.
2.  Run the script:
    ```bash
    python mitre_att&ck_mapping.py
    ```
3.  The script will download the latest ATT&CK data, analyze `mitre.txt`, and generate the `extracted_ttp_summary.csv` file. A summary will also be printed to the console.

### Ransomware.live Integration

Run the scripts from your terminal, and they will prompt you for the required input.

- **Search for a ransomware group:**

  ```bash
  python ransomware_live_ransomware_group_search.py
  ```

- **Search for victims of a group:**

  ```bash
  python ransomware_live_victim_search_by_group.py
  ```

- **Get sector or country statistics:**
  ```bash
  python ransomwarelive_sector_country_search.py
  ```

### Top 25 Recent CVEs

- **Get the top 25 recent CVEs:**
  ```bash
  python top_25_recent_cves.py
  ```

- **Search for CVEs by keyword:**
  ```bash
  python top_25_recent_cves_keyword_search.py
  ```

### Infrastructure Analysis and Enumeration

- **Enumerate ASN information:**
    ```bash
    python asn_enumeration.py
    ```
- **Cluster Infrastructure:**
    ```bash
    python c2_infrastructure_clustering.py
    ```

### CTI Reports and Visualization

- **Generate CTI report from ransomware data:**
    ```bash
    python ransomware_group_attack_analysis_for_cti_report.py
    ```
- **Generate sector-specific CTI report:**
    ```bash
    python ransomware_sector_analysis_for_cti_report.py
    ```

### Threat Actor Analysis

- **Analyze attack vectors:**
    ```bash
    python ransomware_attack_vector_analysis.py
    ```
- **Analyze motivations:**
    ```bash
    python ransomware_motivation_analysis.py
    ```
