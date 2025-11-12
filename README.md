# CyberSecurity Python Scripts

This repository contains a collection of Python scripts for performing various cybersecurity analysis tasks, including Indicator of Compromise (IOC) extraction and enrichment, and mapping threat intelligence to the MITRE ATT&CK® framework.

## Scripts

### 1. IOC Extraction and Enrichment (`ioc_extraction_and_enrichment.py`)

This script extracts various types of IOCs from a given log file, enriches them with threat intelligence from external services, and outputs the results to a CSV file.

**Features:**

*   **IOC Extraction:** Extracts IPs, domains, URLs, file hashes (MD5, SHA1, SHA256), encoded PowerShell commands, suspicious file paths, scheduled tasks, and detects patterns of failed logins and network beaconing.
*   **Domain Analysis:** Identifies potential Domain Generation Algorithm (DGA) domains using entropy analysis.
*   **Threat Intelligence Enrichment:**
    *   **IPs:** Checks IP reputation using [AbuseIPDB](https://www.abuseipdb.com/).
    *   **Domains & Hashes:** Gathers intelligence from [AlienVault OTX](https://otx.alienvault.com/).
    *   **URLs:** Submits URLs for scanning and retrieves verdicts from [urlscan.io](https://urlscan.io/).
*   **Output:** Saves all findings into a structured CSV file (`ioc_enrichment_results.csv`).

### 2. MITRE ATT&CK Mapping (`mitre_att&ck_mapping.py`)

This script analyzes a text file (e.g., a threat intelligence report) and maps the content to specific tactics and techniques within the MITRE ATT&CK® Enterprise framework.

**Features:**

*   **Dynamic ATT&CK Data:** Downloads the latest Enterprise ATT&CK matrix from MITRE's official CTI repository.
*   **NLP-Powered Matching:** Uses `spaCy` for natural language processing and `rapidfuzz` for fuzzy string matching to identify techniques and their synonyms within the text.
*   **Structured Output:** Generates a CSV file (`extracted_ttp_summary.csv`) that organizes the identified techniques under their respective ATT&CK tactics.
*   **Console Summary:** Prints a clean summary of the findings directly to the console.

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
