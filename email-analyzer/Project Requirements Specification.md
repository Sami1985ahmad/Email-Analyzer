# 📋 Project Requirements Specification: Email Security & Header Analyzer (CLI)

## 1. Executive Summary
- **Project Name:** Email Security & Header Analyzer
- **Target User:** Junior SOC Analyst / Incident Responder
- **Type:** Interactive Command Line Interface (CLI) Tool
- **Language:** Python 3.10+
- **Primary Goal:** Parse `.eml` files, analyze email headers and content for phishing/spoofing indicators, query external threat intelligence APIs (VirusTotal), and generate a color-coded CLI report using `Rich`.

---

## 2. Technical Stack & Dependencies
- **Core Language:** Python
- **Parsing:** `email` (built-in), `mailparser`
- **DNS Queries:** `dnspython` (for SPF, DKIM, DMARC record lookups)
- **Networking/API:** `requests`
- **UI/Formatting:** `rich`
- **CLI Management:** `argparse` (built-in) or `typer`

---

## 3. Core Architecture & Functional Requirements

### Feature 1: Email Parsing Engine
- Read local `.eml` files passed via CLI argument.
- Extract basic metadata: `From`, `To`, `Subject`, `Date`, `Message-ID`.
- Extract body content (Plain Text & HTML).
- Extract embedded URLs and hyperlinked texts.
- Extract file attachments and compute their cryptographic hashes (`SHA-256`).

### Feature 2: Email Header & Authentication Analysis
- **Hop-by-Hop Tracking:** Parse `Received` headers from bottom to top to identify the originating sender IP address.
- **SPF Verification:** Query DNS TXT records for the sender's domain to verify if the sending IP is authorized.
- **DKIM Check:** Check for the presence of `DKIM-Signature` header and locate public key selectors.
- **DMARC Evaluation:** Query DMARC DNS records (`_dmarc.domain.com`) to extract the declared policy (`p=none`, `p=quarantine`, `p=reject`).

### Feature 3: Threat Intelligence Integration
- **VirusTotal API Integration:**
  - Query extracted domain/URL reputations.
  - Query attachment `SHA-256` hashes against VirusTotal malware detection databases.
- Include failure handling/graceful degradation if the API key is missing or rate-limited.

### Feature 4: Rich CLI Reporting & Risk Scoring
- **Risk Assessment Logic:**
  - Low Risk (Safe): Valid SPF/DKIM/DMARC + 0 VirusTotal detections.
  - Medium Risk (Suspicious): Failed authentication checks OR 1-2 VT hits.
  - High Risk (Malicious): Failed auth + multiple VT malicious detections or suspicious attachments.
- **Formatting (`Rich` UI):**
  - Header panel with file name and execution time.
  - Styled tables for Metadata and Authentication Checks (`PASS` in Green, `WARNING` in Yellow, `FAIL` in Red).
  - Tree structure for Routing Hops and extracted URLs.
  - Final Verdict Panel summarizing the risk score.

---

## 4. Step-by-Step Implementation Roadmap

Execution must proceed sequentially. Complete each phase before moving to the next.

### Phase 1: Environment & Project Setup
1. Initialize the project repository with a standard structure:
   ```text
   email-analyzer/
   ├── main.py
   ├── config.py
   ├── requirements.txt
   ├── sample.eml
   └── modules/
       ├── parser.py
       ├── auth_checker.py
       ├── threat_intel.py
       └── reporter.py