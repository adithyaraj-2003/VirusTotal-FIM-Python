# 🔍 Automated File Integrity Monitor (FIM) with VirusTotal Integration

## 📌 Project Overview
Built a lightweight Python-based File Integrity Monitoring (FIM) tool designed to track real-time modifications and new file creations within a sensitive directory. To elevate standard log monitoring, the script automatically computes SHA-256 file hashes and queries the **VirusTotal REST API** to check for malicious indicators across global threat feeds.

---

## 🛠️ Technology Stack & APIs
* **Language:** Python (`os`, `hashlib`, `requests`, `pathlib`)
* **Threat Intelligence:** VirusTotal API v3
* **Security Framework Alignment:** NIST CSF (PR.DS-1, DE.CM-1), ISO/IEC 27001:2022 (Annex A.8.9 - Configuration Management / Integrity)

---

## ⚙️ How It Works
1. **Baseline Establishment:** On startup, the script scans the target directory and catalogs existing files with their cryptographic SHA-256 hashes.
2. **Continuous Polling:** Periodically checks the directory for newly dropped files or unauthorized alterations to existing files.
3. **Automated Threat Lookups:** When a change is triggered, the script extracts the file hash and queries VirusTotal to determine if security vendors flag it as malicious, generating instant alerts in the console.

---

## 🚀 Key Skills Demonstrated
* **API Integration:** Interfacing Python scripts with external threat intelligence APIs (VirusTotal v3).
* **Cryptographic Hashing:** Utilizing SHA-256 for precise file state tracking.
* **Security Automation:** Building proactive detection mechanisms to reduce manual analyst overhead.
