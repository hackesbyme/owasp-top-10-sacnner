# owasp-top-10-sacnner

# EB Web Vulnerability Scanner

A **non-intrusive web vulnerability scanner** built in Python for educational and ethical hacking purposes.  
It crawls a target website, performs basic security checks (OWASP Top 10 related), and generates **beautiful TailwindCSS HTML** and **PDF** reports.

![EB Scanner Screenshot](assets/screenshot.png)

---

## ✨ Features
- 🌐 **Website Crawler** – Discovers internal pages.
- 🛡 **Security Header Checks** – Detects missing/weak headers.
- 🍪 **Cookie Flag Checks** – Finds cookies missing `HttpOnly`/`Secure`.
- 📝 **Form Discovery** – Detects forms & hidden inputs.
- 🔍 **Token Discovery** – Finds CSRF/API tokens in HTML & JS.
- 💉 **XSS & SQLi Checks** – Basic reflected XSS & error-based SQLi detection.
- 🏷 **Server Technology Fingerprinting** – From HTTP headers.
- 📂 **Directory Listing Detection** – Checks for open indexes.
- 📊 **Professional Reports** – Outputs:
  - Markdown (`.md`)
  - Plain Text (`.txt`)
  - TailwindCSS HTML (`.html`)
  - PDF (`.pdf`)

---

## 📸 Report Preview
![HTML Report Preview](assets/screenshot.png)

---

## 📦 Installation

**Clone the repo:**
```bash
git clone https://github.com/yourusername/eb-vuln-scanner.git
cd eb-vuln-scanner
