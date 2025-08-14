
---

````markdown
# 🛡 EB Web Vulnerability Scanner

EB Web Vulnerability Scanner is a **Python-based, non-intrusive security testing tool** that detects common OWASP Top 10 risks. It crawls target websites, performs safe security checks, and generates professional **Markdown, HTML, and PDF** reports with a modern, TailwindCSS-styled dashboard design.

![HTML Report Screenshot](assets/screenshot.png)

---

## ✨ Features

- 🌐 **Website Crawler** – Discovers internal links up to a configurable depth
- 🛡 **Security Header Analysis** – Detects missing or weak HTTP headers
- 🍪 **Cookie Security Checks** – Identifies missing `HttpOnly` and `Secure` flags
- 📝 **Form Discovery** – Finds forms and hidden inputs for further testing
- 🔍 **Token Detection** – Extracts CSRF/API tokens from HTML and JavaScript
- 💉 **XSS & SQLi Indicators** – Detects reflected input points and SQL error messages
- 🏷 **Server Fingerprinting** – Identifies server technology from headers
- 📂 **Directory Listing Detection**
- 📊 **Report Generation** – Outputs:
  - Plain Text (`.txt`)
  - Markdown (`.md`)
  - TailwindCSS-styled HTML (`.html`)
  - PDF (`.pdf`)

---

 📦 Installation

**Clone the repository:**
```bash
git clone https://github.com/yourusername/eb-vuln-scanner.git
cd eb-vuln-scanner
````

Install dependencies:

```bash
pip install -r requirements.txt
```

Optional – PDF Export Support:

```bash
# Linux / Ubuntu
sudo apt install wkhtmltopdf
# macOS
brew install wkhtmltopdf
```

---

⚙ Dependencies

All Python dependencies are listed in `requirements.txt`:

```
requests
beautifulsoup4
markdown2
jinja2
pdfkit
reportlab
```

---

🚀 Usage

Basic scan:

```bash
python eb_vuln_scanner.py https://testphp.vulnweb.com
```

Set maximum pages and depth:

```bash
python eb_vuln_scanner.py https://testphp.vulnweb.com --max-pages 50 --max-depth 3
```

Specify output file name:

```bash
python eb_vuln_scanner.py https://testphp.vulnweb.com --output my_report.md
```

---

 📁 Output Files

After each scan, you will get:

| File Type | Description                               |
| --------- | ----------------------------------------- |
| `.txt`    | Plain text report for quick reading       |
| `.md`     | Markdown report for easy formatting       |
| `.html`   | TailwindCSS-styled professional dashboard |
| `.pdf`    | PDF version of the styled HTML report     |

Example reports are available in the [`example_reports`](example_reports/) folder.

---

📸 Screenshots

HTML Report Example:
[HTML Report](assets/screenshot.png)

**PDF Report Example:**
[PDF Report](assets/pdf_screenshot.png)

---

 📜 Example Command & Output

Command:

```bash
python eb_vuln_scanner.py https://testphp.vulnweb.com --max-pages 20 --max-depth 2
```

Output:

```
[INFO] Starting scan on https://testphp.vulnweb.com ...
[INFO] Crawling pages...
[INFO] Checking security headers...
[INFO] Detecting cookies...
[INFO] Looking for vulnerabilities...
[INFO] Scan completed in 14.2 seconds.
[INFO] Reports saved: report.md, report.txt, report.html, report.pdf
```

---

 ⚠ Disclaimer

> This tool is intended for **educational purposes and authorized security testing only**.
> Do **not** use it on systems you do not own or have explicit permission to test.
> The author assumes no responsibility for any misuse or damage caused by this tool.

---

📄 License

This project is licensed under the [MIT License](LICENSE).

---

🤝 Contributing

Contributions are welcome! If you’d like to improve the scanner, please fork the repository and submit a pull request.

---

📬 Contact

**Author:** Hamza Majeed
**GitHub:** [yourusername](https://github.com/yourusername)
**Email:** [youremail@example.com](mailto:youremail@example.com)

```

---

This is now a **single README file**, no splitting, no placeholders except `yourusername` and `youremail@example.com`.  
If you want, I can **also add GitHub badges** at the top so when someone visits your repo, it instantly looks professional.  

Do you want me to add those badges?
```
