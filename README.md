# XSS-Injection Scanner

An advanced, automated **Cross-Site Scripting (XSS)** vulnerability scanner built with Python . It features automated link crawling, form discovery, GET/POST parameter extraction, and multi-vector payload injection to identify potential reflected and stored XSS vulnerabilities in web applications.

---

## 🚀 Features

- **Automated Web Crawling & Discovery:** Automatically parses and maps unique internal links, input fields, and HTML forms across target domains.
- **Dynamic Form Testing:** Extracts POST forms, automatically populates standard fields (email, password, search inputs, etc.), and tests inputs for injection vulnerabilities.
- **Comprehensive XSS Payloads:** Evaluates multiple critical attack vectors including standard script tags, case-insensitive variants, event handlers (`onerror`, `onload`, `onfocus`, `ontoggle`), SVG injections, and JavaScript pseudo-protocol execution.
- **Smart Pattern Analysis & Filtering:** Leverages regex pattern matching and response comparison heuristics while automatically filtering out generic error codes (403, 404, 500) and common security challenges (CAPTCHAs, Cloudflare walls, CSRF token mismatches).
- **Dual Scan Modes:**
  - **Quick Scan:** Fast triage mode targeting top parameters and payloads for rapid assessments.
  - **Deep Scan:** Intensive mode expanding coverage across broader page sets and comprehensive payload banks.
- **Rich Terminal Interface:** Color-coded status logging and formatted summary dashboards.

---

## 📋 Prerequisites & Requirements

- **Python 3.8+**
- **Playwright for Python**

### Installation
---

1. Install the required Python dependencies:
   ```
   pip install playwright
   ```
   playwright install chromium
   ```

---

### Interactive Menu Options:
1. **Quick Scan (Default):** Runs a rapid assessment over discovered endpoints using core payload sets.
2. **Deep Scan:** Executes an exhaustive check covering maximum pages and the full payload bank.
3. **Exit:** Safely quits the tool.

When prompted, enter your target URL (e.g., `https://example.com`).


---

## ⚠️ Disclaimer

This tool is created strictly for **educational purposes, authorized security auditing, and bug bounty programs**. Do not scan targets without explicit prior written authorization from the system owners. Unauthorized testing is illegal and unethical.

جارٍ عرض "README.md".
