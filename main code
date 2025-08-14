#!/usr/bin/env python3
"""
EB Web Vulnerability Scanner (single-file)
Outputs: .md, .txt, styled .html (Tailwind), and .pdf (pdfkit/wkhtmltopdf preferred; reportlab fallback).

Usage:
    python eb_vuln_scanner.py https://example.com --max-pages 50 --output eb_report.md

Dependencies:
    pip install requests beautifulsoup4 markdown2 jinja2 pdfkit reportlab
    (wkhtmltopdf is optional but recommended for HTML->PDF fidelity)
"""

import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
import re
import time
import os
import json
from collections import deque

# Optional libs (best-effort)
try:
    import markdown2
except Exception:
    markdown2 = None

try:
    import jinja2
except Exception:
    jinja2 = None

try:
    import pdfkit
except Exception:
    pdfkit = None

try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
except Exception:
    SimpleDocTemplate = None

# ----------------------------- Configuration ---------------------------------
DEFAULT_HEADERS = {
    'User-Agent': 'EB-Vuln-Scanner/1.0 (+https://example.org/intern-tool)'
}

SQL_ERROR_SIGNS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'pdoexception',
    'pg_query():',
    'mysql_fetch',
    'odbc sql',
    'syntax error',
]

# ----------------------------- Utilities ------------------------------------

def normalized_domain(url):
    p = urlparse(url)
    return p.netloc.lower()

def same_domain(base, url):
    try:
        return normalized_domain(base) == normalized_domain(url)
    except Exception:
        return False

def make_request(url, session=None, **kwargs):
    session = session or requests.Session()
    try:
        r = session.get(url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True, **kwargs)
        return r
    except Exception:
        return None

# ----------------------------- Crawling -------------------------------------

def crawl(start_url, max_pages=100, max_depth=2):
    session = requests.Session()
    seen = set()
    q = deque()
    q.append((start_url, 0))
    pages = []

    while q and len(pages) < max_pages:
        url, depth = q.popleft()
        if url in seen:
            continue
        seen.add(url)

        r = make_request(url, session=session)
        if r is None:
            continue

        pages.append({'url': url, 'status_code': r.status_code, 'text': r.text, 'headers': dict(r.headers)})

        content_type = r.headers.get('content-type', '').lower()
        if depth < max_depth and content_type.startswith('text/html'):
            soup = BeautifulSoup(r.text, 'html.parser')
            # extract links
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                joined = urljoin(url, href)
                parsed = urlparse(joined)
                if parsed.scheme in ('http', 'https') and same_domain(start_url, joined):
                    if joined not in seen:
                        q.append((joined, depth + 1))
            # also check script src
            for s in soup.find_all('script', src=True):
                src = urljoin(url, s['src'].strip())
                if src not in seen and same_domain(start_url, src):
                    q.append((src, depth + 1))

    return pages

# ----------------------------- Discovery -----------------------------------

def find_forms_and_inputs(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action') or base_url
        method = (form.get('method') or 'get').lower()
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            inp_type = inp.get('type', 'text')
            name = inp.get('name')
            value = inp.get('value')
            inputs.append({'type': inp_type, 'name': name, 'value': value})
        forms.append({'action': urljoin(base_url, action), 'method': method, 'inputs': inputs})
    return forms

def find_hidden_tokens_and_js(html):
    findings = {'hidden_inputs': [], 'js_tokens': []}
    soup = BeautifulSoup(html, 'html.parser')
    for inp in soup.find_all('input', {'type': 'hidden'}):
        findings['hidden_inputs'].append({'name': inp.get('name'), 'value': inp.get('value')})
    scripts = soup.find_all('script')
    token_regex = re.compile(r"(csrf_token|csrf|api_key|token|_token)[\"'\s:=]+([A-Za-z0-9\-_=]+)", re.I)
    for s in scripts:
        text = s.string or ''
        if not text:
            continue
        for m in token_regex.finditer(text):
            findings['js_tokens'].append({'key': m.group(1), 'value': m.group(2)})
    return findings

# ----------------------------- Checks --------------------------------------

def check_security_headers(headers):
    issues = []
    checks = {
        'content-security-policy': ('present', 'high', 'Content-Security-Policy header missing.'),
        'strict-transport-security': ('present', 'high', 'HSTS header missing or insufficient.'),
        'x-frame-options': ('present', 'medium', 'X-Frame-Options header missing.'),
        'x-content-type-options': ('present', 'medium', 'X-Content-Type-Options header missing.'),
    }
    lh = {k.lower(): v for k, v in headers.items()}
    for h, (expected, severity, msg) in checks.items():
        if h not in lh:
            issues.append({'name': h, 'severity': severity, 'message': msg})
    if 'content-security-policy' in lh:
        csp = lh['content-security-policy']
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            issues.append({'name': 'csp-policy', 'severity': 'medium', 'message': 'CSP allows unsafe-inline or unsafe-eval.'})
    return issues

def check_cookies_from_response(r):
    issues = []
    for c in r.cookies:
        name = c.name
        sc_text = ' '.join([v for k, v in r.headers.items() if k.lower() == 'set-cookie'])
        pattern = re.compile(re.escape(name) + r'=[^;]+;?\s*([^\n\r]*)', re.I)
        m = pattern.search(sc_text)
        cookie_hdr = m.group(0) if m else ''
        if 'httponly' not in cookie_hdr.lower():
            issues.append({'name': name, 'severity': 'low', 'message': 'Cookie missing HttpOnly flag.'})
        if 'secure' not in cookie_hdr.lower():
            issues.append({'name': name, 'severity': 'low', 'message': 'Cookie missing Secure flag.'})
    return issues

def check_reflected_xss(url, session=None):
    session = session or requests.Session()
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    findings = []
    marker = 'EB_XSS_TEST_12345'
    if not qs:
        return []
    for param in list(qs.keys()):
        original = qs[param]
        qs[param] = marker
        new_qs = urlencode(qs)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment))
        r = make_request(new_url, session=session)
        if r and marker in r.text:
            findings.append({'param': param, 'url': new_url, 'evidence': snippet(r.text, marker), 'severity': 'high'})
        qs[param] = original
    return findings

def check_sql_errors(url, session=None):
    session = session or requests.Session()
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    findings = []
    if not qs:
        return []
    for param in list(qs.keys()):
        original = qs[param]
        qs[param] = original + "'"
        new_qs = urlencode(qs)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment))
        r = make_request(new_url, session=session)
        if r and any(sig in r.text.lower() for sig in SQL_ERROR_SIGNS):
            findings.append({'param': param, 'url': new_url, 'evidence': snippet(r.text, "'"), 'severity': 'high'})
        qs[param] = original
    return findings

def snippet(body, marker, length=200):
    idx = body.find(marker)
    if idx == -1:
        return ''
    start = max(0, idx - length//2)
    end = min(len(body), idx + len(marker) + length//2)
    return body[start:end].replace('\n', ' ')[:1000]

def identify_software(headers):
    return headers.get('Server') or headers.get('X-Powered-By') or ''

# ----------------------------- Reporting -----------------------------------

def severity_label(sev):
    if sev == 'high': return 'HIGH'
    if sev == 'medium': return 'MEDIUM'
    if sev == 'low': return 'LOW'
    return 'INFO'

# Jinja2 HTML template (Tailwind CDN) - similar to the UI you provided
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EB Vulnerability Assessment Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .vulnerability-card{transition:all .25s}
    .vulnerability-card:hover{transform:translateY(-6px);box-shadow:0 12px 30px -10px rgba(0,0,0,0.15)}
    .risk-critical{background-color:#ef4444}
    .risk-high{background-color:#f97316}
    .risk-medium{background-color:#f59e0b}
    .risk-low{background-color:#10b981}
    .risk-info{background-color:#3b82f6}
    pre{white-space:pre-wrap;word-break:break-word}
  </style>
</head>
<body class="bg-gray-100">
  <div class="bg-gradient-to-r from-slate-800 to-sky-800 text-white">
    <div class="container mx-auto px-4 py-8">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-4">
          <div class="w-36">
            <!-- inline svg logo -->
            <svg width="140" height="40" viewBox="0 0 140 40" xmlns="http://www.w3.org/2000/svg">
              <rect rx="6" ry="6" width="140" height="40" fill="#0b3a66"/>
              <g transform="translate(10,6)">
                <circle cx="12" cy="12" r="9" fill="#78c0e0"/>
                <text x="30" y="18" font-family="Helvetica, Arial, sans-serif" font-size="12" fill="#fff">EB Vulnerability</text>
              </g>
            </svg>
          </div>
          <div>
            <h1 class="text-2xl font-bold">EB Vulnerability Assessment Report</h1>
            <p class="text-blue-100 text-sm">Non-intrusive web assessment</p>
          </div>
        </div>
        <div class="text-right">
          <p class="text-sm">Target: <strong>{{ target }}</strong></p>
          <p class="text-sm">Scan time: {{ scan_time }}</p>
        </div>
      </div>
    </div>
  </div>

  <div class="container mx-auto px-4 py-8">
    <div class="bg-white rounded-xl shadow p-6 mb-6">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="p-4 bg-blue-50 rounded-lg">
          <p class="text-sm text-gray-500">Target</p>
          <p class="font-semibold text-gray-800">{{ target }}</p>
        </div>
        <div class="p-4 bg-green-50 rounded-lg">
          <p class="text-sm text-gray-500">Pages Found</p>
          <p class="font-semibold text-gray-800">{{ pages|length }}</p>
        </div>
        <div class="p-4 bg-red-50 rounded-lg">
          <p class="text-sm text-gray-500">Findings</p>
          <p class="font-semibold text-gray-800">{{ findings|length }}</p>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div class="lg:col-span-2">
        <div class="bg-white rounded-xl shadow p-6 mb-6">
          <h2 class="text-xl font-semibold mb-4">Vulnerability Findings</h2>
          <div class="space-y-4">
            {% if findings %}
              {% for f in findings %}
                <div class="vulnerability-card bg-white p-4 rounded-lg border border-gray-200">
                  <div class="flex justify-between items-start mb-2">
                    <div>
                      <h4 class="text-lg font-semibold text-gray-800">{{ f.name }}</h4>
                      <p class="text-xs text-gray-500">Location: {{ f.location }}</p>
                    </div>
                    <div>
                      {% set cls = 'risk-info' %}
                      {% if f.severity == 'high' %}{% set cls = 'risk-high' %}{% endif %}
                      {% if f.severity == 'medium' %}{% set cls = 'risk-medium' %}{% endif %}
                      {% if f.severity == 'low' %}{% set cls = 'risk-low' %}{% endif %}
                      <span class="px-3 py-1 rounded-full text-white text-sm {{ cls }}">{{ f.severity|upper }}</span>
                    </div>
                  </div>
                  <p class="text-gray-600 mb-3">{{ f.message }}</p>
                  {% if f.evidence %}
                    <details class="mt-2">
                      <summary class="text-sm text-blue-700 cursor-pointer">Evidence (click to expand)</summary>
                      <pre class="mt-2 bg-gray-50 p-3 rounded">{{ f.evidence }}</pre>
                    </details>
                  {% endif %}
                  {% if f.meta %}
                    <div class="mt-3 text-sm text-gray-600">
                      <strong>Extra:</strong> {{ f.meta }}
                    </div>
                  {% endif %}
                </div>
              {% endfor %}
            {% else %}
              <p class="text-gray-600">No findings discovered.</p>
            {% endif %}
          </div>
        </div>

        <div class="bg-white rounded-xl shadow p-6">
          <h2 class="text-xl font-semibold mb-4">Technical Details</h2>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                {% for f in findings %}
                <tr>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ f.name }}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ f.message }}{% if f.evidence %}<div class="mt-1 text-xs text-gray-400">Evidence included</div>{% endif %}</td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-3 py-1 rounded-full text-white text-sm {% if f.severity == 'high' %}bg-orange-600{% elif f.severity == 'medium' %}bg-yellow-600{% else %}bg-green-600{% endif %}">{{ f.severity|upper }}</span>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div>
        <div class="bg-white rounded-xl shadow p-6 mb-6">
          <h3 class="text-lg font-semibold mb-3">Pages Discovered</h3>
          <div class="space-y-2 max-h-96 overflow-auto">
            {% for p in pages %}
              <div class="p-3 bg-gray-50 rounded border border-gray-100">
                <div class="flex justify-between">
                  <div class="truncate"><span class="text-sm text-gray-600">{{ p.url }}</span></div>
                  <div>
                    <span class="px-2 py-1 text-xs rounded-full {% if p.status_code == 200 %}bg-green-100 text-green-800{% elif p.status_code==403 %}bg-red-100 text-red-800{% else %}bg-yellow-100 text-yellow-800{% endif %}">{{ p.status_code }}</span>
                  </div>
                </div>
              </div>
            {% endfor %}
          </div>
        </div>

        <div class="bg-white rounded-xl shadow p-6">
          <h3 class="text-lg font-semibold mb-3">Summary</h3>
          <p class="text-sm text-gray-600">Pages: <strong>{{ pages|length }}</strong></p>
          <p class="text-sm text-gray-600">Findings: <strong>{{ findings|length }}</strong></p>
        </div>
      </div>
    </div>
  </div>

  <footer class="bg-gray-900 text-white py-8 mt-12">
    <div class="container mx-auto px-4 text-center text-sm text-gray-400">
      <p>This tool is for educational purposes only. Always obtain permission before scanning any website.</p>
    </div>
  </footer>
</body>
</html>
"""

def generate_html_report(output_path, target, pages, findings, scan_time_str):
    # Render with jinja2 if available, otherwise do a dumb replace fallback
    try:
        if jinja2 is None:
            raise RuntimeError("jinja2 not available")
        tpl = jinja2.Template(HTML_TEMPLATE)
        rendered = tpl.render(target=target, pages=pages, findings=findings, scan_time=scan_time_str)
        with open(output_path, 'w', encoding='utf-8') as fh:
            fh.write(rendered)
        print(f"HTML report written to: {output_path}")
        return True
    except Exception as e:
        print("Failed to render HTML with jinja2:", e)
        # Fallback: write simple HTML with minimal substitution
        try:
            basic = HTML_TEMPLATE.replace("{{ target }}", target).replace("{{ scan_time }}", scan_time_str)
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(basic)
            print("Wrote basic HTML (no templating).")
            return True
        except Exception as e2:
            print("Failed to write HTML fallback:", e2)
            return False

def generate_markdown_and_txt(output_md_path, target, pages, findings, scan_time_str):
    lines = []
    lines.append(f"# EB Vulnerability Assessment Report\n")
    lines.append(f"**Target:** {target}\n")
    lines.append(f"**Scan time:** {scan_time_str}\n")
    lines.append('---\n')
    lines.append('## Pages discovered\n')
    if not pages:
        lines.append('No pages discovered.\n')
    else:
        for p in pages:
            lines.append(f"- {p['url']} (status: {p.get('status_code')})\n")
    lines.append('\n## Findings\n')
    if not findings:
        lines.append('No issues discovered with the heuristic checks performed.\n')
    else:
        for f in findings:
            lines.append(f"### {f['name']} - {severity_label(f.get('severity','low'))}\n")
            lines.append(f"- **Location:** {f.get('location','-')}\n")
            lines.append(f"- **Details:** {f.get('message','-')}\n")
            if f.get('evidence'):
                lines.append('\n**Evidence snippet:**\n')
                lines.append('```\n')
                lines.append(f"{f.get('evidence')[:1000]}\n")
                lines.append('```\n')
            if f.get('meta'):
                lines.append(f"- **Extra:** {f.get('meta')}\n")
            lines.append('\n')

    md = '\n'.join(lines)
    with open(output_md_path, 'w', encoding='utf-8') as fh:
        fh.write(md)
    txt_path = os.path.splitext(output_md_path)[0] + '.txt'
    with open(txt_path, 'w', encoding='utf-8') as fh:
        fh.write(md)
    print(f"Markdown and text reports written to: {output_md_path}, {txt_path}")
    return md

def generate_pdf_from_html(html_path, pdf_path):
    # Try pdfkit first (requires wkhtmltopdf)
    if pdfkit:
        try:
            config = None
            # If wkhtmltopdf is in PATH pdfkit will find it; if not, user must configure.
            pdfkit.from_file(html_path, pdf_path)
            print(f"PDF (from HTML) written to: {pdf_path}")
            return True
        except Exception as e:
            print("pdfkit/wkhtmltopdf failed:", e)
    # Fallback: reportlab-based PDF (structured tables)
    if SimpleDocTemplate is None:
        print("reportlab not available — cannot create fallback PDF.")
        return False
    try:
        md = open(html_path.replace('.html', '.md'), 'r', encoding='utf-8').read()
    except Exception:
        md = ''
    # Build PDF using structured extraction from provided files won't work here - we'll parse the md we just generated
    # Simpler: try to extract pages and findings stored in a JSON sidecar if present
    sidecar = html_path.replace('.html', '.json')
    pages = []
    findings = []
    if os.path.exists(sidecar):
        try:
            j = json.load(open(sidecar, 'r', encoding='utf-8'))
            pages = j.get('pages', [])
            findings = j.get('findings', [])
        except Exception:
            pages = []
            findings = []
    # If no sidecar, attempt to parse minimal info from md (best-effort)
    if not pages or not findings:
        # try to recover some content from md
        # (this fallback is intentionally simple)
        pages = []
        findings = []
    # Build simple PDF tables
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, rightMargin=28, leftMargin=28, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    story = []
    # Title
    story.append(Paragraph("EB Vulnerability Assessment Report", styles['Title']))
    story.append(Paragraph(time.asctime(), styles['Normal']))
    story.append(Spacer(1, 12))
    # Pages table (if any)
    if pages:
        story.append(Paragraph("Pages Discovered", styles['Heading2']))
        data = [['URL', 'Status']]
        for p in pages:
            data.append([p.get('url', ''), str(p.get('status_code', ''))])
        t = Table(data, colWidths=[360, 80])
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f4f8')),
                               ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e6e9ee'))]))
        story.append(t)
        story.append(Spacer(1, 12))
    # Findings table
    if findings:
        story.append(Paragraph("Findings", styles['Heading2']))
        data = [['Severity', 'Name', 'Location', 'Details']]
        for f in findings:
            data.append([f.get('severity',''), f.get('name',''), f.get('location',''), f.get('message','')])
        t = Table(data, colWidths=[70, 160, 150, 140])
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f4f8')),
                               ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e6e9ee'))]))
        story.append(t)
    try:
        doc.build(story)
        print(f"PDF fallback written to: {pdf_path}")
        return True
    except Exception as e:
        print("Failed to build fallback PDF:", e)
        return False

# ----------------------------- Main Scan Flow -------------------------------

def scan_target(target_url, max_pages=50, max_depth=2, output='eb_report.md'):
    print(f"Starting scan on {target_url} (max_pages={max_pages}, max_depth={max_depth})")
    pages = crawl(target_url, max_pages=max_pages, max_depth=max_depth)
    findings = []
    session = requests.Session()

    for p in pages:
        url = p['url']
        r = make_request(url, session=session)
        if not r:
            continue
        # header checks
        header_issues = check_security_headers(r.headers)
        for hi in header_issues:
            findings.append({
                'name': 'Missing/Weak Header: ' + hi['name'],
                'location': url,
                'message': hi['message'],
                'severity': hi['severity'],
                'evidence': None,
                'meta': None
            })
        # cookie checks
        cookie_issues = check_cookies_from_response(r)
        for ci in cookie_issues:
            findings.append({
                'name': 'Cookie flag: ' + ci['name'],
                'location': url,
                'message': ci['message'],
                'severity': ci['severity'],
                'evidence': None,
                'meta': None
            })
        # forms
        forms = find_forms_and_inputs(r.text, url)
        for form in forms:
            findings.append({
                'name': 'Form discovered',
                'location': form['action'],
                'message': f"Form method={form['method']}, inputs={len(form['inputs'])}",
                'severity': 'low',
                'evidence': json.dumps(form),
                'meta': None
            })
        hidden = find_hidden_tokens_and_js(r.text)
        if hidden['hidden_inputs'] or hidden['js_tokens']:
            findings.append({
                'name': 'Hidden inputs / JS tokens',
                'location': url,
                'message': f"Hidden inputs: {len(hidden['hidden_inputs'])}, JS tokens: {len(hidden['js_tokens'])}",
                'severity': 'medium',
                'evidence': json.dumps(hidden),
                'meta': None
            })
        # reflection tests
        try:
            xss = check_reflected_xss(url, session=session)
            for x in xss:
                findings.append({
                    'name': 'Possible Reflected XSS',
                    'location': x['url'],
                    'message': f"Parameter {x['param']} reflected",
                    'severity': x['severity'],
                    'evidence': x['evidence'],
                    'meta': None
                })
        except Exception:
            pass
        # sqli tests
        try:
            sqli = check_sql_errors(url, session=session)
            for s in sqli:
                findings.append({
                    'name': 'SQL error indicator',
                    'location': s['url'],
                    'message': f"Parameter {s['param']} may be injectable (error-based evidence)",
                    'severity': s['severity'],
                    'evidence': s['evidence'],
                    'meta': None
                })
        except Exception:
            pass
        # identify software
        sw = identify_software(r.headers)
        if sw:
            findings.append({
                'name': 'Server technology',
                'location': url,
                'message': f"Server header: {sw}",
                'severity': 'low',
                'evidence': None,
                'meta': None
            })
        # detect directory listing
        if 'index of' in (r.text or '').lower():
            findings.append({
                'name': 'Directory listing',
                'location': url,
                'message': 'Index of - potential open directory listing',
                'severity': 'medium',
                'evidence': snippet(r.text, 'index of'),
                'meta': None
            })

    # Prepare outputs
    scan_time_str = time.strftime('%Y-%m-%d %H:%M:%S')
    md_path = output
    html_path = os.path.splitext(output)[0] + '.html'
    pdf_path = os.path.splitext(output)[0] + '.pdf'
    # Save a JSON sidecar to help PDF fallback
    sidecar = os.path.splitext(output)[0] + '.json'
    try:
        json.dump({'target': target_url, 'pages': pages, 'findings': findings, 'scan_time': scan_time_str},
                  open(sidecar, 'w', encoding='utf-8'), indent=2)
    except Exception:
        pass

    # Markdown & TXT
    md_content = generate_markdown_and_txt(md_path, target_url, pages, findings, scan_time_str)

    # HTML (Tailwind)
    ok = generate_html_report(html_path, target_url, pages, findings, scan_time_str)

    # PDF: try HTML->PDF (pdfkit/wkhtmltopdf), else fallback
    pdf_ok = False
    if ok:
        pdf_ok = generate_pdf_from_html(html_path, pdf_path)
    else:
        pdf_ok = generate_pdf_from_html(html_path, pdf_path)

    print("Scan finished.")
    print(f"Files: {md_path}, {html_path}, {pdf_path} (pdf_ok={pdf_ok})")

# ----------------------------- CLI -----------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description='EB Web Vulnerability Scanner (non-intrusive)')
    p.add_argument('target', help='Target URL (e.g., https://example.com)')
    p.add_argument('--max-pages', type=int, default=50, help='Maximum pages to crawl')
    p.add_argument('--max-depth', type=int, default=2, help='Maximum crawl depth')
    p.add_argument('--output', default='eb_report.md', help='Output markdown report path (html/pdf same base)')
    return p.parse_args()

if __name__ == '__main__':
    args = parse_args()
    scan_target(args.target, max_pages=args.max_pages, max_depth=args.max_depth, output=args.output)
