#!/usr/bin/env python3

import argparse
import asyncio
import http.client
import json
import os
import re
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse


# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[38;5;82m"
    RED     = "\033[38;5;196m"
    YELLOW  = "\033[38;5;220m"
    CYAN    = "\033[38;5;51m"
    GRAY    = "\033[38;5;240m"
    WHITE   = "\033[38;5;255m"
    ORANGE  = "\033[38;5;208m"
    BLUE    = "\033[38;5;39m"
    MAGENTA = "\033[38;5;213m"
    PINK    = "\033[38;5;205m"


# ─────────────────────────────────────────────
#  Severity levels
# ─────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.CYAN,
    "INFO":     C.GRAY,
}


# ─────────────────────────────────────────────
#  Common JS paths to fuzz
# ─────────────────────────────────────────────
JS_FUZZ_PATHS = [
    # Bundlers / build tools
    "main.js", "app.js", "index.js", "bundle.js", "vendor.js",
    "chunk.js", "runtime.js", "polyfills.js", "common.js",
    "webpack.js", "app.bundle.js", "main.bundle.js",
    # Frameworks
    "angular.js", "react.js", "vue.js", "ember.js",
    # Static dirs
    "static/js/main.js", "static/js/app.js", "static/js/bundle.js",
    "assets/js/app.js", "assets/js/main.js", "assets/application.js",
    "js/app.js", "js/main.js", "js/index.js", "js/bundle.js",
    "js/vendor.js", "js/common.js", "js/utils.js", "js/config.js",
    "js/api.js", "js/auth.js", "js/routes.js", "js/router.js",
    # Source maps (can reveal original source)
    "main.js.map", "app.js.map", "bundle.js.map",
    "static/js/main.js.map", "assets/js/app.js.map",
    # Next.js / Nuxt / SPA
    "_next/static/chunks/main.js",
    "_next/static/chunks/pages/index.js",
    "_next/static/chunks/webpack.js",
    "nuxt/static/js/app.js",
    # Config / env leaks
    "config.js", "settings.js", "env.js", "environment.js",
    "js/config.js", "js/settings.js", "js/env.js",
    "dist/js/app.js", "dist/main.js", "dist/bundle.js",
    # API clients
    "js/api.js", "js/client.js", "js/service.js",
    "src/api.js", "src/client.js", "src/config.js",
    # Admin panels
    "admin/js/app.js", "admin/main.js", "dashboard/js/app.js",
    # Swagger / API docs embedded JS
    "swagger-ui.js", "swagger-ui-bundle.js",
    # Generic numbered chunks (webpack)
    *[f"static/js/{i}.chunk.js" for i in range(10)],
    *[f"js/{i}.js" for i in range(5)],
]


# ─────────────────────────────────────────────
#  Secret patterns
# ─────────────────────────────────────────────
# Each entry: (category, severity, compiled_regex, group_index_for_value)
SECRET_PATTERNS = [
    # ── Endpoints / Routes ──────────────────────────────────────────────
    ("endpoint",    "INFO",     re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request)|XMLHttpRequest|\.open\s*\(|url\s*[:=]\s*|href\s*[:=]\s*|api\s*[:=]\s*|baseURL\s*[:=]\s*|endpoint\s*[:=]\s*)"""
        r"""['"` ]*((?:/[a-zA-Z0-9_\-/.{}?=&%#]+){1,})['"` ]*""", re.I), 1),

    ("endpoint",    "INFO",     re.compile(
        r"""['"`]((?:https?://)[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_\-/.{}?=&%#]*)+)['"`]""", re.I), 1),

    ("route",       "INFO",     re.compile(
        r"""(?:path|route|to)\s*[:=]\s*['"`]((?:/[a-zA-Z0-9_\-/.{}:*]+)+)['"`]""", re.I), 1),

    # ── AWS ─────────────────────────────────────────────────────────────
    ("aws_key",         "CRITICAL", re.compile(r"""(?:AKIA|AIPA|AIFA|AROA|ASCA|ASIA)[A-Z0-9]{16}"""), 0),
    ("aws_secret",      "CRITICAL", re.compile(
        r"""(?:aws.{0,20}secret|secret.{0,20}aws|aws_secret_access_key)\s*[:=]\s*['"`]?([A-Za-z0-9/+=]{40})['"`]?""", re.I), 1),
    ("aws_bucket",      "HIGH",     re.compile(
        r"""(?:https?://)?([a-zA-Z0-9.\-]+)\.s3(?:[\.\-][a-zA-Z0-9\-]+)?\.amazonaws\.com""", re.I), 0),

    # ── Google ───────────────────────────────────────────────────────────
    ("google_api_key",  "CRITICAL", re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), 0),
    ("google_oauth",    "HIGH",     re.compile(r"""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"""), 0),
    ("firebase_url",    "HIGH",     re.compile(r"""https://[a-zA-Z0-9\-]+\.firebaseio\.com""", re.I), 0),
    ("firebase_key",    "HIGH",     re.compile(r"""(?:firebase|FIREBASE).{0,20}(?:key|token|secret)\s*[:=]\s*['"`]?([A-Za-z0-9_\-]{20,})['"`]?""", re.I), 1),

    # ── Azure ────────────────────────────────────────────────────────────
    ("azure_storage",   "HIGH",     re.compile(
        r"""DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+""", re.I), 0),
    ("azure_tenant",    "MEDIUM",   re.compile(
        r"""(?:tenant|tenantId)\s*[:=]\s*['"`]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]?""", re.I), 1),

    # ── JWT ──────────────────────────────────────────────────────────────
    ("jwt_token",       "CRITICAL", re.compile(
        r"""eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"""), 0),
    ("jwt_secret",      "CRITICAL", re.compile(
        r"""(?:jwt.{0,10}secret|secret.{0,10}jwt|jwtSecret|JWT_SECRET)\s*[:=]\s*['"`]([^'"` \n]{8,})['"`]""", re.I), 1),

    # ── Generic API Keys / Tokens ────────────────────────────────────────
    ("api_key",         "HIGH",     re.compile(
        r"""(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,64})['"`]""", re.I), 1),
    ("secret_key",      "HIGH",     re.compile(
        r"""(?:secret[_\-]?key|secretkey|app[_\-]?secret|client[_\-]?secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-+/=]{16,})['"`]""", re.I), 1),
    ("bearer_token",    "CRITICAL", re.compile(
        r"""(?:bearer|token|auth[_\-]?token|access[_\-]?token)\s*[:=]\s*['"`]([A-Za-z0-9_\-+/=.]{20,})['"`]""", re.I), 1),
    ("auth_header",     "HIGH",     re.compile(
        r"""[Aa]uthorization\s*[:=]\s*['"`]?(Bearer|Basic|Token)\s+([A-Za-z0-9_\-+/=.]{10,})['"`]?""", re.I), 0),

    # ── Credentials ──────────────────────────────────────────────────────
    ("password",        "CRITICAL", re.compile(
        r"""(?:password|passwd|pwd|pass)\s*[:=]\s*['"`]([^'"` \n]{4,})['"`]""", re.I), 1),
    ("username",        "HIGH",     re.compile(
        r"""(?:username|user|login|usr)\s*[:=]\s*['"`]([^'"` \n]{3,})['"`]""", re.I), 1),
    ("email_cred",      "HIGH",     re.compile(
        r"""['"`]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"`]"""), 1),

    # ── Database ─────────────────────────────────────────────────────────
    ("db_connection",   "CRITICAL", re.compile(
        r"""(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|redis|mssql|oracle|jdbc)://[^\s'"` ]+""", re.I), 0),
    ("db_password",     "CRITICAL", re.compile(
        r"""(?:DB_PASS|DATABASE_PASSWORD|DB_PASSWORD|MONGO_PASS)\s*[:=]\s*['"`]?([^'"` \n]{4,})['"`]?""", re.I), 1),

    # ── Private Keys / Certificates ──────────────────────────────────────
    ("private_key",     "CRITICAL", re.compile(
        r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""), 0),
    ("ssh_key",         "CRITICAL", re.compile(
        r"""ssh-(?:rsa|dss|ed25519|ecdsa)\s+AAAA[A-Za-z0-9+/]+"""), 0),

    # ── OAuth / Social ───────────────────────────────────────────────────
    ("github_token",    "CRITICAL", re.compile(r"""gh[pousr]_[A-Za-z0-9]{36}"""), 0),
    ("slack_token",     "CRITICAL", re.compile(r"""xox[baprs]-[A-Za-z0-9\-]{10,}"""), 0),
    ("stripe_key",      "CRITICAL", re.compile(r"""(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"""), 0),
    ("twilio_sid",      "HIGH",     re.compile(r"""AC[a-zA-Z0-9]{32}"""), 0),
    ("sendgrid_key",    "HIGH",     re.compile(r"""SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"""), 0),
    ("mailgun_key",     "HIGH",     re.compile(r"""key-[a-zA-Z0-9]{32}"""), 0),
    ("heroku_key",      "HIGH",     re.compile(r"""[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""), 0),
    ("npm_token",       "CRITICAL", re.compile(r"""npm_[A-Za-z0-9]{36}"""), 0),
    ("discord_token",   "CRITICAL", re.compile(r"""[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}"""), 0),
    ("telegram_token",  "CRITICAL", re.compile(r"""[0-9]{9}:[A-Za-z0-9_\-]{35}"""), 0),

    # ── Environment / Config leaks ───────────────────────────────────────
    ("env_variable",    "MEDIUM",   re.compile(
        r"""process\.env\.([A-Z_]{3,})\s*(?:\|\|\s*['"`]([^'"` ]{1,})['"`])?"""), 0),
    ("hardcoded_ip",    "MEDIUM",   re.compile(
        r"""['"`]((?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)(?:\d{1,3}\.){1,2}\d{1,3}(?::\d+)?)['"`]"""), 1),
    ("internal_url",    "MEDIUM",   re.compile(
        r"""['"`](https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?[/a-zA-Z0-9_\-.]*)['"`]""", re.I), 1),

    # ── Crypto / Hashes ──────────────────────────────────────────────────
    ("crypto_key",      "HIGH",     re.compile(
        r"""(?:encrypt|decrypt|cipher|aes|des|rsa).{0,20}(?:key|secret|iv)\s*[:=]\s*['"`]([A-Za-z0-9+/=]{16,})['"`]""", re.I), 1),
    ("hash_secret",     "HIGH",     re.compile(
        r"""(?:hmac|hash|salt)\s*[:=]\s*['"`]([A-Za-z0-9_\-+/=]{16,})['"`]""", re.I), 1),

    # ── Debug / Dev artifacts ────────────────────────────────────────────
    ("debug_flag",      "LOW",      re.compile(
        r"""(?:debug|DEBUG|isDev|isProduction|NODE_ENV)\s*[:=]\s*(?:true|false|['"`](?:development|production|staging)['"`])""", re.I), 0),
    ("console_log",     "LOW",      re.compile(
        r"""console\.(?:log|warn|error|debug)\s*\(\s*['"`]([^'"` \n]{10,})['"`]""", re.I), 1),
    ("todo_comment",    "LOW",      re.compile(
        r"""//\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE)\s*[:—\-]?\s*(.{10,80})""", re.I), 1),

    # ── Source map ───────────────────────────────────────────────────────
    ("source_map",      "MEDIUM",   re.compile(
        r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)""", re.I), 1),
]


# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────
@dataclass
class Finding:
    category:  str
    severity:  str
    value:     str
    line:      int
    source:    str
    context:   str = ""


@dataclass
class JSFile:
    url:      str
    source:   str          # "crawled" | "fuzzed" | "local" | "inline"
    size:     int = 0
    findings: List[Finding] = field(default_factory=list)


# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
def print_banner():
    print(f"""
{C.YELLOW}{C.BOLD}\
    ██╗███████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗
    ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║
    ██║███████╗██║     ██████╔╝███████║██║ █╗ ██║██║
██  ██║╚════██║██║     ██╔══██╗██╔══██║██║███╗██║██║
╚█████╔╝███████║╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
 ╚════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
{C.RESET}{C.GRAY}  JavaScript Endpoint & Secrets Extractor v1.0  —  zero deps, pure Python{C.RESET}
""")


def print_config(args, mode):
    sep = f"{C.GRAY}{'─' * 64}{C.RESET}"
    now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    print(sep)
    print(f"  {C.GRAY}Mode      {C.RESET}: {C.YELLOW}jscrawl{C.RESET}")
    if mode == "url":
        print(f"  {C.GRAY}Target    {C.RESET}: {C.WHITE}{args.url}{C.RESET}")
        print(f"  {C.GRAY}Crawl     {C.RESET}: {C.WHITE}{'yes' if not args.no_crawl else 'no'}{C.RESET}")
        print(f"  {C.GRAY}Fuzz      {C.RESET}: {C.WHITE}{'yes' if not args.no_fuzz else 'no'}{C.RESET}")
    else:
        print(f"  {C.GRAY}Input     {C.RESET}: {C.WHITE}{args.local}{C.RESET}")
    print(f"  {C.GRAY}Threads   {C.RESET}: {C.WHITE}{args.threads}{C.RESET}")
    print(f"  {C.GRAY}Timeout   {C.RESET}: {C.WHITE}{args.timeout}s{C.RESET}")
    print(f"  {C.GRAY}Min sev   {C.RESET}: {C.WHITE}{args.min_severity}{C.RESET}")
    print(f"  {C.GRAY}Started   {C.RESET}: {C.WHITE}{now}{C.RESET}")
    print(sep)
    print()


# ─────────────────────────────────────────────
#  HTTP helpers
# ─────────────────────────────────────────────
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _fetch(url: str, timeout: float) -> Tuple[Optional[int], Optional[bytes]]:
    parsed  = urlparse(url)
    use_ssl = parsed.scheme == "https"
    host    = parsed.hostname
    port    = parsed.port or (443 if use_ssl else 80)
    path    = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        if use_ssl:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_make_ssl_ctx())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={
            "User-Agent":      "Mozilla/5.0 jscrawl/1.0",
            "Accept":          "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection":      "close",
        })
        resp   = conn.getresponse()
        status = resp.status
        body   = resp.read(5_000_000)  # 5 MB cap
        conn.close()
        return status, body
    except Exception:
        return None, None


async def fetch_async(url: str, timeout: float, loop, semaphore) -> Tuple[Optional[int], Optional[bytes]]:
    async with semaphore:
        return await loop.run_in_executor(None, _fetch, url, timeout)


# ─────────────────────────────────────────────
#  JS discovery
# ─────────────────────────────────────────────
JS_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*['"]([^'"]+\.js(?:[?#][^'"]*)?)['"]\s*""", re.I
)
INLINE_JS_RE = re.compile(r"""<script(?:[^>]*)>(.*?)</script>""", re.I | re.S)


def extract_js_urls_from_html(html: str, base_url: str) -> List[str]:
    urls = []
    for m in JS_SRC_RE.finditer(html):
        src = m.group(1)
        full = urljoin(base_url, src)
        # Only follow same-origin or relative
        if urlparse(full).netloc == urlparse(base_url).netloc or src.startswith("/"):
            urls.append(full)
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


def extract_js_urls_from_js(content: str, base_url: str) -> List[str]:
    """Find dynamically imported or referenced .js files inside JS content."""
    urls = []
    patterns = [
        re.compile(r"""import\s*\(['"](.*?\.js)['"]\)"""),
        re.compile(r"""require\s*\(['"](.*?\.js)['"]\)"""),
        re.compile(r"""['"`]((?:/[a-zA-Z0-9_\-/]+)+\.js)['"`]"""),
        re.compile(r"""loadScript\s*\(['"](.*?\.js)['"]\)"""),
    ]
    for p in patterns:
        for m in p.finditer(content):
            src  = m.group(1)
            full = urljoin(base_url, src)
            if urlparse(full).netloc == urlparse(base_url).netloc:
                urls.append(full)
    return list(dict.fromkeys(urls))


# ─────────────────────────────────────────────
#  Secret extraction
# ─────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MIN_VALUE_LEN = 3
DEDUP_WINDOW = 500  # characters around match for context


def _line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def extract_secrets(content: str, source: str, min_severity: str) -> List[Finding]:
    findings   = []
    seen       = set()
    min_order  = SEV_ORDER.get(min_severity, 4)

    for category, severity, pattern, group in SECRET_PATTERNS:
        if SEV_ORDER.get(severity, 4) > min_order:
            continue
        for m in pattern.finditer(content):
            try:
                raw_value = m.group(group) if group < len(m.groups()) + 1 else m.group(0)
            except IndexError:
                raw_value = m.group(0)

            if not raw_value or len(raw_value.strip()) < MIN_VALUE_LEN:
                continue

            value = raw_value.strip()

            # Deduplicate: same category + value
            key = (category, value[:80])
            if key in seen:
                continue
            seen.add(key)

            # Skip obvious false positives
            if _is_false_positive(category, value):
                continue

            line    = _line_number(content, m.start())
            start   = max(0, m.start() - 60)
            end     = min(len(content), m.end() + 60)
            context = content[start:end].replace("\n", " ").replace("\r", "").strip()

            findings.append(Finding(
                category=category,
                severity=severity,
                value=value,
                line=line,
                source=source,
                context=context,
            ))

    return findings


def _is_false_positive(category: str, value: str) -> bool:
    FP_VALUES = {
        "true", "false", "null", "undefined", "none", "string", "number",
        "boolean", "object", "function", "example", "test", "placeholder",
        "your_key_here", "your-key-here", "xxxxxxxx", "aaaaaaaa",
        "changeme", "todo", "fixme", "n/a", "na", "empty",
    }
    if value.lower() in FP_VALUES:
        return True
    # All same char
    if len(set(value.lower())) <= 2 and len(value) > 4:
        return True
    # Generic variable names
    if category == "username" and value.lower() in {
        "admin", "user", "username", "name", "login", "email", "string",
        "text", "value", "data", "input", "field",
    }:
        return True
    if category == "password" and value.lower() in {
        "password", "pass", "pwd", "secret", "string", "text",
        "value", "input", "mypassword", "yourpassword",
    }:
        return True
    return False


# ─────────────────────────────────────────────
#  Inline JS extraction
# ─────────────────────────────────────────────
def extract_inline_js(html: str) -> List[str]:
    blocks = []
    for m in INLINE_JS_RE.finditer(html):
        content = m.group(1).strip()
        if len(content) > 50:
            blocks.append(content)
    return blocks


# ─────────────────────────────────────────────
#  Output
# ─────────────────────────────────────────────
def sev_label(severity: str) -> str:
    color = SEV_COLOR.get(severity, C.GRAY)
    return f"{color}{C.BOLD}[{severity:<8}]{C.RESET}"


def _wrap_value(value: str, width: int = 90) -> List[str]:
    """Break a long value into lines of at most `width` chars."""
    lines = []
    while len(value) > width:
        lines.append(value[:width])
        value = value[width:]
    lines.append(value)
    return lines


# Human-readable descriptions for each category
CATEGORY_DESC: Dict[str, str] = {
    "endpoint":       "API endpoint / URL encontrado no código",
    "route":          "Rota interna da aplicação",
    "aws_key":        "Chave de acesso AWS (Access Key ID)",
    "aws_secret":     "Segredo de acesso AWS",
    "aws_bucket":     "Bucket S3 da Amazon",
    "google_api_key": "Chave de API do Google",
    "google_oauth":   "Client ID OAuth do Google",
    "firebase_url":   "URL de banco Firebase",
    "firebase_key":   "Chave/token do Firebase",
    "azure_storage":  "String de conexão Azure Storage",
    "azure_tenant":   "Tenant ID do Azure",
    "jwt_token":      "Token JWT (sessão/autenticação)",
    "jwt_secret":     "Segredo usado para assinar JWTs",
    "api_key":        "Chave de API genérica",
    "secret_key":     "Chave secreta da aplicação",
    "bearer_token":   "Token Bearer (cabeçalho Authorization)",
    "auth_header":    "Cabeçalho de autenticação HTTP",
    "password":       "Senha em texto claro",
    "username":       "Nome de usuário em texto claro",
    "email_cred":     "Endereço de e-mail exposto",
    "db_connection":  "String de conexão com banco de dados",
    "db_password":    "Senha de banco de dados",
    "private_key":    "Chave privada (RSA/EC/SSH)",
    "ssh_key":        "Chave pública SSH",
    "github_token":   "Token de acesso ao GitHub",
    "slack_token":    "Token do Slack",
    "stripe_key":     "Chave da API Stripe (pagamentos)",
    "twilio_sid":     "SID/Token Twilio (SMS/voz)",
    "sendgrid_key":   "Chave da API SendGrid (e-mail)",
    "mailgun_key":    "Chave da API Mailgun (e-mail)",
    "heroku_key":     "Chave/UUID Heroku (pode ser ID de app)",
    "npm_token":      "Token de autenticação do NPM",
    "discord_token":  "Token de bot do Discord",
    "telegram_token": "Token de bot do Telegram",
    "env_variable":   "Variável de ambiente exposta no bundle",
    "hardcoded_ip":   "IP interno hardcoded",
    "internal_url":   "URL de ambiente local/interno",
    "crypto_key":     "Chave criptográfica (AES/DES/RSA)",
    "hash_secret":    "Segredo de HMAC/hash",
    "debug_flag":     "Flag de debug ou ambiente exposto",
    "console_log":    "console.log com dado sensível",
    "todo_comment":   "Comentário TODO/FIXME no código",
    "source_map":     "Source map referenciado (expõe código-fonte)",
}


def print_finding(f: Finding):
    sc  = SEV_COLOR.get(f.severity, C.GRAY)

    # Linha 1: badge + categoria + valor truncado + :linha
    val = f.value if len(f.value) <= 72 else f.value[:69] + "..."
    val = re.sub(r"\s+", " ", val).strip()
    line_str = f"  {C.DIM}:{f.line}{C.RESET}" if f.line else ""

    print(
        f"  {sev_label(f.severity)} "
        f"{sc}{f.category:<18}{C.RESET} "
        f"{C.WHITE}{val}{C.RESET}"
        f"{line_str}"
    )

    # Linha 2: descrição da categoria
    desc = CATEGORY_DESC.get(f.category, "")
    if desc:
        print(f"  {C.GRAY}  ↳ {desc}{C.RESET}")

    # Linha 3: contexto com valor destacado
    if f.context and f.context.strip():
        ctx = re.sub(r"\s+", " ", f.context).strip()
        val_clean = re.sub(r"\s+", " ", f.value).strip()
        if val_clean in ctx:
            ctx = ctx.replace(
                val_clean,
                f"{C.YELLOW}{C.BOLD}{val_clean}{C.RESET}{C.DIM}",
                1
            )
        MAX_CTX = 110
        display_ctx = ctx if len(ctx) <= MAX_CTX else ctx[:MAX_CTX] + "..."
        print(f"  {C.GRAY}  └─{C.RESET} {C.DIM}{display_ctx}{C.RESET}")

    print()  # espaço entre findings


# Categories treated as "endpoints" (grouped in a compact table, not mixed with secrets)
ENDPOINT_CATEGORIES = {"endpoint", "route"}



def print_endpoints_table(findings: List[Finding]):
    ep = [f for f in findings if f.category in ENDPOINT_CATEGORIES]
    if not ep:
        return
    print(f"  {C.CYAN}— Endpoints / URLs encontrados  ({len(ep)} total){C.RESET}")
    print()
    print(f"  {C.GRAY}  URLs completas:{C.RESET}")
    for i, f in enumerate(ep, 1):
        val = f.value if len(f.value) <= 90 else f.value[:87] + "..."
        print(f"  {C.GRAY}  {i:>3}.{C.RESET} {C.CYAN}{val}{C.RESET}"
              + (f"  {C.DIM}(linha {f.line}){C.RESET}" if f.line else ""))
    print()



def print_js_findings(jsfile: JSFile):
    secrets = [f for f in jsfile.findings if f.category not in ENDPOINT_CATEGORIES]
    eps     = [f for f in jsfile.findings if f.category in ENDPOINT_CATEGORIES]

    if secrets:
        print(f"\n  {C.ORANGE}— Segredos / dados sensíveis —{C.RESET}")
        for f in secrets:
            print_finding(f)
    if eps:
        print_endpoints_table(jsfile.findings)



def print_js_header(jsfile: JSFile):
    src_color = {"crawled": C.GREEN, "fuzzed": C.CYAN,
                 "local": C.MAGENTA, "inline": C.YELLOW}.get(jsfile.source, C.GRAY)
    label    = jsfile.source.upper()
    size_str = f"{jsfile.size/1024:.1f}KB" if jsfile.size >= 1024 else f"{jsfile.size}B"
    url      = jsfile.url if len(jsfile.url) <= 80 else "..." + jsfile.url[-77:]
    n_sec    = sum(1 for f in jsfile.findings if f.category not in ENDPOINT_CATEGORIES)
    n_ep     = sum(1 for f in jsfile.findings if f.category in ENDPOINT_CATEGORIES)
    parts    = []
    if n_sec: parts.append(f"{C.ORANGE}{n_sec} secret(s){C.RESET}")
    if n_ep:  parts.append(f"{C.CYAN}{n_ep} endpoint(s){C.RESET}")
    counts   = "  ".join(parts) if parts else f"{C.GRAY}0 achados{C.RESET}"

    # ← separador + layout em duas linhas
    print(f"\n{C.GRAY}  {'─' * 68}{C.RESET}")
    print(f"  {src_color}{C.BOLD}{label:<8}{C.RESET}  {C.WHITE}{url}{C.RESET}")
    print(f"  {C.DIM}{size_str:<10}{C.RESET}  {counts}")
    print(f"{C.GRAY}  {'─' * 68}{C.RESET}")


def print_summary(js_files: List[JSFile]):
    all_findings = [f for js in js_files for f in js.findings]
    by_sev: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}

    for f in all_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

    print(f"\n  {C.BOLD}{C.WHITE}── RESUMO {C.RESET}{C.DIM}({len(js_files)} arquivo(s) · {len(all_findings)} achado(s)){C.RESET}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        color = SEV_COLOR.get(sev, C.GRAY)
        bar   = "█" * min(count, 30)
        print(f"  {color}{sev:<10}{C.RESET} {color}{bar}{C.RESET} {C.WHITE}{count}{C.RESET}")

    if by_cat:
        print()
        for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
            color = C.GRAY if count < 3 else (C.ORANGE if count < 10 else C.RED)
            print(f"  {color}{cat:<22}{C.RESET} {C.WHITE}{count}{C.RESET}")
    print()

def save_output(js_files: List[JSFile], output_path: str, fmt: str):
    all_findings = [f for js in js_files for f in js.findings]
    if fmt == "json":
        data = []
        for js in js_files:
            for f in js.findings:
                data.append({
                    "source":   js.url,
                    "js_type":  js.source,
                    "category": f.category,
                    "severity": f.severity,
                    "line":     f.line,
                    "value":    f.value,
                    "context":  f.context,
                })
        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2)
    else:
        with open(output_path, "w") as fh:
            fh.write("=" * 70 + "\n")
            fh.write("  jscrawl — Relatório de Achados\n")
            fh.write(f"  Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write("=" * 70 + "\n\n")
            for js in js_files:
                if not js.findings:
                    continue
                fh.write(f"\n{'━' * 70}\n")
                fh.write(f"  [{js.source.upper()}]  {js.url}\n")
                fh.write(f"{'━' * 70}\n\n")
                for f in js.findings:
                    desc = CATEGORY_DESC.get(f.category, "")
                    fh.write(f"  ┌─ [{f.severity}]  {f.category}\n")
                    if desc:
                        fh.write(f"  │   {desc}\n")
                    fh.write(f"  │   Linha   : {f.line}\n")
                    fh.write(f"  │   Valor   : {f.value}\n")
                    if f.context and f.context.strip() != f.value.strip():
                        fh.write(f"  │   Contexto: {f.context}\n")
                    fh.write(f"  └{'─' * 60}\n\n")

    print(f"\n  {C.GRAY}Results saved → {output_path}{C.RESET}")


# ─────────────────────────────────────────────
#  Core logic
# ─────────────────────────────────────────────
async def process_js_content(
    content: str,
    url: str,
    source: str,
    base_url: str,
    min_severity: str,
    visited_js: Set[str],
) -> Tuple[JSFile, List[str]]:
    js = JSFile(url=url, source=source, size=len(content.encode()))
    js.findings = extract_secrets(content, url, min_severity)

    # Discover more JS references within this file
    new_js_urls = [
        u for u in extract_js_urls_from_js(content, base_url)
        if u not in visited_js
    ]
    return js, new_js_urls


async def run_url(args):
    base_url    = args.url.rstrip("/")
    visited_js  = set()
    js_queue    = asyncio.Queue()
    js_files    = []
    loop        = asyncio.get_event_loop()
    semaphore   = asyncio.Semaphore(args.threads)

    print_banner()
    print_config(args, "url")

    # ── Step 1: Fetch HTML and extract linked JS ──────────────────────
    if not args.no_crawl:
        print(f"  {C.GRAY}[*] Fetching base page...{C.RESET}")
        status, body = await fetch_async(base_url, args.timeout, loop, semaphore)
        if body:
            html = body.decode("utf-8", errors="replace")
            linked = extract_js_urls_from_html(html, base_url)
            print(f"  {C.GRAY}[*] Found {len(linked)} linked JS file(s){C.RESET}")
            for u in linked:
                if u not in visited_js:
                    await js_queue.put(("crawled", u))
                    visited_js.add(u)

            # Inline JS blocks
            inline_blocks = extract_inline_js(html)
            if inline_blocks:
                print(f"  {C.GRAY}[*] Found {len(inline_blocks)} inline <script> block(s){C.RESET}")
                for i, block in enumerate(inline_blocks):
                    fake_url = f"{base_url}#inline-{i}"
                    jsf = JSFile(url=fake_url, source="inline", size=len(block.encode()))
                    jsf.findings = extract_secrets(block, fake_url, args.min_severity)
                    if jsf.findings:
                        js_files.append(jsf)
                        print_js_header(jsf)
                        print_js_findings(jsf)

    # ── Step 2: Fuzz common JS paths ─────────────────────────────────
    if not args.no_fuzz:
        print(f"\n  {C.GRAY}[*] Fuzzing {len(JS_FUZZ_PATHS)} common JS paths...{C.RESET}")
        fuzz_tasks = []
        for path in JS_FUZZ_PATHS:
            url = f"{base_url}/{path.lstrip('/')}"
            if url not in visited_js:
                fuzz_tasks.append(url)

        async def check_fuzz(url):
            status, body = await fetch_async(url, args.timeout, loop, semaphore)
            if status == 200 and body and len(body) > 100:
                ct = body[:500].decode("utf-8", errors="replace")
                # Must look like JS (not HTML error page)
                if not re.search(r"<html|<!doctype", ct, re.I):
                    if url not in visited_js:
                        visited_js.add(url)
                        await js_queue.put(("fuzzed", url))

        await asyncio.gather(*[check_fuzz(u) for u in fuzz_tasks])
        print(f"  {C.GRAY}[*] Fuzz complete — {js_queue.qsize()} files queued{C.RESET}")

    # ── Step 3: Process JS queue ──────────────────────────────────────
    print(f"\n  {C.GRAY}[*] Analysing JS files...{C.RESET}\n")

    async def process_url_entry(source, url):
        status, body = await fetch_async(url, args.timeout, loop, semaphore)
        if not body or status != 200:
            return
        content  = body.decode("utf-8", errors="replace")
        jsf, new = await process_js_content(
            content, url, source, base_url, args.min_severity, visited_js
        )
        if jsf.findings:
            print_js_header(jsf)
            print_js_findings(jsf)
        js_files.append(jsf)

        # Queue newly discovered JS files
        for new_url in new:
            if new_url not in visited_js:
                visited_js.add(new_url)
                await js_queue.put(("crawled", new_url))

    # Drain queue iteratively (new items may be added while processing)
    workers = []
    while not js_queue.empty() or workers:
        while not js_queue.empty():
            source, url = await js_queue.get()
            task = asyncio.create_task(process_url_entry(source, url))
            workers.append(task)

        if workers:
            done, workers_set = await asyncio.wait(
                workers, return_when=asyncio.FIRST_COMPLETED
            )
            workers = list(workers_set)

    print_summary(js_files)

    if args.output:
        save_output(js_files, args.output, args.format)


async def run_local(args):
    print_banner()
    print_config(args, "local")

    local_path = Path(args.local)
    js_files   = []

    if local_path.is_file():
        paths = [local_path]
    elif local_path.is_dir():
        paths = list(local_path.rglob("*.js")) + list(local_path.rglob("*.js.map"))
    else:
        print(f"\n  {C.RED}[!] Path not found: {args.local}{C.RESET}\n")
        sys.exit(1)

    print(f"  {C.GRAY}[*] Found {len(paths)} JS file(s){C.RESET}\n")

    for path in paths:
        try:
            content = path.read_text(errors="replace")
        except Exception as e:
            print(f"  {C.RED}[!] Cannot read {path}: {e}{C.RESET}")
            continue

        jsf = JSFile(
            url=str(path),
            source="local",
            size=path.stat().st_size,
        )
        jsf.findings = extract_secrets(content, str(path), args.min_severity)

        if jsf.findings:
            print_js_header(jsf)
            print_js_findings(jsf)

        js_files.append(jsf)

    print_summary(js_files)

    if args.output:
        save_output(js_files, args.output, args.format)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="jscrawl",
        description="JavaScript Endpoint & Secrets Extractor — zero deps, pure Python",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url",   metavar="URL",  help="Target URL to crawl and fuzz")
    group.add_argument("--local", metavar="PATH", help="Local .js file or directory to analyse")

    parser.add_argument("-t", "--threads",      type=int, default=30,
                        help="Concurrent HTTP workers (default: 30)")
    parser.add_argument("--timeout",            type=int, default=8,
                        help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--no-crawl",           action="store_true",
                        help="Skip HTML page crawl, only fuzz paths")
    parser.add_argument("--no-fuzz",            action="store_true",
                        help="Skip path fuzzing, only crawl linked JS")
    parser.add_argument("--min-severity",       default="INFO",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to display (default: INFO)")
    parser.add_argument("-o", "--output",       metavar="FILE",
                        help="Save results to file")
    parser.add_argument("--format",             default="txt", choices=["txt", "json"],
                        help="Output format: txt or json (default: txt)")

    args = parser.parse_args()

    try:
        if args.url:
            asyncio.run(run_url(args))
        else:
            asyncio.run(run_local(args))
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Interrupted.{C.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
