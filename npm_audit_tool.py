#!/usr/bin/env python3
"""
NPM Supply Chain Vulnerability Audit Tool
==========================================
Standalone CLI tool for detecting NPM supply chain vulnerabilities.

Capabilities:
  - Detect 2025 Qix/DuckDB supply chain compromised package versions
  - Scan inline JS for crypto-wallet drainer malware patterns
  - Detect browser API hook injection (window.fetch / XHR / ethereum)
  - Detect JS obfuscation (hex variable names, high-entropy blocks)
  - Audit package.json files for dangerous version specs & install hooks
  - Query OSV.dev for live CVE data (no API key required)
  - Check NPM registry for deprecated / outdated packages
  - Detect typosquatting against popular NPM package names

Usage:
  python npm_audit_tool.py --url https://example.com
  python npm_audit_tool.py --file ./package.json
  python npm_audit_tool.py --url https://example.com --file ./package.json
  python npm_audit_tool.py --url https://example.com --json
  python npm_audit_tool.py --url https://example.com --output report.json

Research:
  Based on analysis of the 2025 supply chain attack documented by:
  - The Hacker News (Sep 2025): 20 popular npm packages compromised via
    phishing/AiTM attack on maintainer Josh Junon (Qix).
  - Socket Security: https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack
  - Aikido Security: https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised
"""

import argparse
import json
import math
import os
import re
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ── ANSI colours ──────────────────────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True)
    _C = {
        "CRITICAL": "\033[1;31m",   # bold red
        "HIGH":     "\033[0;31m",   # red
        "MEDIUM":   "\033[0;33m",   # yellow
        "LOW":      "\033[0;36m",   # cyan
        "OK":       "\033[0;32m",   # green
        "BOLD":     "\033[1m",
        "DIM":      "\033[2m",
        "RESET":    "\033[0m",
    }
except ImportError:
    _C = {k: "" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "OK", "BOLD", "DIM", "RESET")}


def _color(severity: str, text: str) -> str:
    return f"{_C.get(severity, '')}{text}{_C['RESET']}"


# ══════════════════════════════════════════════════════════════════════════════
# DATA — 2025 Supply Chain Compromised Versions
# ══════════════════════════════════════════════════════════════════════════════
SUPPLY_CHAIN_COMPROMISED = {
    # Qix account takeover (phishing/AiTM — Sep 2025)
    "ansi-regex":                ["6.2.1"],
    "ansi-styles":               ["6.2.2"],
    "backslash":                 ["0.2.1"],
    "chalk":                     ["5.6.1"],
    "chalk-template":            ["1.1.1"],
    "color-convert":             ["3.1.1"],
    "color-name":                ["2.0.1"],
    "color-string":              ["2.1.1"],
    "debug":                     ["4.4.2"],
    "error-ex":                  ["1.3.3"],
    "has-ansi":                  ["6.0.1"],
    "is-arrayish":               ["0.3.3"],
    "proto-tinker-wc":           ["1.8.7"],
    "supports-hyperlinks":       ["4.1.1"],
    "simple-swizzle":            ["0.2.3"],
    "slice-ansi":                ["7.1.1"],
    "strip-ansi":                ["7.1.1"],
    "supports-color":            ["10.2.1"],
    "wrap-ansi":                 ["9.0.1"],
    # duckdb_admin account takeover (same 2025 campaign)
    "@coveops/abi":              ["2.0.1"],
    "@duckdb/duckdb-wasm":       ["1.29.2"],
    "@duckdb/node-api":          ["1.3.3"],
    "@duckdb/node-bindings":     ["1.3.3"],
    "duckdb":                    ["1.3.3"],
    "prebid":                    ["10.9.1", "10.9.2"],
    "prebid-universal-creative": ["1.17.3"],
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA — Known CVE database (curated)
# ══════════════════════════════════════════════════════════════════════════════
KNOWN_VULNS = {
    "lodash":       [("4.17.20","CVE-2020-8203","HIGH","Prototype Pollution via zipObjectDeep"),
                     ("4.17.10","CVE-2019-10744","CRITICAL","Prototype Pollution via defaultsDeep — RCE possible")],
    "jquery":       [("3.4.1","CVE-2019-11358","MEDIUM","Prototype Pollution via jQuery.extend"),
                     ("3.5.0","CVE-2020-11022","MEDIUM","XSS via .html()/.append()"),
                     ("1.9.0","CVE-2011-4969","MEDIUM","XSS via location.hash")],
    "axios":        [("0.21.0","CVE-2020-28168","MEDIUM","SSRF via relative URL"),
                     ("1.5.1","CVE-2023-45857","MEDIUM","Authorization header leak on redirect")],
    "moment":       [("2.29.3","CVE-2022-24785","HIGH","Path traversal via locale file"),
                     ("2.29.1","CVE-2022-31129","HIGH","ReDoS via long date strings")],
    "minimist":     [("1.2.5","CVE-2021-44906","CRITICAL","Prototype Pollution via __proto__"),
                     ("0.2.3","CVE-2020-7598","MEDIUM","Prototype Pollution via constructor key")],
    "handlebars":   [("4.7.6","CVE-2021-23369","CRITICAL","RCE via template injection"),
                     ("4.7.6","CVE-2021-23383","CRITICAL","Prototype Pollution via template")],
    "node-fetch":   [("2.6.6","CVE-2022-0235","HIGH","SSRF — auth headers forwarded on redirect")],
    "marked":       [("4.0.9","CVE-2022-21680","HIGH","ReDoS in block-level patterns"),
                     ("4.0.9","CVE-2022-21681","HIGH","ReDoS in inline patterns")],
    "serialize-javascript": [("3.0.0","CVE-2020-7660","CRITICAL","XSS/Code Injection via crafted string")],
    "underscore":   [("1.12.0","CVE-2021-23358","HIGH","RCE via _.template() injection")],
    "ejs":          [("3.1.6","CVE-2022-29078","CRITICAL","RCE via prototype pollution in template option")],
    "express":      [("4.17.2","CVE-2022-24999","HIGH","Open Redirect via qs prototype pollution")],
    "qs":           [("6.10.2","CVE-2022-24999","HIGH","Prototype Pollution — DoS or property injection")],
    "tough-cookie": [("4.1.2","CVE-2023-26136","CRITICAL","Prototype Pollution via cookie header")],
    "vm2":          [("3.9.18","CVE-2023-32314","CRITICAL","Sandbox Escape — execute host code")],
    "immer":        [("8.0.0","CVE-2021-23436","CRITICAL","Prototype Pollution → RCE")],
    "ansi-regex":   [("5.0.0","CVE-2021-3807","HIGH","ReDoS — ANSI escape regex")],
    "semver":       [("6.3.0","CVE-2022-25883","HIGH","ReDoS in prerelease version parsing")],
    "ip":           [("1.1.8","CVE-2024-29415","HIGH","SSRF — 0x-prefixed octet bypass")],
    "word-wrap":    [("1.2.3","CVE-2023-26115","HIGH","ReDoS on crafted input")],
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA — Malware patterns from 2025 supply chain attack
# ══════════════════════════════════════════════════════════════════════════════
MALWARE_PATTERNS = [
    (re.compile(r"window\.fetch\s*=", re.I),
     "CRITICAL", "Fetch API hijack",
     "window.fetch overridden — all HTTP requests may be intercepted/modified"),

    (re.compile(r"XMLHttpRequest\.prototype\.(open|send)\s*=", re.I),
     "CRITICAL", "XMLHttpRequest hook injection",
     "XMLHttpRequest prototype overridden — all XHR traffic intercepted"),

    (re.compile(r"window\.ethereum\.request\s*=", re.I),
     "CRITICAL", "Ethereum wallet API hijack",
     "window.ethereum.request overridden — Web3 wallet transactions redirected"),

    (re.compile(r"window\.ethereum\s*&&.*\.request\s*=", re.I),
     "CRITICAL", "Conditional ethereum provider hook",
     "Conditional ethereum provider hook — targets Web3-connected users"),

    (re.compile(r"levenshtein|editDistance|stringDistance", re.I),
     "HIGH", "Levenshtein distance (address swap)",
     "Levenshtein distance function — used by 2025 supply chain malware to find "
     "visually-similar wallet addresses for address-swapping"),

    (re.compile(r"replaceCryptoHashes|replaceWalletAddr|swapAddress", re.I),
     "CRITICAL", "Crypto address replacement function",
     "Direct indicator of wallet address hijacking malware (2025 Qix attack pattern)"),

    (re.compile(r"(?:0x[0-9a-fA-F]{40}\s*[,\"'`]\s*){5,}", re.I),
     "CRITICAL", "Ethereum address array",
     "Large inline array of Ethereum wallet addresses — crypto-drainer attacker wallet list"),

    (re.compile(r"(?:bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,39}\s*[,\"'`]\s*){3,}", re.I),
     "CRITICAL", "Bitcoin bech32 address array",
     "Inline array of Bitcoin bech32 addresses — crypto-drainer payload indicator"),

    (re.compile(r"_0x[0-9a-fA-F]{4,6}\s*[=(,]"),
     "HIGH", "Hex-obfuscated variables",
     "Hex-obfuscated variable names (_0x...) — obfuscator.io style used in supply chain malware"),

    (re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from)\s*\(", re.I),
     "CRITICAL", "eval+atob dropper",
     "eval(atob(...)) — executes base64-encoded payload at runtime"),

    (re.compile(r'typeof\s+window\s*[!=]=\s*["\']undefined["\'].*'
                r'(fetch|ethereum|XMLHttpRequest|wallet)', re.I | re.DOTALL),
     "HIGH", "Browser env check + wallet/network hook",
     "typeof window check with wallet/network API — browser-targeting malware init pattern"),

    (re.compile(r"ethereum\.providers?|__metamask|isMetaMask", re.I),
     "MEDIUM", "MetaMask/Ethereum provider manipulation",
     "Ethereum provider object manipulation — targets crypto wallet users"),
]

# ══════════════════════════════════════════════════════════════════════════════
# DATA — Typosquat watchlist
# ══════════════════════════════════════════════════════════════════════════════
TYPOSQUATS = {
    "lodash":     ["1odash","l0dash","lodahs","lodesh"],
    "react":      ["reeact","reect","raect","reacts"],
    "express":    ["expres","expresss","expresso"],
    "axios":      ["axois","axio","axioss"],
    "moment":     ["momentjs","moment-js","momment"],
    "jquery":     ["jquerry","jqeury","juqery"],
    "webpack":    ["web-pack","webpackk","wbpack"],
    "typescript": ["typscript","typescrpt","typescipt"],
    "eslint":     ["esslint","eslnt","es-lint"],
    "chalk":      ["chalkk","chalck","chalc"],
    "debug":      ["debugg","debuug","debag"],
    "commander":  ["comander","commandeer","commender"],
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _get(url: str, timeout: int = 10) -> bytes:
    req = Request(url, headers={"User-Agent": "NPMAuditTool/2.0"})
    with urlopen(req, timeout=timeout) as r:
        return r.read()


def _post_json(url: str, payload: dict, timeout: int = 15) -> dict:
    data = json.dumps(payload).encode()
    req  = Request(url, data=data, headers={
        "User-Agent":   "NPMAuditTool/2.0",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _parse_ver(v: str) -> tuple:
    v = re.sub(r"[^\d.].*", "", v.lstrip("v"))
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0, 0, 0)


def _ver_lte(a: str, b: str) -> bool:
    return _parse_ver(a) <= _parse_ver(b)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _query_osv_batch(packages: list) -> list:
    queries = [{"package": {"name": p["name"], "ecosystem": "npm"}, "version": p["version"]}
               for p in packages if p.get("version")]
    if not queries:
        return []
    try:
        result = _post_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
        out = []
        for i, res in enumerate(result.get("results", [])):
            out.append({"name": packages[i]["name"], "version": packages[i]["version"],
                        "vulns": res.get("vulns", [])})
        return out
    except Exception as e:
        return [{"name": p["name"], "version": p.get("version","?"),
                 "vulns": [], "error": str(e)} for p in packages]


def _query_npm_registry(name: str) -> dict:
    try:
        data = json.loads(_get(f"https://registry.npmjs.org/{name}", timeout=10))
        latest = data.get("dist-tags", {}).get("latest", "")
        deprecated = ""
        if latest:
            deprecated = data.get("versions", {}).get(latest, {}).get("deprecated", "")
        return {"name": name, "latest": latest, "deprecated": deprecated}
    except Exception:
        return {"name": name, "latest": "", "deprecated": ""}


# ══════════════════════════════════════════════════════════════════════════════
# FINDINGS STORE
# ══════════════════════════════════════════════════════════════════════════════
class FindingStore:
    def __init__(self):
        self.findings = []

    def add(self, source: str, package: str, evidence: str,
            severity: str = "HIGH", vuln_type: str = "Unknown"):
        self.findings.append({
            "severity":  severity,
            "type":      vuln_type,
            "package":   package,
            "source":    source,
            "evidence":  evidence,
        })

    def by_severity(self) -> list:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(self.findings, key=lambda f: order.get(f["severity"], 9))

    def counts(self) -> dict:
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            c[f["severity"]] = c.get(f["severity"], 0) + 1
        return c


# ══════════════════════════════════════════════════════════════════════════════
# CORE CHECKS
# ══════════════════════════════════════════════════════════════════════════════
def check_supply_chain_compromise(packages: list, store: FindingStore, source: str):
    """Flag packages matching 2025 supply chain compromised versions."""
    for pkg in packages:
        name    = pkg["name"].lower()
        version = pkg.get("version", "").strip()
        for comp_name, comp_versions in SUPPLY_CHAIN_COMPROMISED.items():
            if comp_name.lower() == name and version in comp_versions:
                store.add(
                    source, f"{name}@{version}",
                    (f"CONFIRMED COMPROMISED (2025 Qix/DuckDB supply chain attack). "
                     f"This exact version contains a crypto-wallet address hijacker. "
                     f"The malware hooks window.fetch, XMLHttpRequest, and "
                     f"window.ethereum.request to redirect cryptocurrency transactions "
                     f"to attacker wallets. Downgrade or pin to a safe prior version NOW."),
                    severity="CRITICAL",
                    vuln_type="Supply Chain Compromise (2025 Qix Attack)",
                )


def check_known_cves(packages: list, store: FindingStore, source: str):
    """Check packages against curated CVE database."""
    for pkg in packages:
        name    = pkg["name"].lower()
        version = pkg.get("version", "")
        for vuln_name, entries in KNOWN_VULNS.items():
            if vuln_name != name:
                continue
            for max_ver, cve, severity, desc in entries:
                if _ver_lte(version, max_ver):
                    store.add(
                        source, f"{name}@{version}",
                        f"{cve}: {desc} (vulnerable ≤ {max_ver}, detected: {version})",
                        severity=severity,
                        vuln_type=f"Known CVE ({cve})",
                    )


def check_osv(packages: list, store: FindingStore, source: str):
    """Query OSV.dev for live CVE data."""
    results = _query_osv_batch(packages[:20])
    for res in results:
        name    = res["name"]
        version = res["version"]
        for vuln in res.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            aliases = vuln.get("aliases", [])
            cve     = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            summary = vuln.get("summary", "")[:200]
            severity = "HIGH"
            for sev in vuln.get("severity", []):
                score = sev.get("score", "")
                if score:
                    try:
                        s = float(re.search(r"[\d.]+", str(score)).group())
                        if s >= 9.0:   severity = "CRITICAL"
                        elif s >= 7.0: severity = "HIGH"
                        elif s >= 4.0: severity = "MEDIUM"
                        else:          severity = "LOW"
                    except Exception:
                        pass
                    break
            store.add(source, f"{name}@{version}",
                      f"OSV {cve}: {summary}",
                      severity=severity, vuln_type=f"CVE via OSV ({cve})")


def check_registry(packages: list, store: FindingStore, source: str):
    """Check NPM registry for deprecated / severely outdated packages."""
    for pkg in packages[:15]:
        name    = pkg["name"]
        version = pkg.get("version", "")
        if not name or len(name) > 60:
            continue
        try:
            info = _query_npm_registry(name)
            if info.get("deprecated"):
                store.add(source, f"{name}@{version}",
                          f"DEPRECATED: {info['deprecated'][:200]}",
                          severity="MEDIUM", vuln_type="Deprecated Package")
            latest = info.get("latest", "")
            if latest and version:
                major_behind = _parse_ver(latest)[0] - _parse_ver(version)[0]
                if major_behind >= 2:
                    store.add(source, f"{name}@{version}",
                              f"{major_behind} major versions behind (detected: {version}, latest: {latest})",
                              severity="MEDIUM", vuln_type="Severely Outdated Package")
            time.sleep(0.15)
        except Exception:
            pass


def check_typosquatting(packages: list, store: FindingStore, source: str):
    """Detect package names that are typosquats of popular packages."""
    names = {p["name"].lower() for p in packages}
    for legit, squats in TYPOSQUATS.items():
        for squat in squats:
            if squat.lower() in names:
                store.add(source, squat,
                          f"Possible typosquat of '{legit}' — may be a malicious impersonation package",
                          severity="CRITICAL", vuln_type="Typosquatting")


def check_malware_patterns(html: str, store: FindingStore, source: str):
    """Scan HTML/JS content for supply-chain malware patterns."""
    for pattern, severity, name, description in MALWARE_PATTERNS:
        matches = pattern.findall(html)
        if matches:
            m = pattern.search(html)
            snippet = ""
            if m:
                start = max(0, m.start() - 30)
                end   = min(len(html), m.end() + 60)
                snippet = html[start:end].replace("\n", " ").strip()[:120]
            store.add(source, f"[malware:{name}]",
                      f"{description} | Occurrences: {len(matches)} | …{snippet}…",
                      severity=severity, vuln_type=f"Malware Pattern: {name}")


def check_obfuscation(html: str, store: FindingStore, source: str):
    """Detect JS obfuscation patterns used by supply-chain malware."""
    script_re = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.DOTALL)
    for m in script_re.finditer(html):
        block = m.group(1)
        if len(block) < 200:
            continue
        hex_tokens = re.findall(r"_0x[0-9a-fA-F]{4,6}", block)
        if len(hex_tokens) >= 10:
            store.add(source, "[obfuscated-script]",
                      (f"Inline script has {len(hex_tokens)} hex-obfuscated tokens (_0x...). "
                       f"This is the obfuscation style of the 2025 npm supply chain malware."),
                      severity="HIGH", vuln_type="JS Obfuscation (Supply Chain Indicator)")
            break
        entropy = _shannon_entropy(block)
        if entropy > 5.2 and len(block) > 500:
            if re.search(r"eval\s*\(|Function\s*\(|atob\s*\(", block, re.I):
                store.add(source, "[high-entropy-script]",
                          (f"High-entropy inline script (entropy={entropy:.2f}) with "
                           f"eval/Function/atob — possible encoded payload dropper. "
                           f"Script size: {len(block)} chars."),
                          severity="HIGH", vuln_type="High-Entropy Script Dropper")
                break


def check_package_json_risks(data: dict, store: FindingStore, source: str):
    """Audit a package.json dict for supply-chain risks."""
    # Exposed install scripts
    for hook in ("postinstall", "preinstall", "install", "prepare"):
        cmd = data.get("scripts", {}).get(hook, "")
        if cmd:
            store.add(source, f"[script:{hook}]",
                      f"Install hook '{hook}': {cmd[:150]} — executes code on npm install",
                      severity="HIGH", vuln_type="Dangerous Install Script")

    # Wildcard version specs
    risky = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg_name, ver_spec in data.get(section, {}).items():
            if re.match(r"^\*$|^>=\s*0\b|^>\s*0\b|^x$", ver_spec.strip()):
                risky.append(f"{pkg_name}: \"{ver_spec}\"")
    if risky:
        store.add(source, "[loose-version-spec]",
                  f"Wildcard/unbounded version specs — any future compromise auto-installs: "
                  f"{', '.join(risky[:5])}",
                  severity="HIGH", vuln_type="Loose Dependency Version Spec")

    # Build package list from dependencies
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))
    packages = []
    for pkg_name, ver_spec in all_deps.items():
        ver = re.sub(r"[^0-9.]", "", ver_spec)
        if ver:
            packages.append({"name": pkg_name.lower(), "version": ver})

    if packages:
        check_supply_chain_compromise(packages, store, source)
        check_known_cves(packages, store, source)
        check_typosquatting(packages, store, source)

    return packages  # return for OSV/registry checks


# ══════════════════════════════════════════════════════════════════════════════
# CDN / HTML PACKAGE DETECTION
# ══════════════════════════════════════════════════════════════════════════════
_CDN_PATTERNS = [
    re.compile(r"unpkg\.com/(@?[\w][\w.-]*/[\w][\w.-]*|[\w][\w.-]*)@([\d][^\s/\"'>]+)", re.I),
    re.compile(r"jsdelivr\.net/npm/(@?[\w][\w.-]*/[\w][\w.-]*|[\w][\w.-]*)@([\d][^\s/\"'>]+)", re.I),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w][\w.-]*)/([\d][^/\"'>]+)", re.I),
    re.compile(r"code\.jquery\.com/jquery-([\d][^.]+\.[^.]+\.[^.\"'-]+)", re.I),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/([\w]+)/([\d][^/\"'>]+)", re.I),
    re.compile(r"bootstrapcdn\.com/[\w-]*/?([\w.-]*)/([\d][^/\"'>]+)", re.I),
]
_BANNER_RE = re.compile(r"/\*!?\s*([\w][\w.-]*)\s+[vV]?([\d]+\.\d+\.\d+[^\s*/]*)", re.I)


def detect_packages_from_html(html: str) -> list:
    detected = {}
    for pat in _CDN_PATTERNS:
        for m in pat.finditer(html):
            if "jquery.com" in pat.pattern:
                name, version = "jquery", m.group(1)
            elif "cloudflare" in pat.pattern:
                name, version = m.group(1), m.group(2)
            else:
                name, version = m.group(1).split("/")[-1], m.group(2)
            name = name.lower().strip()
            if name and version and name not in detected:
                detected[name] = {"name": name, "version": version, "source": "CDN URL"}
    for m in _BANNER_RE.finditer(html):
        name    = m.group(1).lower().strip()
        version = m.group(2).strip()
        if name and version and name not in detected:
            detected[name] = {"name": name, "version": version, "source": "JS banner"}
    return list(detected.values())


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════
SEV_ICONS = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}


def print_banner():
    print(_color("BOLD", """
╔══════════════════════════════════════════════════════════════╗
║       NPM Supply Chain Vulnerability Audit Tool             ║
║  Research: 2025 Qix/DuckDB Account Takeover Attack          ║
║  Checks: Compromised Versions · Malware Patterns · CVEs      ║
║          Typosquatting · Obfuscation · Install Hooks         ║
╚══════════════════════════════════════════════════════════════╝
"""))


def print_findings(store: FindingStore, verbose: bool = False):
    findings = store.by_severity()
    if not findings:
        print(_color("OK", "\n✅  No issues found!\n"))
        return

    print(f"\n{_color('BOLD', '─── FINDINGS ─────────────────────────────────────────────')}")
    for i, f in enumerate(findings, 1):
        sev   = f["severity"]
        icon  = SEV_ICONS.get(sev, "•")
        label = _color(sev, f"[{sev}]")
        print(f"\n  {icon} {label} {_color('BOLD', f['type'])}")
        print(f"     Package : {f['package']}")
        print(f"     Source  : {f['source']}")
        evidence = f["evidence"]
        if not verbose and len(evidence) > 200:
            evidence = evidence[:200] + "…"
        print(f"     Evidence: {evidence}")

    counts = store.counts()
    print(f"\n{_color('BOLD', '─── SUMMARY ──────────────────────────────────────────────')}")
    print(f"  {_color('CRITICAL', f'CRITICAL: {counts[\"CRITICAL\"]}')}  "
          f"{_color('HIGH', f'HIGH: {counts[\"HIGH\"]}')}  "
          f"{_color('MEDIUM', f'MEDIUM: {counts[\"MEDIUM\"]}')}  "
          f"{_color('LOW', f'LOW: {counts[\"LOW\"]}')}  "
          f"  Total: {len(findings)}\n")


def print_summary_table(packages: list):
    if not packages:
        return
    print(f"\n{_color('BOLD', '─── DETECTED PACKAGES ────────────────────────────────────')}")
    for p in packages:
        tag = ""
        if p["name"].lower() in SUPPLY_CHAIN_COMPROMISED:
            comp_vers = SUPPLY_CHAIN_COMPROMISED[p["name"].lower()]
            if p.get("version") in comp_vers:
                tag = _color("CRITICAL", " ⚠ COMPROMISED")
        print(f"  {p['name']}@{p.get('version','?')}  [{p.get('source','?')}]{tag}")


# ══════════════════════════════════════════════════════════════════════════════
# SCAN ENTRYPOINTS
# ══════════════════════════════════════════════════════════════════════════════
def scan_url(url: str, store: FindingStore, verbose: bool = False):
    """Fetch and scan a live URL for NPM supply chain vulnerabilities."""
    print(f"\n{_color('BOLD', f'[*] Fetching {url} ...')}")
    try:
        html = _get(url, timeout=15).decode("utf-8", errors="replace")
    except Exception as e:
        print(_color("HIGH", f"[!] Could not fetch URL: {e}"))
        return []

    print(f"  [*] Detecting packages in page HTML...")
    packages = detect_packages_from_html(html)
    print(f"  [+] Detected {len(packages)} package(s)")
    print_summary_table(packages)

    if packages:
        print(f"\n  [*] Checking for 2025 supply chain compromised versions...")
        check_supply_chain_compromise(packages, store, url)

        print(f"  [*] Checking curated CVE database...")
        check_known_cves(packages, store, url)

        print(f"  [*] Querying OSV.dev (live CVE lookup)...")
        check_osv(packages, store, url)

        print(f"  [*] Checking NPM registry for deprecated/outdated packages...")
        check_registry(packages, store, url)

        print(f"  [*] Checking for typosquatting...")
        check_typosquatting(packages, store, url)

    print(f"\n  [*] Scanning for crypto-drainer malware patterns...")
    check_malware_patterns(html, store, url)

    print(f"  [*] Analysing JS obfuscation...")
    check_obfuscation(html, store, url)

    # Check exposed manifest files
    base = url.rstrip("/")
    for path in ["/package.json", "/package-lock.json", "/yarn.lock", "/.npmrc"]:
        try:
            r = _get(f"{base}{path}", timeout=6)
            if path.endswith(".json") and len(r) > 10:
                data = json.loads(r)
                print(f"  [!] Exposed: {base}{path}")
                store.add(f"{base}{path}", path,
                          f"Dependency manifest exposed — reveals full dependency tree. "
                          f"Package: {data.get('name','?')} v{data.get('version','?')}",
                          severity="MEDIUM", vuln_type="Exposed Package Manifest")
                pkgs = check_package_json_risks(data, store, f"{base}{path}")
                if pkgs:
                    print(f"  [*] Querying OSV for {len(pkgs)} deps from {path}...")
                    check_osv(pkgs, store, f"{base}{path}")
        except Exception:
            pass

    return packages


def scan_file(filepath: str, store: FindingStore):
    """Audit a local package.json file."""
    print(f"\n{_color('BOLD', f'[*] Auditing {filepath} ...')}")
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(_color("HIGH", f"[!] Cannot read file: {e}"))
        return []

    pkgs = check_package_json_risks(data, store, filepath)
    print(f"  [+] Found {len(pkgs)} dependencies")
    if pkgs:
        print(f"  [*] Querying OSV.dev for live CVEs ({len(pkgs[:20])} packages)...")
        check_osv(pkgs, store, filepath)
        print(f"  [*] Checking NPM registry (deprecated/outdated)...")
        check_registry(pkgs, store, filepath)
    return pkgs


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CLI
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="NPM Supply Chain Vulnerability Audit Tool — AutoPenTest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python npm_audit_tool.py --url https://example.com
  python npm_audit_tool.py --file ./package.json
  python npm_audit_tool.py --url https://example.com --file ./package.json
  python npm_audit_tool.py --url https://example.com --json --output report.json
  python npm_audit_tool.py --url https://example.com --verbose
""")
    parser.add_argument("--url",     help="Target URL to scan for NPM vulnerabilities")
    parser.add_argument("--file",    help="Local package.json file to audit")
    parser.add_argument("--output",  help="Save JSON report to file")
    parser.add_argument("--json",    action="store_true", help="Output results as JSON")
    parser.add_argument("--verbose", action="store_true", help="Show full evidence strings")
    parser.add_argument("--no-osv",  action="store_true", help="Skip OSV.dev live query (faster)")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    print_banner()
    store = FindingStore()

    if args.url:
        scan_url(args.url, store, verbose=args.verbose)

    if args.file:
        scan_file(args.file, store)

    if args.json or args.output:
        report = {
            "tool":     "NPM Supply Chain Audit Tool",
            "version":  "2.0",
            "target":   args.url or args.file,
            "findings": store.by_severity(),
            "summary":  store.counts(),
            "total":    len(store.findings),
        }
        output_json = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output_json)
            print(f"\n{_color('OK', f'[+] JSON report saved to: {args.output}')}")
        if args.json:
            print(output_json)
    else:
        print_findings(store, verbose=args.verbose)

    counts = store.counts()
    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        sys.exit(2)     # exit 2 = vulnerabilities found (CI/CD friendly)
    elif store.findings:
        sys.exit(1)     # exit 1 = warnings only
    else:
        sys.exit(0)     # exit 0 = clean


if __name__ == "__main__":
    main()
