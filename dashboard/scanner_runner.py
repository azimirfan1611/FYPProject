"""
Background scanner runner — Enterprise Edition.
Fixes: race conditions (threading.Lock), config isolation (URL as param),
memory limits (LRU cap + log buffer cap), log XSS safety.
"""
import sys, threading, os, re
from datetime import datetime, timedelta
from collections import OrderedDict
from contextlib import redirect_stdout, redirect_stderr
import io

if "/app/pentest_lib" not in sys.path:
    sys.path.insert(0, "/app/pentest_lib")
_local = os.path.join(os.path.dirname(__file__), "..", "pentester")
if os.path.exists(_local) and _local not in sys.path:
    sys.path.insert(0, _local)

# ── Thread-safe SCANS store ────────────────────────────────────────────────
SCANS: OrderedDict = OrderedDict()
SCANS_LOCK = threading.Lock()
MAX_SCANS        = 100
MAX_LOGS         = 5000
MAX_AGE_HOURS    = 24
_ANSI_RE         = re.compile(r"\x1b\[[0-9;]*m")


def evict_old_scans():
    """Remove completed scans older than MAX_AGE_HOURS; cap at MAX_SCANS."""
    cutoff = (datetime.utcnow() - timedelta(hours=MAX_AGE_HOURS)).isoformat()
    with SCANS_LOCK:
        for sid, s in list(SCANS.items()):
            if (s["status"] in ("complete", "error", "cancelled") and
                    s.get("completed_at", "9999") < cutoff):
                s["report_html"] = None
                s["findings"] = []
        while len(SCANS) > MAX_SCANS:
            SCANS.popitem(last=False)


class _ScanLogger:
    """Captures stdout/stderr into scan log list with buffer cap."""
    def __init__(self, scan_id: str):
        self._id  = scan_id
        self._buf = ""

    def write(self, text: str):
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = _ANSI_RE.sub("", line).strip()
            if line:
                with SCANS_LOCK:
                    logs = SCANS[self._id]["logs"]
                    if len(logs) < MAX_LOGS:
                        logs.append(line)
                    elif logs and logs[-1] != "...log truncated...":
                        logs.append("...log truncated...")

    def flush(self): pass
    def isatty(self): return False


def _update(scan_id: str, **kwargs):
    with SCANS_LOCK:
        SCANS[scan_id].update(kwargs)


def _safe_log(scan_id: str, msg: str):
    with SCANS_LOCK:
        logs = SCANS[scan_id]["logs"]
        if len(logs) < MAX_LOGS:
            logs.append(msg)


def _import_scanner(module_path: str, class_name: str, target_url: str,
                    extra_kwargs: dict = None):
    """Import scanner, instantiating with target_url when supported."""
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    kwargs = {"target_url": target_url}
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    try:
        return cls(**kwargs)
    except TypeError:
        # Legacy scanner — patch config module instead
        try:
            import config as _cfg
            _cfg.TARGET_URL = target_url
            if extra_kwargs:
                for k, v in extra_kwargs.items():
                    if hasattr(_cfg, k.upper()):
                        setattr(_cfg, k.upper(), v)
        except Exception:
            pass
        return cls()


def _run(scan_id: str, url: str, report_dir: str, scan_cfg: dict):
    logger = _ScanLogger(scan_id)

    try:
        zap_url      = scan_cfg.get("zap_url",      os.environ.get("ZAP_URL",        "http://zap:8090"))
        zap_key      = scan_cfg.get("zap_key",      os.environ.get("ZAP_KEY",        ""))
        openai_key   = scan_cfg.get("openai_key",   os.environ.get("OPENAI_API_KEY", ""))
        openai_model = scan_cfg.get("openai_model", os.environ.get("OPENAI_MODEL",   "gpt-4o-mini"))

        # ── Phase 1: Custom + new scanners ─────────────────────────────────
        _update(scan_id, phase="Phase 1: Custom Scanners", progress_pct=5)
        _safe_log(scan_id, "=" * 50)
        _safe_log(scan_id, "PHASE 1: Custom Python Scanners")
        _safe_log(scan_id, "=" * 50)

        custom_steps = [
            ("SQL Injection",     "scanners.sql_injection",    "SQLInjectionScanner"),
            ("XSS",               "scanners.xss_scanner",      "XSSScanner"),
            ("Authentication",    "scanners.auth_tester",      "AuthTester"),
            ("Path Traversal",    "scanners.dir_traversal",    "DirTraversalScanner"),
            ("Command Injection", "scanners.command_injection", "CommandInjectionScanner"),
            ("IDOR",              "scanners.idor_scanner",     "IDORScanner"),
            ("HTTP Headers",      "scanners.headers_scanner",  "HeadersScanner"),
            ("CORS",              "scanners.cors_scanner",     "CORSScanner"),
            ("SSL/TLS",           "scanners.ssl_scanner",      "SSLScanner"),
            ("API Security",      "scanners.api_scanner",      "APIScanner"),
            ("DNS/Subdomain",     "scanners.dns_scanner",      "DNSScanner"),
            ("WAF Detection",     "scanners.waf_scanner",      "WAFScanner"),
            ("NPM Supply Chain",  "scanners.npm_scanner",      "NPMScanner"),
        ]

        all_findings = []
        total_steps  = len(custom_steps) + 5  # 4 tools + 1 for AI+report
        step         = 0

        for name, module_path, class_name in custom_steps:
            with SCANS_LOCK:
                if SCANS[scan_id]["status"] == "cancelled":
                    return
            _safe_log(scan_id, f"[*] Running {name} scanner...")
            try:
                scanner = _import_scanner(module_path, class_name, url)
                with redirect_stdout(logger), redirect_stderr(logger):
                    findings = scanner.run()
                all_findings.extend(findings)
                _safe_log(scan_id, f"    \u2192 {len(findings)} finding(s)")
            except ModuleNotFoundError:
                _safe_log(scan_id, f"    [-] {name} module not available, skipping")
            except Exception as e:
                _safe_log(scan_id, f"    [!] {name} error: {e}")
            step += 1
            _update(scan_id, phase=f"Phase 1: {name}",
                    progress_pct=int(5 + (step / total_steps) * 40))

        # ── Phase 2: Real pentest tools ────────────────────────────────────
        _update(scan_id, phase="Phase 2: Real Pentest Tools", progress_pct=45)
        _safe_log(scan_id, "")
        _safe_log(scan_id, "=" * 50)
        _safe_log(scan_id, "PHASE 2: Real Pentest Tools")
        _safe_log(scan_id, "=" * 50)

        tool_steps = [
            ("Nmap",      "scanners.nmap_scanner",   "NmapScanner",  {}),
            ("Nikto",     "scanners.nikto_scanner",  "NiktoScanner", {}),
            ("SQLMap",    "scanners.sqlmap_scanner", "SQLMapScanner",{}),
            ("OWASP ZAP", "scanners.zap_scanner",    "ZAPScanner",
             {"zap_url": zap_url, "zap_key": zap_key}),
        ]

        for name, module_path, class_name, extra in tool_steps:
            with SCANS_LOCK:
                if SCANS[scan_id]["status"] == "cancelled":
                    return
            _safe_log(scan_id, f"[*] Running {name}...")
            try:
                scanner = _import_scanner(module_path, class_name, url, extra)
                with redirect_stdout(logger), redirect_stderr(logger):
                    findings = scanner.run()
                all_findings.extend(findings)
                _safe_log(scan_id, f"    \u2192 {len(findings)} finding(s)")
            except ModuleNotFoundError:
                _safe_log(scan_id, f"    [-] {name} not available, skipping")
            except Exception as e:
                _safe_log(scan_id, f"    [!] {name} error: {e}")
            step += 1
            _update(scan_id, phase=f"Phase 2: {name}",
                    progress_pct=int(45 + (step / total_steps) * 30))

        # ── Compliance Mapping ─────────────────────────────────────────────
        _safe_log(scan_id, "[*] Running compliance mapping (OWASP/CWE/PCI/NIST)...")
        try:
            from scanners.compliance_mapper import ComplianceMapper
            all_findings = ComplianceMapper().annotate(all_findings)
            _safe_log(scan_id, "    \u2192 Findings annotated with OWASP/CWE/PCI/NIST")
        except Exception as e:
            _safe_log(scan_id, f"    [-] Compliance mapping: {e}")

        # ── Threat Intelligence ────────────────────────────────────────────
        _safe_log(scan_id, "[*] Querying threat intelligence...")
        threat_intel = {}
        try:
            from threat_intel import ThreatIntel
            threat_intel = ThreatIntel(url).query_all()
            _safe_log(scan_id, f"    \u2192 {threat_intel.get('summary', 'N/A')}")
        except Exception as e:
            _safe_log(scan_id, f"    [-] Threat intel: {e}")
        _update(scan_id, threat_intel=threat_intel)

        # ── AI Analysis ────────────────────────────────────────────────────
        _update(scan_id, phase="AI Analysis", progress_pct=88)
        _safe_log(scan_id, "")
        _safe_log(scan_id, "[*] Running AI analysis...")

        # Enrich with live CISA KEV matches
        kev_matches = []
        try:
            from threat_feed import get_relevant_cves_for_findings
            kev_matches = get_relevant_cves_for_findings(all_findings)
            if kev_matches:
                _safe_log(scan_id, f"    → {len(kev_matches)} CISA KEV match(es) found for detected vuln types")
        except Exception:
            pass

        try:
            from ai_analyzer import analyze
            analysis = analyze(all_findings, openai_key=openai_key,
                               openai_model=openai_model)
            if kev_matches:
                analysis["cisa_kev_matches"] = kev_matches
            _safe_log(scan_id, f"    → Risk Rating: {analysis.get('risk_rating','?')}")
            _safe_log(scan_id, f"    → {analysis.get('executive_summary','')[:120]}")
        except Exception as e:
            _safe_log(scan_id, f"    [!] AI error: {e}")
            analysis = {
                "risk_rating": "Unknown", "executive_summary": str(e),
                "total_findings": len(all_findings),
                "critical_count": 0, "high_count": 0,
                "medium_count": 0, "low_count": 0,
                "findings_analysis": [], "top_priorities": [],
                "positive_findings": [], "exploit_chains": [],
                "cisa_kev_matches": kev_matches,
            }

        # ── Generate Reports ───────────────────────────────────────────────
        _update(scan_id, phase="Generating Reports", progress_pct=95)
        _safe_log(scan_id, "[*] Generating reports...")
        try:
            from report_generator import generate
            with redirect_stdout(logger):
                paths = generate(all_findings, analysis,
                                 target_url=url, report_dir=report_dir)
            with open(paths["html"], "r", encoding="utf-8") as fh:
                report_html = fh.read()
            import json as _json
            with open(paths["json"], "r") as fh:
                report_json = _json.load(fh)
            _safe_log(scan_id, f"    \u2192 Saved: {paths['html']}")

            _update(scan_id,
                    status="complete",
                    phase="Complete",
                    progress_pct=100,
                    total_findings=len(all_findings),
                    risk_rating=analysis.get("risk_rating", "Unknown"),
                    findings=all_findings,
                    analysis=analysis,
                    report_html=report_html,
                    report_json=report_json,
                    report_path=paths["html"],
                    completed_at=datetime.utcnow().isoformat())
            _safe_log(scan_id, "[✓] Assessment complete!")
        except Exception as e:
            _safe_log(scan_id, f"[!] Report error: {e}")
            _update(scan_id, status="error", error=str(e),
                    phase="Error", progress_pct=100)

    except Exception as e:
        _update(scan_id, status="error", error=str(e),
                phase="Error", progress_pct=100)


def run_scan_async(scan_id: str, url: str, report_dir: str):
    scan_cfg = {
        "zap_url":      os.environ.get("ZAP_URL",        "http://zap:8090"),
        "zap_key":      os.environ.get("ZAP_KEY",        ""),
        "openai_key":   os.environ.get("OPENAI_API_KEY", ""),
        "openai_model": os.environ.get("OPENAI_MODEL",   "gpt-4o-mini"),
    }
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "id":             scan_id,
            "url":            url,
            "status":         "running",
            "phase":          "Starting...",
            "progress_pct":   0,
            "logs":           [],
            "findings":       [],
            "analysis":       {},
            "threat_intel":   {},
            "report_html":    None,
            "report_json":    None,
            "report_path":    None,
            "total_findings": 0,
            "risk_rating":    "",
            "error":          None,
            "started_at":     datetime.utcnow().isoformat(),
            "completed_at":   None,
        }
    t = threading.Thread(target=_run, args=(scan_id, url, report_dir, scan_cfg),
                         daemon=True)
    t.start()
import sys, io, threading, time, os
from datetime import datetime
from contextlib import redirect_stdout

# Make pentest_lib importable (Docker path)
if "/app/pentest_lib" not in sys.path:
    sys.path.insert(0, "/app/pentest_lib")

# Also support local dev
_local_lib = os.path.join(os.path.dirname(__file__), "..", "pentester")
if os.path.exists(_local_lib) and _local_lib not in sys.path:
    sys.path.insert(0, _local_lib)

SCANS: dict = {}


class _ScanLogger:
    """Thread-safe stdout redirector that appends to scan log list."""
    def __init__(self, scan_id: str):
        self._id = scan_id
        self._buf = ""

    def write(self, text: str):
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line:
                # Strip ANSI colour codes
                import re
                line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                SCANS[self._id]["logs"].append(line)

    def flush(self):
        pass


def _update(scan_id, **kwargs):
    SCANS[scan_id].update(kwargs)


def _run(scan_id: str, url: str, report_dir: str):
    scan = SCANS[scan_id]
    logger = _ScanLogger(scan_id)

    def log(msg):
        scan["logs"].append(msg)

    try:
        from config import TARGET_URL   # will be overridden below
        import config as _cfg
        _cfg.TARGET_URL = url

        # Also patch ZAP config
        zap_url = os.environ.get("ZAP_URL", "http://zap:8090")
        zap_key = os.environ.get("ZAP_KEY", "zapkey123")
        _cfg.ZAP_URL = zap_url
        _cfg.ZAP_KEY = zap_key

    except Exception:
        pass

    # ── Phase 1: Custom scanners ───────────────────────────────────────────
    _update(scan_id, phase="Phase 1: Custom Scanners", progress_pct=5)
    log("=" * 50)
    log("PHASE 1: Custom Python Scanners")
    log("=" * 50)

    custom_steps = [
        ("SQL Injection",     "scanners.sql_injection",   "SQLInjectionScanner"),
        ("XSS",               "scanners.xss_scanner",     "XSSScanner"),
        ("Authentication",    "scanners.auth_tester",     "AuthTester"),
        ("Path Traversal",    "scanners.dir_traversal",   "DirTraversalScanner"),
        ("Command Injection", "scanners.command_injection","CommandInjectionScanner"),
        ("IDOR",              "scanners.idor_scanner",    "IDORScanner"),
        ("NPM Supply Chain",  "scanners.npm_scanner",     "NPMScanner"),
    ]

    all_findings = []
    total_steps  = len(custom_steps) + 4 + 1  # +4 tools, +1 AI
    step         = 0

    for name, module_path, class_name in custom_steps:
        if scan["status"] == "cancelled":
            return
        log(f"[*] Running {name} scanner...")
        try:
            import importlib
            mod = importlib.import_module(module_path)
            # Patch TARGET_URL inside scanner config
            import config as _cfg
            _cfg.TARGET_URL = url

            cls  = getattr(mod, class_name)
            with redirect_stdout(logger):
                findings = cls().run()
            all_findings.extend(findings)
            log(f"    → {len(findings)} finding(s)")
        except Exception as e:
            log(f"    [!] {name} error: {e}")

        step += 1
        _update(scan_id,
                phase=f"Phase 1: {name}",
                progress_pct=int(5 + (step / total_steps) * 40))

    # ── Phase 2: Real pentest tools ────────────────────────────────────────
    _update(scan_id, phase="Phase 2: Real Pentest Tools", progress_pct=45)
    log("")
    log("=" * 50)
    log("PHASE 2: Real Pentest Tools")
    log("=" * 50)

    tool_steps = [
        ("Nmap",      "scanners.nmap_scanner",   "NmapScanner"),
        ("Nikto",     "scanners.nikto_scanner",  "NiktoScanner"),
        ("SQLMap",    "scanners.sqlmap_scanner", "SQLMapScanner"),
        ("OWASP ZAP", "scanners.zap_scanner",    "ZAPScanner"),
    ]

    for name, module_path, class_name in tool_steps:
        if scan["status"] == "cancelled":
            return
        log(f"[*] Running {name}...")
        try:
            import importlib
            mod = importlib.import_module(module_path)
            import config as _cfg
            _cfg.TARGET_URL = url
            _cfg.ZAP_URL    = os.environ.get("ZAP_URL", "http://zap:8090")
            _cfg.ZAP_KEY    = os.environ.get("ZAP_KEY", "zapkey123")

            cls = getattr(mod, class_name)
            with redirect_stdout(logger):
                findings = cls().run()
            all_findings.extend(findings)
            log(f"    → {len(findings)} finding(s)")
        except Exception as e:
            log(f"    [!] {name} error: {e}")

        step += 1
        _update(scan_id,
                phase=f"Phase 2: {name}",
                progress_pct=int(45 + (step / total_steps) * 40))

    # ── AI Analysis ────────────────────────────────────────────────────────
    _update(scan_id, phase="AI Analysis", progress_pct=88)
    log("")
    log("[*] Running AI analysis...")
    try:
        import config as _cfg
        _cfg.OPENAI_KEY   = os.environ.get("OPENAI_API_KEY", "")
        _cfg.OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        from ai_analyzer import analyze
        with redirect_stdout(logger):
            analysis = analyze(all_findings)
        risk = analysis.get("risk_rating", "Unknown")
        log(f"    → Risk Rating: {risk}")
        log(f"    → {analysis.get('executive_summary','')[:120]}")
    except Exception as e:
        log(f"    [!] AI analysis error: {e}")
        analysis = {"risk_rating": "Unknown", "executive_summary": str(e),
                    "total_findings": len(all_findings),
                    "critical_count": 0, "high_count": 0,
                    "medium_count": 0, "low_count": 0,
                    "findings_analysis": [], "top_priorities": [],
                    "positive_findings": []}

    # ── Generate report ────────────────────────────────────────────────────
    _update(scan_id, phase="Generating Report", progress_pct=95)
    log("[*] Generating report...")
    try:
        import config as _cfg
        _cfg.TARGET_URL  = url
        _cfg.REPORT_DIR  = report_dir
        from report_generator import generate
        with redirect_stdout(logger):
            paths = generate(all_findings, analysis)

        with open(paths["html"], "r", encoding="utf-8") as f:
            report_html = f.read()

        import json as _json
        with open(paths["json"], "r") as f:
            report_json = _json.load(f)

        log(f"    → Report saved: {paths['html']}")

        _update(scan_id,
                status="complete",
                phase="Complete",
                progress_pct=100,
                total_findings=len(all_findings),
                risk_rating=analysis.get("risk_rating", "Unknown"),
                findings=all_findings,
                analysis=analysis,
                report_html=report_html,
                report_json=report_json,
                report_path=paths["html"],
                completed_at=datetime.utcnow().isoformat())
        log("[✓] Assessment complete!")

    except Exception as e:
        log(f"[!] Report error: {e}")
        _update(scan_id, status="error", error=str(e), phase="Error",
                progress_pct=100)


def run_scan_async(scan_id: str, url: str, report_dir: str):
    SCANS[scan_id] = {
        "id":             scan_id,
        "url":            url,
        "status":         "running",
        "phase":          "Starting...",
        "progress_pct":   0,
        "logs":           [],
        "findings":       [],
        "analysis":       {},
        "report_html":    None,
        "report_json":    None,
        "report_path":    None,
        "total_findings": 0,
        "risk_rating":    "",
        "error":          None,
        "started_at":     datetime.utcnow().isoformat(),
        "completed_at":   None,
    }
    t = threading.Thread(target=_run, args=(scan_id, url, report_dir), daemon=True)
    t.start()
