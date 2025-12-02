#!/usr/bin/env python3
"""
Recon Orchestrator

Features:
- Input: TLD / domain
- Tools: amass, ffuf, httpx, nuclei, nikto
- Auto-install (best effort) if tools are missing
- Optional Amass API key setup on first run
- Subdomain enumeration (amass + ffuf brute)
- Dedup + stateful JSON DB for progress/resume
- HTTP probing (httpx)
- Vuln scanning (nuclei, nikto)
- One shared HTML dashboard updated every N seconds
- Safe to run multiple times concurrently on the same machine
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import parse_qs

# ====================== CONFIG ======================

DATA_DIR = Path("recon_data")
STATE_FILE = DATA_DIR / "state.json"
HTML_DASHBOARD_FILE = DATA_DIR / "dashboard.html"
LOCK_FILE = DATA_DIR / ".lock"
CONFIG_FILE = DATA_DIR / "config.json"

DEFAULT_INTERVAL = 30
HTML_REFRESH_SECONDS = DEFAULT_INTERVAL  # default; can be overridden

# Tool names (can be adjusted per OS if needed)
TOOLS = {
    "amass": "amass",
    "ffuf": "ffuf",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "nikto": "nikto"
}

CONFIG_LOCK = threading.Lock()
CONFIG: Dict[str, Any] = {}


# ================== UTILITIES =======================

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts} UTC] {msg}")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def default_config() -> Dict[str, Any]:
    base = str(DATA_DIR.resolve())
    return {
        "data_dir": base,
        "state_file": str(STATE_FILE.resolve()),
        "dashboard_file": str(HTML_DASHBOARD_FILE.resolve()),
        "default_interval": DEFAULT_INTERVAL,
        "default_wordlist": "",
        "skip_nikto_by_default": False,
    }


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_dirs()
    tmp_path = CONFIG_FILE.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
    tmp_path.replace(CONFIG_FILE)
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)


def load_config() -> Dict[str, Any]:
    ensure_dirs()
    cfg = default_config()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for key in cfg.keys():
                    if key in data:
                        cfg[key] = data[key]
        except Exception as e:
            log(f"Error loading config.json: {e}")
    else:
        save_config(cfg)
        return cfg
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)
    return dict(CONFIG)


def get_config() -> Dict[str, Any]:
    with CONFIG_LOCK:
        if CONFIG:
            return dict(CONFIG)
    return load_config()


def bool_from_value(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        val = value.strip().lower()
        return val in {"1", "true", "yes", "on"}
    return default


def update_config_settings(values: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    cfg = get_config()
    changed = False

    if "default_wordlist" in values:
        new_wordlist = str(values.get("default_wordlist") or "").strip()
        if cfg.get("default_wordlist", "") != new_wordlist:
            cfg["default_wordlist"] = new_wordlist
            changed = True

    if "default_interval" in values:
        try:
            new_interval = max(5, int(values.get("default_interval")))
        except (TypeError, ValueError):
            return False, "Default interval must be an integer >= 5.", cfg
        if cfg.get("default_interval") != new_interval:
            cfg["default_interval"] = new_interval
            changed = True

    if "skip_nikto_by_default" in values:
        new_skip = bool_from_value(
            values.get("skip_nikto_by_default"),
            cfg.get("skip_nikto_by_default", False)
        )
        if cfg.get("skip_nikto_by_default") != new_skip:
            cfg["skip_nikto_by_default"] = new_skip
            changed = True

    if changed:
        save_config(cfg)
        return True, "Settings updated.", cfg
    return True, "No changes applied.", cfg


def acquire_lock(timeout: int = 10) -> None:
    """
    Very simple file lock; best-effort to avoid concurrent writes.
    """
    start = time.time()
    while True:
        try:
            # use exclusive create
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return
        except FileExistsError:
            if time.time() - start > timeout:
                log("Lock timeout reached, proceeding anyway (best effort).")
                return
            time.sleep(0.1)


def release_lock() -> None:
    try:
        LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def load_state() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {
            "version": 1,
            "targets": {},
            "last_updated": None
        }
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"Error loading state.json: {e}")
        return {
            "version": 1,
            "targets": {},
            "last_updated": None
        }


def save_state(state: Dict[str, Any]) -> None:
    state["last_updated"] = datetime.now(timezone.utc).isoformat()
    acquire_lock()
    try:
        tmp_path = STATE_FILE.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        tmp_path.replace(STATE_FILE)
    finally:
        release_lock()
    try:
        generate_html_dashboard(state)
    except Exception as e:
        log(f"Error refreshing dashboard HTML: {e}")


def ensure_tool_installed(tool: str) -> bool:
    """
    Best-effort install using apt, then brew, then go install (for some tools).
    Returns True if tool is available after this, False otherwise.
    """
    exe = TOOLS[tool]
    if shutil.which(exe):
        log(f"{tool} already installed.")
        return True

    log(f"{tool} not found. Attempting to install (best effort).")

    # Try apt
    try:
        if shutil.which("apt-get"):
            log(f"Trying: sudo apt-get update && sudo apt-get install -y {exe}")
            subprocess.run(
                ["sudo", "apt-get", "update"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", exe],
                check=False,
            )
            if shutil.which(exe):
                log(f"{tool} installed via apt-get.")
                return True
    except Exception as e:
        log(f"apt-get install attempt failed for {tool}: {e}")

    # Try Homebrew
    try:
        if shutil.which("brew"):
            log(f"Trying: brew install {exe}")
            subprocess.run(
                ["brew", "install", exe],
                check=False,
            )
            if shutil.which(exe):
                log(f"{tool} installed via brew.")
                return True
    except Exception as e:
        log(f"brew install attempt failed for {tool}: {e}")

    # Try go install for some known tools
    try:
        if shutil.which("go") and tool in {"amass", "httpx", "nuclei"}:
            go_pkgs = {
                "amass": "github.com/owasp-amass/amass/v3/...@latest",
                "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            }
            pkg = go_pkgs[tool]
            log(f"Trying: go install {pkg}")
            subprocess.run(["go", "install", pkg], check=False)
            if shutil.which(exe):
                log(f"{tool} installed via go install.")
                return True
    except Exception as e:
        log(f"go install attempt failed for {tool}: {e}")

    log(
        f"Could not auto-install {tool}. Please install it manually and re-run. "
        f"Checked binary name: {exe}"
    )
    return False


# ================== AMASS CONFIG ==================

def ensure_amass_config_interactive() -> None:
    """
    If no amass config is found, optionally ask user if they want a basic template
    and (optionally) enter some keys.
    """
    config_dir = Path.home() / ".config" / "amass"
    config_file = config_dir / "config.ini"

    if config_file.exists():
        return

    if not sys.stdin.isatty():
        log("No Amass config.ini found and running non-interactively; skipping auto setup.")
        return

    log("No Amass config.ini found (~/.config/amass/config.ini).")
    try:
        ans = input("Do you want to generate a basic Amass config and optionally enter API keys? [y/N]: ").strip().lower()
    except EOFError:
        # Non-interactive case, just skip
        return

    if ans != "y":
        log("Skipping Amass API key setup.")
        return

    config_dir.mkdir(parents=True, exist_ok=True)

    # Ask optionally for some keys
    providers = {
        "shodan": None,
        "virustotal": None,
        "securitytrails": None,
        "censys": None,
        "passivetotal": None,
    }

    log("Press Enter to skip any provider.")
    for name in list(providers.keys()):
        try:
            key = input(f"Enter API key for {name} (or leave blank): ").strip()
        except EOFError:
            key = ""
        providers[name] = key or None

    # Write basic config.ini
    lines = [
        "# Generated by recon_dashboard.py",
        "[resolvers]",
        "dns = 8.8.8.8, 1.1.1.1",
        "",
        "[datasources]",
    ]
    for name, key in providers.items():
        if key:
            lines.append(f"    [{name}]")
            lines.append(f"    apikey = {key}")
            lines.append("")
        else:
            # add commented stub
            lines.append(f"    #[{name}]")
            lines.append("    #apikey = YOUR_KEY_HERE")
            lines.append("")

    config_file.write_text("\n".join(lines), encoding="utf-8")
    log(f"Amass config created at {config_file}. You can tweak it later if needed.")


# ================== PIPELINE STEPS ==================

def run_subprocess(cmd, outfile=None):
    log("Running: " + " ".join(cmd))
    try:
        if outfile:
            out = open(outfile, "w", encoding="utf-8")
        else:
            out = subprocess.DEVNULL

        result = subprocess.run(
            cmd,
            stdout=out,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )

        if outfile:
            out.close()

        if result.returncode != 0:
            stderr_preview = (result.stderr or "")[:500]
            log(
                f"Command failed (return code {result.returncode}): "
                + " ".join(cmd)
                + "\nstderr: " + stderr_preview
            )
            return False

    except FileNotFoundError:
        log(f"Command not found: {cmd[0]}")
        return False

    except Exception as e:
        log("Error running command " + " ".join(cmd) + f": {e}")
        return False

    return True


def amass_enum(domain: str) -> Path:
    """
    Run Amass enum with JSON output and return path to JSON file.
    """
    if not ensure_tool_installed("amass"):
        return None

    ensure_amass_config_interactive()

    out_base = DATA_DIR / f"amass_{domain}"
    out_json = out_base.with_suffix(".json")
    cmd = [
        TOOLS["amass"],
        "enum",
        "-d", domain,
        "-oA", str(out_base),
    ]
    success = run_subprocess(cmd)
    return out_json if success and out_json.exists() else None


def parse_amass_json(json_path: Path) -> List[str]:
    subs = set()
    if not json_path or not json_path.exists():
        return []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    name = obj.get("name")
                    if name:
                        subs.add(name.strip().lower())
                except Exception:
                    continue
    except Exception as e:
        log(f"Error parsing Amass JSON: {e}")
    return sorted(subs)


def ffuf_bruteforce(domain: str, wordlist: str) -> List[str]:
    """
    Use ffuf to brute-force vhosts via Host header.
    This is HTTP-based vhost brute, not pure DNS brute, but still useful.
    """
    if not ensure_tool_installed("ffuf"):
        return []

    out_json = DATA_DIR / f"ffuf_{domain}.json"
    # NOTE: user can tune -mc, -fs, etc to avoid wildcard noise.
    cmd = [
        TOOLS["ffuf"],
        "-u", f"http://{domain}",
        "-H", "Host: FUZZ." + domain,
        "-w", wordlist,
        "-of", "json",
        "-o", str(out_json),
        "-mc", "200,301,302,403,401"
    ]
    success = run_subprocess(cmd)
    if not success or not out_json.exists():
        return []

    subs = set()
    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
        for r in data.get("results", []):
            host = r.get("host") or r.get("url")
            if host:
                # ffuf may show host as FUZZ.domain.tld
                host = host.replace("https://", "").replace("http://", "").split("/")[0]
                subs.add(host.lower())
    except Exception as e:
        log(f"Error parsing ffuf JSON: {e}")
    return sorted(subs)


def write_subdomains_file(domain: str, subs: List[str]) -> Path:
    out_path = DATA_DIR / f"subs_{domain}.txt"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for s in sorted(set(subs)):
                f.write(s + "\n")
    except Exception as e:
        log(f"Error writing subdomains file: {e}")
    return out_path


def httpx_scan(subs_file: Path, domain: str) -> Path:
    if not ensure_tool_installed("httpx"):
        return None
    out_json = DATA_DIR / f"httpx_{domain}.json"
    cmd = [
        TOOLS["httpx"],
        "-l", str(subs_file),
        "-json",
        "-o", str(out_json),
        "-timeout", "10",
        "-follow-redirects",
        "-silent",
    ]
    success = run_subprocess(cmd)
    return out_json if success and out_json.exists() else None


def nuclei_scan(subs_file: Path, domain: str) -> Path:
    if not ensure_tool_installed("nuclei"):
        return None
    out_json = DATA_DIR / f"nuclei_{domain}.json"
    cmd = [
        TOOLS["nuclei"],
        "-l", str(subs_file),
        "-json",
        "-o", str(out_json),
        "-silent",
    ]
    success = run_subprocess(cmd)
    return out_json if success and out_json.exists() else None


def nikto_scan(subs: List[str], domain: str) -> Path:
    if not ensure_tool_installed("nikto"):
        return None
    out_json = DATA_DIR / f"nikto_{domain}.json"

    results = []
    for host in subs:
        target = f"http://{host}"
        cmd = [
            TOOLS["nikto"],
            "-h", target,
            "-Format", "json",
            "-output", "-",
        ]
        log(f"Running nikto against {target}")
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                log(f"Nikto failed for {host}: {proc.stderr[:300]}")
                continue
            # Nikto sometimes outputs multiple JSON objects; attempt to parse leniently
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    results.append(obj)
                except Exception:
                    continue
        except FileNotFoundError:
            log("Nikto binary not found during run.")
            break
        except Exception as e:
            log(f"Nikto error for {host}: {e}")
            continue

    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        log(f"Error writing Nikto JSON: {e}")
        return None

    return out_json if out_json.exists() else None


# ================== STATE ENRICHMENT ==================

def ensure_target_state(state: Dict[str, Any], domain: str) -> Dict[str, Any]:
    targets = state.setdefault("targets", {})
    tgt = targets.setdefault(domain, {
        "subdomains": {},
        "flags": {
            "amass_done": False,
            "ffuf_done": False,
            "httpx_done": False,
            "nuclei_done": False,
            "nikto_done": False,
        }
    })
    # Normalize missing keys
    tgt.setdefault("subdomains", {})
    tgt.setdefault("flags", {})
    for k in ["amass_done", "ffuf_done", "httpx_done", "nuclei_done", "nikto_done"]:
        tgt["flags"].setdefault(k, False)
    return tgt


def add_subdomains_to_state(state: Dict[str, Any], domain: str, subs: List[str], source: str) -> None:
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for s in subs:
        s = s.strip().lower()
        if not s:
            continue
        entry = submap.setdefault(s, {
            "sources": [],
            "httpx": None,
            "nuclei": [],
            "nikto": [],
        })
        if "sources" not in entry:
            entry["sources"] = []
        if source not in entry["sources"]:
            entry["sources"].append(source)


def enrich_state_with_httpx(state: Dict[str, Any], domain: str, httpx_json: Path) -> None:
    if not httpx_json or not httpx_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        with open(httpx_json, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                host = obj.get("host") or obj.get("url")
                if not host:
                    continue
                host = host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                entry = submap.setdefault(host, {
                    "sources": [],
                    "httpx": None,
                    "nuclei": [],
                    "nikto": [],
                })
                entry["httpx"] = {
                    "url": obj.get("url"),
                    "status_code": obj.get("status_code"),
                    "content_length": obj.get("content_length"),
                    "title": obj.get("title"),
                    "webserver": obj.get("webserver"),
                    "tech": obj.get("tech"),
                }
    except Exception as e:
        log(f"Error enriching state with httpx data: {e}")


def enrich_state_with_nuclei(state: Dict[str, Any], domain: str, nuclei_json: Path) -> None:
    if not nuclei_json or not nuclei_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        with open(nuclei_json, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                host = obj.get("host") or obj.get("matched-at") or obj.get("url")
                if not host:
                    continue
                host = host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                entry = submap.setdefault(host, {
                    "sources": [],
                    "httpx": None,
                    "nuclei": [],
                    "nikto": [],
                })
                finding = {
                    "template_id": obj.get("template-id"),
                    "name": (obj.get("info") or {}).get("name"),
                    "severity": (obj.get("info") or {}).get("severity"),
                    "matched_at": obj.get("matched-at") or obj.get("url"),
                }
                entry.setdefault("nuclei", []).append(finding)
    except Exception as e:
        log(f"Error enriching state with nuclei data: {e}")


def enrich_state_with_nikto(state: Dict[str, Any], domain: str, nikto_json: Path) -> None:
    if not nikto_json or not nikto_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        data = json.loads(nikto_json.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = [data]
        for obj in data:
            host = obj.get("host") or obj.get("target") or obj.get("banner")
            if not host:
                continue
            host = str(host).replace("https://", "").replace("http://", "").split("/")[0].lower()
            entry = submap.setdefault(host, {
                "sources": [],
                "httpx": None,
                "nuclei": [],
                "nikto": [],
            })
            vulns = obj.get("vulnerabilities") or obj.get("vulns") or []
            normalized_vulns = []
            for v in vulns:
                if isinstance(v, dict):
                    normalized_vulns.append({
                        "id": v.get("id"),
                        "msg": v.get("msg") or v.get("description"),
                        "osvdb": v.get("osvdb"),
                        "risk": v.get("risk"),
                        "uri": v.get("uri"),
                    })
                else:
                    normalized_vulns.append({"raw": str(v)})
            entry.setdefault("nikto", []).extend(normalized_vulns)
    except Exception as e:
        log(f"Error enriching state with nikto data: {e}")


# ================== DASHBOARD GENERATION ==================

def generate_html_dashboard(state: Optional[Dict[str, Any]] = None) -> None:
    """
    Generate a single HTML file from the global state.
    All runs of this script share this dashboard.
    """
    if state is None:
        state = load_state()
    targets = state.get("targets", {})

    # Very simple HTML; auto-refresh via meta
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        f"<meta http-equiv='refresh' content='{HTML_REFRESH_SECONDS}'>",
        "<title>Recon Dashboard</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; padding: 20px; }",
        "h1 { color:#facc15; }",
        "h2 { color:#93c5fd; }",
        "table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }",
        "th, td { border: 1px solid #1f2937; padding: 4px 6px; font-size: 12px; }",
        "th { background:#111827; }",
        "tr:nth-child(even) { background:#020617; }",
        ".tag { display:inline-block; padding:2px 6px; border-radius:999px; margin-right:4px; font-size:10px; }",
        ".sev-low { background:#0f766e; }",
        ".sev-medium { background:#eab308; }",
        ".sev-high { background:#f97316; }",
        ".sev-critical { background:#b91c1c; }",
        ".badge { background:#1f2937; padding:2px 6px; border-radius:999px; font-size:11px; margin-right:4px; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Recon Dashboard</h1>",
        f"<p>Last updated: {state.get('last_updated', 'never')}</p>",
    ]

    for domain, tgt in sorted(targets.items(), key=lambda x: x[0]):
        subs = tgt.get("subdomains", {})
        flags = tgt.get("flags", {})
        html_parts.append(f"<h2>{domain}</h2>")
        html_parts.append(
            "<p>"
            f"<span class='badge'>Subdomains: {len(subs)}</span>"
            f"<span class='badge'>Amass: {'✅' if flags.get('amass_done') else '⏳'}</span>"
            f"<span class='badge'>ffuf: {'✅' if flags.get('ffuf_done') else '⏳'}</span>"
            f"<span class='badge'>httpx: {'✅' if flags.get('httpx_done') else '⏳'}</span>"
            f"<span class='badge'>nuclei: {'✅' if flags.get('nuclei_done') else '⏳'}</span>"
            f"<span class='badge'>nikto: {'✅' if flags.get('nikto_done') else '⏳'}</span>"
            "</p>"
        )

        html_parts.append("<table>")
        html_parts.append(
            "<tr>"
            "<th>#</th>"
            "<th>Subdomain</th>"
            "<th>Sources</th>"
            "<th>HTTP</th>"
            "<th>Nuclei Findings</th>"
            "<th>Nikto Findings</th>"
            "</tr>"
        )
        for idx, (sub, info) in enumerate(sorted(subs.items(), key=lambda x: x[0]), start=1):
            sources = info.get("sources", [])
            httpx = info.get("httpx") or {}
            nuclei = info.get("nuclei") or []
            nikto = info.get("nikto") or []

            # HTTP summary
            http_summary = ""
            if httpx:
                http_summary = (
                    f"{httpx.get('status_code')} "
                    f"{httpx.get('title') or ''} "
                    f"[{httpx.get('webserver') or ''}]"
                )

            # Nuclei summary
            nuclei_bits = []
            for n in nuclei:
                sev = (n.get("severity") or "info").lower()
                cls = "sev-" + ("critical" if sev == "critical"
                                else "high" if sev == "high"
                                else "medium" if sev == "medium"
                                else "low")
                nuclei_bits.append(
                    f"<span class='tag {cls}'>{sev}: {n.get('template_id')}</span>"
                )
            nuclei_html = " ".join(nuclei_bits)

            # Nikto summary
            nikto_html = ""
            if nikto:
                nikto_html = f"{len(nikto)} findings"

            html_parts.append(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td>{sub}</td>"
                f"<td>{', '.join(sources)}</td>"
                f"<td>{http_summary}</td>"
                f"<td>{nuclei_html}</td>"
                f"<td>{nikto_html}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    html_parts.append("</body></html>")

    acquire_lock()
    try:
        tmp = HTML_DASHBOARD_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))
        tmp.replace(HTML_DASHBOARD_FILE)
    finally:
        release_lock()


# ================== MAIN PIPELINE ==================

def run_pipeline(domain: str, wordlist: Optional[str], skip_nikto: bool = False, interval: int = DEFAULT_INTERVAL) -> None:
    ensure_dirs()
    config = get_config()
    if not wordlist:
        default_wordlist = config.get("default_wordlist") or ""
        wordlist = default_wordlist or None

    global HTML_REFRESH_SECONDS
    HTML_REFRESH_SECONDS = max(5, interval)

    # Load state
    state = load_state()
    tgt = ensure_target_state(state, domain)
    flags = tgt["flags"]

    # ---------- Amass ----------
    if not flags.get("amass_done"):
        log(f"=== Amass enumeration for {domain} ===")
        amass_json = amass_enum(domain)
        if amass_json:
            subs = parse_amass_json(amass_json)
            log(f"Amass found {len(subs)} subdomains.")
            add_subdomains_to_state(state, domain, subs, "amass")
            flags["amass_done"] = True
            save_state(state)
        else:
            log("Amass enumeration skipped/failed; continuing.")

    # ---------- ffuf ----------
    if not flags.get("ffuf_done"):
        if not wordlist or not Path(wordlist).exists():
            log("ffuf wordlist not provided or not found; skipping ffuf brute-force.")
        else:
            log(f"=== ffuf brute-force for {domain} using {wordlist} ===")
            subs_ffuf = ffuf_bruteforce(domain, wordlist)
            log(f"ffuf found {len(subs_ffuf)} vhost subdomains.")
            add_subdomains_to_state(state, domain, subs_ffuf, "ffuf")
            flags["ffuf_done"] = True
            save_state(state)

    # Dedup & write subdomains file
    all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())
    log(f"Total unique subdomains for {domain}: {len(all_subs)}")
    subs_file = write_subdomains_file(domain, all_subs)

    # ---------- httpx ----------
    if not flags.get("httpx_done"):
        log(f"=== httpx scan for {domain} ({len(all_subs)} hosts) ===")
        httpx_json = httpx_scan(subs_file, domain)
        enrich_state_with_httpx(state, domain, httpx_json)
        flags["httpx_done"] = True
        save_state(state)

    # ---------- nuclei ----------
    if not flags.get("nuclei_done"):
        log(f"=== nuclei scan for {domain} ({len(all_subs)} hosts) ===")
        nuclei_json = nuclei_scan(subs_file, domain)
        enrich_state_with_nuclei(state, domain, nuclei_json)
        flags["nuclei_done"] = True
        save_state(state)

    # ---------- nikto ----------
    if not skip_nikto and not flags.get("nikto_done"):
        log(f"=== nikto scan for {domain} ({len(all_subs)} hosts) ===")
        nikto_json = nikto_scan(all_subs, domain)
        enrich_state_with_nikto(state, domain, nikto_json)
        flags["nikto_done"] = True
        save_state(state)
    elif skip_nikto:
        log("Skipping nikto because --skip-nikto was set.")

    log("Pipeline finished for this run.")


# ================== WEB COMMAND CENTER ==================

RUNNING_JOBS: Dict[str, Dict[str, Any]] = {}
JOB_LOCK = threading.Lock()

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Command Center</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: Arial, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:20px; }
h1, h2, h3, h4 { margin:0; }
a { color:#93c5fd; }
code { background:#1e293b; padding:2px 4px; border-radius:4px; font-size:12px; }
.muted { color:#94a3b8; font-size:14px; }
.layout { max-width:1200px; margin:0 auto; }
.panel { background:#111827; padding:20px; border-radius:12px; margin-bottom:20px; box-shadow:0 10px 25px rgba(0,0,0,0.3); }
.panel h2 { color:#fbbf24; margin-bottom:12px; }
label { display:block; font-weight:bold; margin-bottom:8px; }
input[type="text"], input[type="number"] { width:100%; padding:10px; border-radius:8px; border:1px solid #1f2937; background:#0f172a; color:#f8fafc; }
.checkbox { display:flex; align-items:center; gap:8px; font-weight:600; margin-top:12px; }
.checkbox input { width:auto; }
button { background:#2563eb; border:none; padding:10px 18px; border-radius:8px; color:white; font-size:15px; cursor:pointer; }
button:hover { background:#1d4ed8; }
.status { margin-top:10px; min-height:20px; }
.status.error { color:#f87171; }
.status.success { color:#4ade80; }
.success { color:#4ade80; }
.error { color:#f87171; }
.targets { display:flex; flex-direction:column; gap:18px; }
.target-card { border:1px solid #1e293b; border-radius:12px; padding:16px; background:#0f172a; }
.target-header { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px; }
.badge { background:#1e293b; padding:4px 10px; border-radius:999px; font-size:12px; margin-right:6px; display:inline-block; }
table { width:100%; border-collapse:collapse; margin-top:12px; }
th, td { border:1px solid #1f2937; padding:6px 8px; font-size:12px; }
th { background:#1e293b; text-align:left; }
tr:nth-child(even) { background:#0b152c; }
.tag { display:inline-block; padding:2px 6px; border-radius:8px; margin:2px; font-size:11px; }
.sev-low { background:#0f766e; }
.sev-medium { background:#eab308; }
.sev-high { background:#f97316; }
.sev-critical { background:#b91c1c; }
.settings-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; }
.tool-list { list-style:none; padding-left:0; margin:8px 0 0 0; }
.tool-list li { margin-bottom:4px; }
</style>
</head>
<body>
<div class="layout">
  <header class="panel">
    <h1>Recon Command Center</h1>
    <p id="last-updated" class="muted">Last updated: never</p>
  </header>

  <section class="panel">
    <h2>Launch New Recon</h2>
    <form id="launch-form">
      <label>Domain / TLD
        <input id="launch-domain" type="text" name="domain" placeholder="example.com" required />
      </label>
      <label>Wordlist path (optional)
        <input id="launch-wordlist" type="text" name="wordlist" placeholder="./w.txt" />
      </label>
      <label>Dashboard interval seconds
        <input id="launch-interval" type="number" name="interval" min="5" />
      </label>
      <label class="checkbox">
        <input id="launch-skip-nikto" type="checkbox" name="skip_nikto" />
        Skip Nikto for this run
      </label>
      <button type="submit">Start Recon</button>
    </form>
    <div class="status" id="launch-status"></div>
  </section>

  <section class="panel">
    <h2>Settings</h2>
    <div id="settings-summary" class="muted">Loading settings…</div>
    <form id="settings-form">
      <div class="settings-grid">
        <label>Default wordlist
          <input id="settings-wordlist" type="text" name="default_wordlist" placeholder="./w.txt" />
        </label>
        <label>Default interval (seconds)
          <input id="settings-interval" type="number" name="default_interval" min="5" />
        </label>
      </div>
      <label class="checkbox">
        <input id="settings-skip-nikto" type="checkbox" name="skip_nikto_by_default" />
        Skip Nikto by default
      </label>
      <button type="submit">Save Settings</button>
    </form>
    <div class="status" id="settings-status"></div>
  </section>

  <section class="panel">
    <h2>Active Jobs</h2>
    <div id="active-jobs" class="muted">No active jobs.</div>
  </section>

  <section class="panel">
    <h2>Targets</h2>
    <div id="targets" class="targets">
      <p class="muted">No reconnaissance data yet.</p>
    </div>
  </section>
</div>

<script>
const POLL_INTERVAL = 8000;
const launchForm = document.getElementById('launch-form');
const launchWordlist = document.getElementById('launch-wordlist');
const launchInterval = document.getElementById('launch-interval');
const launchSkipNikto = document.getElementById('launch-skip-nikto');
const launchStatus = document.getElementById('launch-status');
const settingsForm = document.getElementById('settings-form');
const settingsWordlist = document.getElementById('settings-wordlist');
const settingsInterval = document.getElementById('settings-interval');
const settingsSkipNikto = document.getElementById('settings-skip-nikto');
const settingsStatus = document.getElementById('settings-status');
const settingsSummary = document.getElementById('settings-summary');
let launchFormDirty = false;
let settingsFormDirty = false;

function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderJobs(jobs) {
  const container = document.getElementById('active-jobs');
  if (!jobs || jobs.length === 0) {
    container.innerHTML = '<p class="muted">No active jobs.</p>';
    return;
  }
  const items = jobs.map(job => {
    const nikto = job.skip_nikto ? ' (Nikto skipped)' : '';
    const wl = job.wordlist ? ` wordlist: ${escapeHtml(job.wordlist)}` : '';
    return `<li><strong>${escapeHtml(job.domain)}</strong> since ${escapeHtml(job.started || 'now')}${wl}${nikto}</li>`;
  });
  container.innerHTML = `<ul>${items.join('')}</ul>`;
}

function renderTargets(targets) {
  const container = document.getElementById('targets');
  if (!targets || Object.keys(targets).length === 0) {
    container.innerHTML = '<p class="muted">No reconnaissance data yet.</p>';
    return;
  }
  const cards = [];
  const flagIcon = (label, done) => `<span class="badge">${label}: ${done ? '✅' : '⏳'}</span>`;

  Object.keys(targets).sort().forEach(domain => {
    const info = targets[domain] || {};
    const subs = info.subdomains || {};
    const flags = info.flags || {};
    const header = `
      <div class="target-header">
        <h3>${escapeHtml(domain)}</h3>
        <div>
          ${flagIcon('Subdomains', Object.keys(subs).length)}
          ${flagIcon('Amass', flags.amass_done)}
          ${flagIcon('ffuf', flags.ffuf_done)}
          ${flagIcon('httpx', flags.httpx_done)}
          ${flagIcon('nuclei', flags.nuclei_done)}
          ${flagIcon('nikto', flags.nikto_done)}
        </div>
      </div>
    `;

    const rows = Object.keys(subs).sort().map((sub, idx) => {
      const entry = subs[sub] || {};
      const httpx = entry.httpx || {};
      const nuclei = Array.isArray(entry.nuclei) ? entry.nuclei : [];
      const nikto = Array.isArray(entry.nikto) ? entry.nikto : [];
      const httpSummary = httpx.status_code ? `${httpx.status_code} ${escapeHtml(httpx.title || '')} [${escapeHtml(httpx.webserver || '')}]` : '';

      const nucleiTags = nuclei.map(n => {
        const sev = (n.severity || 'info').toLowerCase();
        const cls = sev === 'critical' ? 'sev-critical' :
                    sev === 'high' ? 'sev-high' :
                    sev === 'medium' ? 'sev-medium' : 'sev-low';
        return `<span class="tag ${cls}">${escapeHtml(sev)}: ${escapeHtml(n.template_id || '')}</span>`;
      }).join('');

      const niktoText = nikto.length ? `${nikto.length} findings` : '';
      const sources = Array.isArray(entry.sources) ? entry.sources.join(', ') : '';

      return `
        <tr>
          <td>${idx + 1}</td>
          <td>${escapeHtml(sub)}</td>
          <td>${escapeHtml(sources)}</td>
          <td>${escapeHtml(httpSummary)}</td>
          <td>${nucleiTags}</td>
          <td>${escapeHtml(niktoText)}</td>
        </tr>
      `;
    }).join('');

    const table = rows ? `
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Subdomain</th>
            <th>Sources</th>
            <th>HTTP</th>
            <th>Nuclei</th>
            <th>Nikto</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    ` : '<p class="muted">No subdomains collected yet.</p>';

    cards.push(`<div class="target-card">${header}${table}</div>`);
  });

  container.innerHTML = cards.join('');
}

function renderSettings(config, tools) {
  const toolItems = Object.keys(tools || {}).sort().map(name => {
    const path = tools[name];
    const status = path ? `<span class="success">found</span> <code>${escapeHtml(path)}</code>` : '<span class="error">missing</span>';
    return `<li><strong>${escapeHtml(name)}</strong>: ${status}</li>`;
  }).join('');

  settingsSummary.innerHTML = `
    <div class="settings-grid">
      <div>
        <strong>Results directory</strong>
        <p><code>${escapeHtml(config.data_dir || '')}</code></p>
      </div>
      <div>
        <strong>state.json</strong>
        <p><code>${escapeHtml(config.state_file || '')}</code></p>
      </div>
      <div>
        <strong>dashboard.html</strong>
        <p><code>${escapeHtml(config.dashboard_file || '')}</code></p>
      </div>
    </div>
    <h4>Toolchain</h4>
    <ul class="tool-list">${toolItems || '<li>No tool data.</li>'}</ul>
  `;

  if (!settingsFormDirty) {
    settingsWordlist.value = config.default_wordlist || '';
    settingsInterval.value = config.default_interval || 30;
    settingsSkipNikto.checked = !!config.skip_nikto_by_default;
  }

  if (!launchFormDirty) {
    launchWordlist.value = config.default_wordlist || '';
    launchInterval.value = config.default_interval || 30;
    launchSkipNikto.checked = !!config.skip_nikto_by_default;
  }
}

async function fetchState() {
  try {
    const resp = await fetch('/api/state');
    if (!resp.ok) throw new Error('Failed to fetch state');
    const data = await resp.json();
    document.getElementById('last-updated').textContent = 'Last updated: ' + (data.last_updated || 'never');
    renderJobs(data.running_jobs || []);
    renderTargets(data.targets || {});
    renderSettings(data.config || {}, data.tools || {});
  } catch (err) {
    document.getElementById('targets').innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

launchForm.addEventListener('input', () => { launchFormDirty = true; });
settingsForm.addEventListener('input', () => { settingsFormDirty = true; });

launchForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    domain: event.target.domain.value,
    wordlist: launchWordlist.value,
    interval: launchInterval.value,
    skip_nikto: launchSkipNikto.checked,
  };
  launchStatus.textContent = 'Dispatching...';
  launchStatus.className = 'status';
  try {
    const resp = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    launchStatus.textContent = data.message || 'Done';
    launchStatus.className = 'status ' + (data.success ? 'success' : 'error');
    if (data.success) {
      event.target.reset();
      launchFormDirty = false;
      fetchState();
    }
  } catch (err) {
    launchStatus.textContent = err.message;
    launchStatus.className = 'status error';
  }
});

settingsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    default_wordlist: settingsWordlist.value,
    default_interval: settingsInterval.value,
    skip_nikto_by_default: settingsSkipNikto.checked,
  };
  settingsStatus.textContent = 'Saving...';
  settingsStatus.className = 'status';
  try {
    const resp = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    settingsStatus.textContent = data.message || 'Saved';
    settingsStatus.className = 'status ' + (data.success ? 'success' : 'error');
    if (data.success) {
      settingsFormDirty = false;
      fetchState();
    }
  } catch (err) {
    settingsStatus.textContent = err.message;
    settingsStatus.className = 'status error';
  }
});

fetchState();
setInterval(fetchState, POLL_INTERVAL);
</script>
</body>
</html>
"""


def snapshot_running_jobs() -> List[Dict[str, Any]]:
    with JOB_LOCK:
        results = []
        for domain, job in RUNNING_JOBS.items():
            results.append({
                "domain": domain,
                "started": job.get("started"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
            })
        return results


def start_pipeline_job(domain: str, wordlist: Optional[str], skip_nikto: bool, interval: Optional[int]) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."

    config = get_config()
    interval_val = max(5, interval or config.get("default_interval", DEFAULT_INTERVAL))
    default_wordlist = config.get("default_wordlist") or ""
    if wordlist is None or (isinstance(wordlist, str) and not wordlist.strip()):
        wordlist_path = default_wordlist.strip()
    else:
        wordlist_path = str(wordlist).strip()

    def job():
        try:
            run_pipeline(normalized, wordlist_path or None, skip_nikto=skip_nikto, interval=interval_val)
        finally:
            with JOB_LOCK:
                RUNNING_JOBS.pop(normalized, None)

    thread = threading.Thread(target=job, name=f"pipeline-{normalized}", daemon=True)

    with JOB_LOCK:
        existing = RUNNING_JOBS.get(normalized)
        if existing and existing.get("thread") and existing["thread"].is_alive():
            return False, f"A job for {normalized} is already running."
        RUNNING_JOBS[normalized] = {
            "thread": thread,
            "started": datetime.now(timezone.utc).isoformat(),
            "wordlist": wordlist_path,
            "skip_nikto": skip_nikto,
            "interval": interval_val,
        }

    log(f"Dispatching recon job for {normalized} (skip_nikto={skip_nikto}).")
    thread.start()
    return True, f"Recon started for {normalized}."


def build_state_payload() -> Dict[str, Any]:
    state = load_state()
    config = get_config()
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    return {
        "last_updated": state.get("last_updated"),
        "targets": state.get("targets", {}),
        "running_jobs": snapshot_running_jobs(),
        "config": config,
        "tools": tool_info,
    }


class CommandCenterHandler(BaseHTTPRequestHandler):
    server_version = "ReconCommandCenter/1.0"

    def _send_bytes(self, payload: bytes, status: HTTPStatus = HTTPStatus.OK, content_type: str = "text/html") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self._send_bytes(data, status=status, content_type="application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_bytes(INDEX_HTML.encode("utf-8"))
            return
        if self.path == "/api/state":
            self._send_json(build_state_payload())
            return
        if self.path == "/api/settings":
            self._send_json({"config": get_config()})
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        if self.path not in {"/api/run", "/api/settings"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        content_type = self.headers.get("Content-Type", "")

        payload = {}
        try:
            if "application/json" in content_type and body:
                payload = json.loads(body)
            else:
                payload = {k: v[0] for k, v in parse_qs(body).items()}
        except json.JSONDecodeError:
            self._send_json({"success": False, "message": "Invalid JSON payload."}, status=HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/run":
            domain = payload.get("domain", "")
            wordlist = payload.get("wordlist")
            interval_val = payload.get("interval")
            interval_int: Optional[int] = None
            if interval_val not in (None, ""):
                try:
                    interval_int = int(interval_val)
                except (TypeError, ValueError):
                    interval_int = None
            skip_default = get_config().get("skip_nikto_by_default", False)
            skip_nikto = bool_from_value(payload.get("skip_nikto"), skip_default)

            success, message = start_pipeline_job(domain, wordlist, skip_nikto, interval_int)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        success, message, cfg = update_config_settings(payload)
        status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
        self._send_json({"success": success, "message": message, "config": cfg}, status=status)

    def log_message(self, format: str, *args) -> None:
        log(f"HTTP {self.address_string()} - {format % args}")


def run_server(host: str, port: int, interval: int) -> None:
    global HTML_REFRESH_SECONDS
    config = get_config()
    refresh = interval or config.get("default_interval", DEFAULT_INTERVAL)
    HTML_REFRESH_SECONDS = max(5, refresh)
    ensure_dirs()
    generate_html_dashboard()
    server = ThreadingHTTPServer((host, port), CommandCenterHandler)
    log(f"Recon Command Center available at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Web server interrupted by user.")
    finally:
        server.server_close()

# ================== CLI ==================

def main():
    parser = argparse.ArgumentParser(description="Recon pipeline + web command center")
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain / TLD (if omitted, launch the web UI instead)."
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Wordlist path for ffuf subdomain brute-force (optional but recommended)."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help="Dashboard refresh interval in seconds (default: 30)."
    )
    parser.add_argument(
        "--skip-nikto",
        action="store_true",
        help="Skip Nikto scanning (can be heavy)."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host/IP for the web UI (default: 127.0.0.1)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8342,
        help="Port for the web UI (default: 8342)."
    )

    args = parser.parse_args()

    if args.domain:
        log(f"Running single pipeline execution for {args.domain}.")
        try:
            run_pipeline(args.domain, args.wordlist, skip_nikto=args.skip_nikto, interval=args.interval)
        except KeyboardInterrupt:
            log("Interrupted by user.")
        except Exception as e:
            log(f"Fatal error: {e}")
        return

    log("Launching Recon Command Center web server.")
    run_server(args.host, args.port, args.interval)


if __name__ == "__main__":
    main()
