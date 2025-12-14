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
import csv
import io
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse, unquote

# ====================== CONFIG ======================

DATA_DIR = Path("recon_data")
STATE_FILE = DATA_DIR / "state.json"
HTML_DASHBOARD_FILE = DATA_DIR / "dashboard.html"
LOCK_FILE = DATA_DIR / ".lock"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_DIR = DATA_DIR / "history"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"

DEFAULT_INTERVAL = 30
HTML_REFRESH_SECONDS = DEFAULT_INTERVAL  # default; can be overridden
MAX_JOB_LOG_LINES = 400
MAX_JOB_LOG_LINE_LENGTH = 500

# Tool names (can be adjusted per OS if needed)
TOOLS = {
    "amass": "amass",
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "findomain": "findomain",
    "sublist3r": "sublist3r",
    "ffuf": "ffuf",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "nikto": "nikto",
    "gowitness": "gowitness",
}

CONFIG_LOCK = threading.Lock()
CONFIG: Dict[str, Any] = {}


class ToolGate:
    def __init__(self, limit: int):
        self._limit = max(1, int(limit))
        self._count = 0
        self._cond = threading.Condition()

    def acquire(self) -> None:
        with self._cond:
            while self._count >= self._limit:
                self._cond.wait()
            self._count += 1

    def release(self) -> None:
        with self._cond:
            if self._count > 0:
                self._count -= 1
            self._cond.notify_all()

    def update_limit(self, limit: int) -> None:
        with self._cond:
            self._limit = max(1, int(limit))
            self._cond.notify_all()

    def snapshot(self) -> Dict[str, int]:
        with self._cond:
            return {
                "limit": self._limit,
                "active": self._count,
            }

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()


TOOL_GATES: Dict[str, ToolGate] = {
    "ffuf": ToolGate(1),
    "nuclei": ToolGate(1),
    "nikto": ToolGate(1),
    "gowitness": ToolGate(1),
}
JOB_QUEUE: deque = deque()
MAX_RUNNING_JOBS = 1
RUNNING_JOBS: Dict[str, Dict[str, Any]] = {}
JOB_LOCK = threading.Lock()
PIPELINE_STEPS = ["amass", "subfinder", "assetfinder", "findomain", "sublist3r", "ffuf", "httpx", "screenshots", "nuclei", "nikto"]
STEP_PROGRESS = {
    "pending": 0,
    "queued": 0,
    "running": 55,
    "completed": 100,
    "skipped": 0,
    "error": 100,
    "failed": 100,
}


# ================== UTILITIES =======================

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts} UTC] {msg}")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def apply_concurrency_limits(cfg: Dict[str, Any]) -> None:
    global MAX_RUNNING_JOBS
    try:
        MAX_RUNNING_JOBS = max(1, int(cfg.get("max_running_jobs", 1)))
    except (TypeError, ValueError):
        MAX_RUNNING_JOBS = 1
    parallel_fields = {
        "ffuf": "max_parallel_ffuf",
        "nuclei": "max_parallel_nuclei",
        "nikto": "max_parallel_nikto",
        "gowitness": "max_parallel_gowitness",
    }
    for tool, field in parallel_fields.items():
        gate = TOOL_GATES.setdefault(tool, ToolGate(1))
        limit = cfg.get(field, 1)
        try:
            limit_int = max(1, int(limit))
        except (TypeError, ValueError):
            limit_int = 1
        gate.update_limit(limit_int)
    schedule_jobs()


def is_subdomain_input(domain: str) -> bool:
    if not domain:
        return False
    parts = [part for part in domain.split(".") if part]
    return len(parts) >= 3


def job_log_append(domain: Optional[str], text: Optional[str], source: str = "system") -> None:
    if not domain or not text:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    lines = str(text).splitlines() or [str(text)]
    entries_to_store = []
    for line in lines[-200:]:
        clean = line.strip("\n")
        if not clean:
            continue
        entry = {
            "ts": timestamp,
            "source": source,
            "text": clean[:MAX_JOB_LOG_LINE_LENGTH],
        }
        entries_to_store.append(entry)
        append_domain_history(domain, entry)

    if not entries_to_store:
        return

    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        entries = job.setdefault("logs", [])
        entries.extend(entries_to_store)
        if len(entries) > MAX_JOB_LOG_LINES:
            job["logs"] = entries[-MAX_JOB_LOG_LINES:]
        else:
            job["logs"] = entries


def default_config() -> Dict[str, Any]:
    base = str(DATA_DIR.resolve())
    return {
        "data_dir": base,
        "state_file": str(STATE_FILE.resolve()),
        "dashboard_file": str(HTML_DASHBOARD_FILE.resolve()),
        "default_interval": DEFAULT_INTERVAL,
        "default_wordlist": "",
        "skip_nikto_by_default": False,
        "enable_screenshots": True,
        "enable_amass": True,
        "amass_timeout": 600,
        "enable_subfinder": True,
        "enable_assetfinder": True,
        "enable_findomain": True,
        "enable_sublist3r": True,
        "subfinder_threads": 32,
        "assetfinder_threads": 10,
        "findomain_threads": 40,
        "max_parallel_ffuf": 1,
        "max_parallel_nuclei": 1,
        "max_parallel_nikto": 1,
        "max_parallel_gowitness": 1,
        "max_running_jobs": 1,
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
    apply_concurrency_limits(cfg)


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
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)
    apply_concurrency_limits(cfg)
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

    if "enable_amass" in values:
        new_amass = bool_from_value(values.get("enable_amass"), cfg.get("enable_amass", True))
        if cfg.get("enable_amass", True) != new_amass:
            cfg["enable_amass"] = new_amass
            changed = True

    for key in ["enable_subfinder", "enable_assetfinder", "enable_findomain", "enable_sublist3r", "enable_screenshots"]:
        if key in values:
            new_value = bool_from_value(values.get(key), cfg.get(key, True))
            if cfg.get(key, True) != new_value:
                cfg[key] = new_value
                changed = True

    concurrency_fields = {
        "max_running_jobs": "Max concurrent jobs",
        "max_parallel_ffuf": "FFUF parallel slots",
        "max_parallel_nuclei": "Nuclei parallel slots",
        "max_parallel_nikto": "Nikto parallel slots",
        "subfinder_threads": "Subfinder threads",
        "assetfinder_threads": "Assetfinder threads",
        "findomain_threads": "Findomain threads",
        "amass_timeout": "Amass timeout (seconds)",
        "max_parallel_gowitness": "Screenshot parallel slots",
    }
    for field, label in concurrency_fields.items():
        if field in values:
            try:
                new_limit = max(1, int(values.get(field)))
            except (TypeError, ValueError):
                return False, f"{label} must be an integer >= 1.", cfg
            if cfg.get(field, 1) != new_limit:
                cfg[field] = new_limit
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


def _candidate_tool_paths(exe: str) -> List[str]:
    """
    Return a de-duplicated list of candidate paths for a tool, checking PATH and common Go bin dirs.
    """
    candidates: List[str] = []
    exe_path = Path(exe)
    if exe_path.is_absolute():
        candidates.append(str(exe_path))
    else:
        found = shutil.which(exe)
        if found:
            candidates.append(found)
    gobin = os.environ.get("GOBIN")
    if gobin:
        candidates.append(str(Path(gobin) / exe))
    gopath = os.environ.get("GOPATH")
    if gopath:
        candidates.append(str(Path(gopath) / "bin" / exe))
    candidates.append(str(Path.home() / "go" / "bin" / exe))
    seen = set()
    ordered: List[str] = []
    for cand in candidates:
        if not cand:
            continue
        if cand in seen:
            continue
        seen.add(cand)
        ordered.append(cand)
    return ordered


def _validate_tool_binary(tool: str, path_str: str) -> bool:
    """
    Ensure we are invoking the intended binary.
    This is mainly to avoid grabbing the Python 'httpx' CLI instead of ProjectDiscovery's tool.
    """
    if not path_str:
        return False
    path = Path(path_str)
    if not path.exists():
        return False
    if tool not in {"httpx", "nuclei"}:
        return True
    try:
        result = subprocess.run(
            [str(path), "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception:
        return False
    output = (result.stdout or "") + (result.stderr or "")
    output_lower = output.lower()
    if tool == "httpx":
        if "projectdiscovery" in output_lower or "httpx version" in output_lower:
            return True
        if "httpx command line client" in output_lower:
            return False
    elif tool == "nuclei":
        if "nuclei engine version" in output_lower or "projectdiscovery" in output_lower:
            return True
    return False


def _resolve_tool_path(tool: str) -> Optional[str]:
    exe = TOOLS[tool]
    candidates = _candidate_tool_paths(exe)
    for cand in candidates:
        if not cand:
            continue
        path = Path(cand)
        if not path.exists():
            continue
        if _validate_tool_binary(tool, cand):
            return cand
        else:
            log(f"Found {tool} at {cand} but it does not look like the expected binary. Ignoring.")
    return None


def ensure_tool_installed(tool: str) -> bool:
    """
    Best-effort install using apt, then brew, then go install (for some tools).
    Returns True if tool is available after this, False otherwise.
    """
    resolved = _resolve_tool_path(tool)
    if resolved:
        TOOLS[tool] = resolved
        log(f"{tool} already installed.")
        return True

    exe = TOOLS[tool]

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
            resolved = _resolve_tool_path(tool)
            if resolved:
                TOOLS[tool] = resolved
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
            resolved = _resolve_tool_path(tool)
            if resolved:
                TOOLS[tool] = resolved
                log(f"{tool} installed via brew.")
                return True
    except Exception as e:
        log(f"brew install attempt failed for {tool}: {e}")

    # Try go install for some known tools
    try:
        if shutil.which("go") and tool in {"amass", "httpx", "nuclei", "subfinder", "assetfinder"}:
            go_pkgs = {
                "amass": "github.com/owasp-amass/amass/v3/...@latest",
                "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "assetfinder": "github.com/tomnomnom/assetfinder@latest",
            }
            pkg = go_pkgs[tool]
            log(f"Trying: go install {pkg}")
            subprocess.run(["go", "install", pkg], check=False)
            resolved = _resolve_tool_path(tool)
            if resolved:
                TOOLS[tool] = resolved
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

def run_subprocess(
    cmd,
    outfile: Optional[Path] = None,
    *,
    job_domain: Optional[str] = None,
    step: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
) -> bool:
    display_cmd = " ".join(cmd)
    log(f"Running: {display_cmd}")
    if job_domain:
        job_log_append(job_domain, f"$ {display_cmd}", source=step or "command")
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update({k: str(v) for k, v in env.items()})

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=merged_env,
            timeout=timeout,
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if outfile:
            try:
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(stdout)
            except Exception as file_err:
                log(f"Error writing {outfile}: {file_err}")

        if job_domain:
            if stdout.strip():
                job_log_append(job_domain, stdout, source=step or cmd[0])
            if stderr.strip():
                job_log_append(job_domain, stderr, source=f"{(step or cmd[0]).upper()} stderr")

        if result.returncode != 0:
            stderr_preview = (stderr or "")[:500]
            log(
                f"Command failed (return code {result.returncode}): "
                + display_cmd
                + "\nstderr: " + stderr_preview
            )
            return False

    except FileNotFoundError:
        log(f"Command not found: {cmd[0]}")
        if job_domain:
            job_log_append(job_domain, f"Command not found: {cmd[0]}", source=step or "system")
        return False

    except Exception as e:
        log("Error running command " + display_cmd + f": {e}")
        if job_domain:
            job_log_append(job_domain, f"Error: {e}", source=step or "system")
        return False

    return True


def amass_enum(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> Path:
    """
    Run Amass enum with JSON output and return path to JSON file.
    """
    if not ensure_tool_installed("amass"):
        return None

    ensure_amass_config_interactive()

    out_base = DATA_DIR / f"amass_{domain}"
    out_json = out_base.with_suffix(".json")
    extra_args = []
    timeout = None
    if config:
        try:
            timeout = int(config.get("amass_timeout"))
            if timeout <= 0:
                timeout = None
        except (TypeError, ValueError):
            timeout = None
        if config.get("amass_passive"):
            extra_args.append("-passive")
    cmd = [
        TOOLS["amass"],
        "enum",
        "-d", domain,
        "-oA", str(out_base),
    ] + extra_args
    success = run_subprocess(cmd, job_domain=job_domain, step="amass", timeout=timeout)
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


def read_lines_file(path: Path) -> List[str]:
    if not path or not path.exists():
        return []
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line.lower())
    except Exception as exc:
        log(f"Error reading {path}: {exc}")
    return lines


def amass_collect_subdomains(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> List[str]:
    amass_json = amass_enum(domain, config=config, job_domain=job_domain)
    return parse_amass_json(amass_json)


def subfinder_enum(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("subfinder"):
        return []
    out_path = DATA_DIR / f"subfinder_{domain}.txt"
    threads = 32
    if config:
        try:
            threads = max(1, int(config.get("subfinder_threads", threads)))
        except (TypeError, ValueError):
            threads = 32
    cmd = [
        TOOLS["subfinder"],
        "-silent",
        "-d", domain,
        "-t", str(threads),
        "-o", str(out_path),
    ]
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="subfinder")
    return read_lines_file(out_path) if success else []


def assetfinder_enum(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("assetfinder"):
        return []
    out_path = DATA_DIR / f"assetfinder_{domain}.txt"
    threads = 10
    if config:
        try:
            threads = max(1, int(config.get("assetfinder_threads", threads)))
        except (TypeError, ValueError):
            threads = 10
    cmd = [
        TOOLS["assetfinder"],
        "--subs-only",
        domain,
    ]
    success = run_subprocess(
        cmd,
        outfile=out_path,
        job_domain=job_domain,
        step="assetfinder",
        env={"GOMAXPROCS": str(threads)},
    )
    return read_lines_file(out_path) if success else []


def findomain_enum(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("findomain"):
        return []
    out_path = DATA_DIR / f"findomain_{domain}.txt"
    threads = 40
    if config:
        try:
            threads = max(1, int(config.get("findomain_threads", threads)))
        except (TypeError, ValueError):
            threads = 40
    cmd = [
        TOOLS["findomain"],
        "--target", domain,
        "--threads", str(threads),
        "--quiet",
        "--output", str(out_path),
    ]
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="findomain")
    return read_lines_file(out_path) if success else []


def sublist3r_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("sublist3r"):
        return []
    out_path = DATA_DIR / f"sublist3r_{domain}.txt"
    cmd = [
        TOOLS["sublist3r"],
        "-d", domain,
        "-o", str(out_path),
    ]
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="sublist3r")
    return read_lines_file(out_path) if success else []


def harvest_enumerator_outputs(
    domain: str,
    config: Dict[str, Any],
    seen_cache: Dict[str, set],
    job_domain: Optional[str] = None,
) -> bool:
    state = None
    added = False

    def ensure_state():
        nonlocal state
        if state is None:
            state = load_state()
        return state

    def process(name: str, enabled: bool, path: Path, parser):
        nonlocal added
        if not enabled:
            return
        if not path.exists():
            return
        try:
            subs = parser(path)
        except Exception as exc:
            log(f"Error parsing {path}: {exc}")
            return
        cache = seen_cache.setdefault(name, set())
        new_items = [s for s in subs if s not in cache]
        if not new_items:
            return
        cache.update(new_items)
        add_subdomains_to_state(ensure_state(), domain, new_items, name)
        job_log_append(job_domain, f"{name} added {len(new_items)} new subdomains.", name)
        added = True

    amass_enabled = config.get("enable_amass", True)
    process(
        "amass",
        amass_enabled,
        DATA_DIR / f"amass_{domain}.json",
        parse_amass_json,
    )
    process(
        "subfinder",
        config.get("enable_subfinder", True),
        DATA_DIR / f"subfinder_{domain}.txt",
        read_lines_file,
    )
    process(
        "assetfinder",
        config.get("enable_assetfinder", True),
        DATA_DIR / f"assetfinder_{domain}.txt",
        read_lines_file,
    )
    process(
        "findomain",
        config.get("enable_findomain", True),
        DATA_DIR / f"findomain_{domain}.txt",
        read_lines_file,
    )
    process(
        "sublist3r",
        config.get("enable_sublist3r", True),
        DATA_DIR / f"sublist3r_{domain}.txt",
        read_lines_file,
    )

    if added and state is not None:
        save_state(state)
    return added


def run_downstream_pipeline(
    domain: str,
    wordlist: Optional[str],
    config: Dict[str, Any],
    skip_nikto: bool,
    interval: int,
    job_domain: Optional[str],
    enumerators_done_event: threading.Event,
) -> None:
    def update_step(step_name: str, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
        job_step_update(job_domain, step_name, status=status, message=message, progress=progress)

    def wait_for_subdomains() -> List[str]:
        while True:
            state = load_state()
            tgt = ensure_target_state(state, domain)
            subs = sorted(tgt["subdomains"].keys())
            if subs or enumerators_done_event.is_set():
                return subs
            time.sleep(5)

    all_subs = wait_for_subdomains()
    log(f"Total unique subdomains for {domain}: {len(all_subs)}")
    subs_file = write_subdomains_file(domain, all_subs)

    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]

    # ---------- ffuf ----------
    if not flags.get("ffuf_done"):
        if not wordlist or (wordlist and not Path(wordlist).exists()):
            log("ffuf wordlist not provided or not found; skipping ffuf brute-force.")
            update_step("ffuf", status="skipped", message="Wordlist missing; ffuf skipped.", progress=0)
        else:
            log(f"=== ffuf brute-force for {domain} using {wordlist} ===")
            update_step("ffuf", status="running", message=f"ffuf running with {wordlist}", progress=50)
            if job_domain:
                job_log_append(job_domain, "Waiting for ffuf slot...", "scheduler")
            with TOOL_GATES["ffuf"]:
                if job_domain:
                    job_log_append(job_domain, "ffuf slot acquired.", "scheduler")
                subs_ffuf = ffuf_bruteforce(domain, wordlist, job_domain=job_domain)
            log(f"ffuf found {len(subs_ffuf)} vhost subdomains.")
            add_subdomains_to_state(state, domain, subs_ffuf, "ffuf")
            flags["ffuf_done"] = True
            save_state(state)
            update_step("ffuf", status="completed", message=f"ffuf found {len(subs_ffuf)} subdomains.", progress=100)
    else:
        update_step("ffuf", status="skipped", message="ffuf already completed for this target.", progress=0)

    # ---------- httpx ----------
    httpx_processed: set = set()
    while True:
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())
        new_hosts = [s for s in all_subs if s not in httpx_processed]
        if not flags.get("httpx_done") and httpx_processed == set():
            log(f"=== httpx scan for {domain} ({len(all_subs)} hosts) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["httpx_done"] = True
                save_state(state)
                update_step("httpx", status="completed", message="httpx scan finished.", progress=100)
                break
            time.sleep(5)
            continue
        update_step("httpx", status="running", message=f"httpx scanning {len(new_hosts)} new hosts", progress=40)
        batch_file = write_subdomains_file(domain, new_hosts, suffix="_httpx_batch")
        httpx_json = httpx_scan(batch_file, domain, job_domain=job_domain)
        try:
            batch_file.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if not httpx_json:
            job_log_append(job_domain, "httpx batch failed.", "httpx")
            update_step("httpx", status="error", message="httpx batch failed. Check logs for details.", progress=100)
            break
        enrich_state_with_httpx(state, domain, httpx_json)
        httpx_processed.update(new_hosts)
        save_state(state)
        job_log_append(job_domain, f"httpx scanned {len(new_hosts)} hosts.", "httpx")

    # ---------- screenshots ----------
    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]
    if not config.get("enable_screenshots", True):
        update_step("screenshots", status="skipped", message="Screenshots disabled in settings.", progress=0)
        flags["screenshots_done"] = True
        save_state(state)
    else:
        screenshot_targets = gather_screenshot_targets(state, domain)
        if not screenshot_targets:
            update_step("screenshots", status="skipped", message="No HTTP targets available for screenshots.", progress=0)
            flags["screenshots_done"] = True
            save_state(state)
        else:
            update_step("screenshots", status="running", message=f"Capturing screenshots for {len(screenshot_targets)} hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for screenshot slot...", "scheduler")
            with TOOL_GATES["gowitness"]:
                if job_domain:
                    job_log_append(job_domain, "Screenshot slot acquired.", "scheduler")
                screenshot_map = capture_screenshots(screenshot_targets, domain, job_domain=job_domain)
            if not screenshot_map:
                job_log_append(job_domain, "Screenshot batch failed.", "screenshots")
                update_step("screenshots", status="error", message="Screenshot capture failed.", progress=100)
            else:
                state = load_state()
                enrich_state_with_screenshots(state, domain, screenshot_map)
                ensure_target_state(state, domain)["flags"]["screenshots_done"] = True
                save_state(state)
                job_log_append(job_domain, f"Captured screenshots for {len(screenshot_map)} hosts.", "screenshots")
                update_step("screenshots", status="completed", message=f"Screenshots captured for {len(screenshot_map)} hosts.", progress=100)

    # ---------- nuclei ----------
    nuclei_processed: set = set()
    while True:
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())
        new_hosts = [s for s in all_subs if s not in nuclei_processed]
        if not flags.get("nuclei_done") and nuclei_processed == set():
            log(f"=== nuclei scan for {domain} ({len(all_subs)} hosts) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["nuclei_done"] = True
                save_state(state)
                update_step("nuclei", status="completed", message="nuclei scan finished.", progress=100)
                break
            time.sleep(5)
            continue
        update_step("nuclei", status="running", message=f"nuclei scanning {len(new_hosts)} new hosts", progress=40)
        batch_file = write_subdomains_file(domain, new_hosts, suffix="_nuclei_batch")
        if job_domain:
            job_log_append(job_domain, "Waiting for nuclei slot...", "scheduler")
        with TOOL_GATES["nuclei"]:
            if job_domain:
                job_log_append(job_domain, "nuclei slot acquired.", "scheduler")
            nuclei_json = nuclei_scan(batch_file, domain, job_domain=job_domain)
        try:
            batch_file.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if not nuclei_json:
            job_log_append(job_domain, "nuclei batch failed.", "nuclei")
            update_step("nuclei", status="error", message="nuclei batch failed. Check logs for details.", progress=100)
            break
        enrich_state_with_nuclei(state, domain, nuclei_json)
        nuclei_processed.update(new_hosts)
        save_state(state)
        job_log_append(job_domain, f"nuclei processed {len(new_hosts)} hosts.", "nuclei")

    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]
    all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())

    # ---------- nikto ----------
    nikto_processed: set = set()
    if skip_nikto:
        update_step("nikto", status="skipped", message="Nikto skipped per run options.", progress=0)
    else:
        while True:
            state = load_state()
            flags = ensure_target_state(state, domain)["flags"]
            all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())
            new_hosts = [s for s in all_subs if s not in nikto_processed]
            if not flags.get("nikto_done") and nikto_processed == set():
                log(f"=== nikto scan for {domain} ({len(all_subs)} hosts) ===")
            if not new_hosts:
                if enumerators_done_event.is_set():
                    flags["nikto_done"] = True
                    save_state(state)
                    update_step("nikto", status="completed", message="Nikto scan finished.", progress=100)
                    break
                time.sleep(5)
                continue
            update_step("nikto", status="running", message=f"Nikto scanning {len(new_hosts)} new hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for Nikto slot...", "scheduler")
            with TOOL_GATES["nikto"]:
                if job_domain:
                    job_log_append(job_domain, "Nikto slot acquired.", "scheduler")
                nikto_json = nikto_scan(new_hosts, domain, job_domain=job_domain)
            if not nikto_json:
                job_log_append(job_domain, "Nikto batch failed.", "nikto")
                update_step("nikto", status="error", message="Nikto batch failed. Check logs for details.", progress=100)
                break
            enrich_state_with_nikto(state, domain, nikto_json)
            nikto_processed.update(new_hosts)
            save_state(state)
            job_log_append(job_domain, f"Nikto scanned {len(new_hosts)} hosts.", "nikto")

    log("Pipeline finished for this run.")


def ffuf_bruteforce(domain: str, wordlist: str, job_domain: Optional[str] = None) -> List[str]:
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
        "-v",
        "-u", f"http://{domain}",
        "-H", "Host: FUZZ." + domain,
        "-w", wordlist,
        "-of", "json",
        "-o", str(out_json),
        "-mc", "200,301,302,403,401"
    ]
    success = run_subprocess(cmd, job_domain=job_domain, step="ffuf")
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


def write_subdomains_file(domain: str, subs: List[str], suffix: Optional[str] = None) -> Path:
    sanitized = sorted(set(subs))
    out_name = f"subs_{domain}{suffix or ''}.txt"
    out_path = DATA_DIR / out_name
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for s in sanitized:
                f.write(s + "\n")
    except Exception as e:
        log(f"Error writing subdomains file: {e}")
    return out_path


def httpx_scan(subs_file: Path, domain: str, job_domain: Optional[str] = None) -> Path:
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
        "-v",
    ]
    success = run_subprocess(cmd, job_domain=job_domain, step="httpx")
    return out_json if success and out_json.exists() else None


def _normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def gather_screenshot_targets(state: Dict[str, Any], domain: str) -> List[Tuple[str, str]]:
    tgt = ensure_target_state(state, domain)
    submap = tgt.get("subdomains", {})
    targets: List[Tuple[str, str]] = []
    seen_urls = set()
    for host, info in submap.items():
        httpx_info = info.get("httpx") or {}
        url = httpx_info.get("url")
        if not url:
            continue
        norm = url.strip()
        if not norm or norm in seen_urls:
            continue
        seen_urls.add(norm)
        targets.append((host, norm))
    return targets


def capture_screenshots(
    targets: List[Tuple[str, str]],
    domain: str,
    job_domain: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    if not targets:
        return {}
    if not ensure_tool_installed("gowitness"):
        return {}

    dest_dir = SCREENSHOTS_DIR / domain
    dest_dir.mkdir(parents=True, exist_ok=True)
    target_file = dest_dir / f"{domain}_gowitness_targets.txt"
    db_path = dest_dir / f"{domain}_gowitness.sqlite3"
    try:
        with open(target_file, "w", encoding="utf-8") as f:
            for _, url in targets:
                f.write(url.strip() + "\n")
    except Exception as exc:
        log(f"Failed writing screenshot target file: {exc}")
        return {}

    run_started = time.time()
    cmd = [
        TOOLS["gowitness"],
        "file",
        "-f", str(target_file),
        "-P", str(dest_dir),
        "--db", str(db_path),
        "--log-level", "error",
    ]
    success = run_subprocess(cmd, job_domain=job_domain, step="screenshots")
    try:
        target_file.unlink(missing_ok=True)
    except Exception:
        pass
    if not success:
        return {}

    recent_files: Dict[str, Path] = {}
    cutoff = run_started - 5
    for path in dest_dir.rglob("*.png"):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime < cutoff:
            continue
        key = _normalize_identifier(path.stem)
        recent_files[key] = path

    mapping: Dict[str, Dict[str, Any]] = {}
    captured_ts = datetime.now(timezone.utc).isoformat()
    for host, url in targets:
        normalized_candidates = [
            _normalize_identifier(url),
            _normalize_identifier(host),
        ]
        screenshot_path: Optional[Path] = None
        for candidate in normalized_candidates:
            screenshot_path = recent_files.get(candidate)
            if screenshot_path:
                break
        if not screenshot_path or not screenshot_path.exists():
            continue
        try:
            rel_path = screenshot_path.relative_to(SCREENSHOTS_DIR)
        except ValueError:
            rel_path = screenshot_path
        mapping[host] = {
            "path": str(rel_path).replace("\\", "/"),
            "url": url,
            "captured_at": captured_ts,
        }
    return mapping


def nuclei_scan(subs_file: Path, domain: str, job_domain: Optional[str] = None) -> Path:
    if not ensure_tool_installed("nuclei"):
        return None
    out_json = DATA_DIR / f"nuclei_{domain}.json"
    cmd = [
        TOOLS["nuclei"],
        "-l", str(subs_file),
        "-jsonl",
    ]
    success = run_subprocess(cmd, outfile=out_json, job_domain=job_domain, step="nuclei")
    return out_json if success and out_json.exists() else None


def _parse_nikto_output(host: str, stdout_text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not stdout_text:
        return findings
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("+"):
            continue
        # Skip summary lines (e.g. "+ 0 host(s) tested")
        normalized = line.lstrip("+").strip()
        if not normalized or normalized.lower().startswith("0 host"):
            continue
        finding: Dict[str, Any] = {
            "host": host,
            "msg": normalized,
        }
        osvdb_match = re.search(r"OSVDB-(\d+)", normalized, re.IGNORECASE)
        if osvdb_match:
            finding["osvdb"] = osvdb_match.group(1)
        cve_match = re.search(r"CVE-\d{4}-\d+", normalized, re.IGNORECASE)
        if cve_match:
            finding["cve"] = cve_match.group(0).upper()
        uri_match = re.search(r"(?:https?://[^\s]+)", normalized, re.IGNORECASE)
        if uri_match:
            finding["uri"] = uri_match.group(0)
        findings.append(finding)
    return findings


def nikto_scan(subs: List[str], domain: str, job_domain: Optional[str] = None) -> Path:
    if not ensure_tool_installed("nikto"):
        return None
    out_json = DATA_DIR / f"nikto_{domain}.json"

    results: List[Dict[str, Any]] = []
    for host in subs:
        target = f"http://{host}"
        cmd = [
            TOOLS["nikto"],
            "-h", target,
        ]
        log(f"Running nikto against {target}")
        if job_domain:
            job_log_append(job_domain, f"Nikto scanning {target}", source="nikto")
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            log("Nikto binary not found during run.")
            return None
        except Exception as e:
            log(f"Nikto error for {host}: {e}")
            if job_domain:
                job_log_append(job_domain, f"Nikto error for {host}: {e}", source="nikto")
            continue

        if job_domain and proc.stdout:
            job_log_append(job_domain, proc.stdout, source="nikto")
        if job_domain and proc.stderr:
            job_log_append(job_domain, proc.stderr, source="nikto stderr")

        if proc.returncode != 0:
            log(f"Nikto failed for {host}: {proc.stderr[:300]}")
            continue

        host_findings = _parse_nikto_output(host, proc.stdout or "")
        if host_findings:
            results.extend(host_findings)

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
            "subfinder_done": False,
            "assetfinder_done": False,
            "findomain_done": False,
            "sublist3r_done": False,
            "ffuf_done": False,
            "httpx_done": False,
            "screenshots_done": False,
            "nuclei_done": False,
            "nikto_done": False,
        }
    })
    # Normalize missing keys
    tgt.setdefault("subdomains", {})
    tgt.setdefault("flags", {})
    for k in ["amass_done", "subfinder_done", "assetfinder_done", "findomain_done", "sublist3r_done",
              "ffuf_done", "httpx_done", "screenshots_done", "nuclei_done", "nikto_done"]:
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
            "screenshot": None,
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
                    "screenshot": None,
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
                    "screenshot": None,
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
                "screenshot": None,
            })
            vulns = obj.get("vulnerabilities") or obj.get("vulns")
            if not vulns:
                vulns = [obj]
            normalized_vulns = []
            for v in vulns:
                if isinstance(v, dict):
                    normalized_vulns.append({
                        "id": v.get("id"),
                        "msg": v.get("msg") or v.get("description") or v.get("message"),
                        "osvdb": v.get("osvdb"),
                        "risk": v.get("risk"),
                        "uri": v.get("uri"),
                    })
                else:
                    normalized_vulns.append({"raw": str(v)})
            entry.setdefault("nikto", []).extend(normalized_vulns)
    except Exception as e:
        log(f"Error enriching state with nikto data: {e}")


def enrich_state_with_screenshots(state: Dict[str, Any], domain: str, mapping: Dict[str, Dict[str, Any]]) -> None:
    if not mapping:
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for host, data in mapping.items():
        entry = submap.setdefault(host, {
            "sources": [],
            "httpx": None,
            "nuclei": [],
            "nikto": [],
            "screenshot": None,
        })
        entry["screenshot"] = data


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
            f"<span class='badge'>Subfinder: {'✅' if flags.get('subfinder_done') else '⏳'}</span>"
            f"<span class='badge'>Assetfinder: {'✅' if flags.get('assetfinder_done') else '⏳'}</span>"
            f"<span class='badge'>Findomain: {'✅' if flags.get('findomain_done') else '⏳'}</span>"
            f"<span class='badge'>Sublist3r: {'✅' if flags.get('sublist3r_done') else '⏳'}</span>"
            f"<span class='badge'>ffuf: {'✅' if flags.get('ffuf_done') else '⏳'}</span>"
            f"<span class='badge'>httpx: {'✅' if flags.get('httpx_done') else '⏳'}</span>"
            f"<span class='badge'>Screenshots: {'✅' if flags.get('screenshots_done') else '⏳'}</span>"
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
            "<th>Screenshot</th>"
            "<th>Nuclei Findings</th>"
            "<th>Nikto Findings</th>"
            "</tr>"
        )
        for idx, (sub, info) in enumerate(sorted(subs.items(), key=lambda x: x[0]), start=1):
            sources = info.get("sources", [])
            httpx = info.get("httpx") or {}
            screenshot = info.get("screenshot") or {}
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

            screenshot_html = ""
            screenshot_path = screenshot.get("path")
            if screenshot_path:
                screenshot_html = (
                    f"<a href='/screenshots/{screenshot_path}' target='_blank'>View</a>"
                )

            html_parts.append(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td>{sub}</td>"
                f"<td>{', '.join(sources)}</td>"
                f"<td>{http_summary}</td>"
                f"<td>{screenshot_html or '—'}</td>"
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

def run_pipeline(
    domain: str,
    wordlist: Optional[str],
    skip_nikto: bool = False,
    interval: int = DEFAULT_INTERVAL,
    job_domain: Optional[str] = None,
) -> None:
    ensure_dirs()
    config = get_config()
    if not wordlist:
        default_wordlist = config.get("default_wordlist") or ""
        wordlist = default_wordlist or None

    global HTML_REFRESH_SECONDS
    HTML_REFRESH_SECONDS = max(5, interval)

    def update_step(step_name: str, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
        job_step_update(job_domain, step_name, status=status, message=message, progress=progress)

    state = load_state()
    tgt = ensure_target_state(state, domain)
    flags = tgt["flags"]

    enumerators_done_event = threading.Event()
    downstream_started = threading.Event()
    downstream_thread_holder: Dict[str, threading.Thread] = {}
    seen_cache = {
        "amass": set(),
        "subfinder": set(),
        "assetfinder": set(),
        "findomain": set(),
        "sublist3r": set(),
    }

    def start_downstream_if_ready() -> None:
        if downstream_started.is_set():
            return
        current_state = load_state()
        sub_count = len(ensure_target_state(current_state, domain)["subdomains"])
        if sub_count == 0 and not enumerators_done_event.is_set():
            return
        downstream_started.set()
        t = threading.Thread(
            target=run_downstream_pipeline,
            args=(domain, wordlist, config, skip_nikto, interval, job_domain, enumerators_done_event),
            daemon=True,
        )
        downstream_thread_holder["thread"] = t
        t.start()

    def flush_loop() -> None:
        while not enumerators_done_event.is_set():
            harvest_enumerator_outputs(domain, config, seen_cache, job_domain)
            start_downstream_if_ready()
            time.sleep(30)
        harvest_enumerator_outputs(domain, config, seen_cache, job_domain)
        start_downstream_if_ready()

    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    # ---------- Parallel Subdomain Enumerators ----------
    subdomain_input = is_subdomain_input(domain)
    if subdomain_input and not flags.get("amass_done"):
        log(f"Detected subdomain input ({domain}); seeding pipeline with that host.")
        add_subdomains_to_state(state, domain, [domain], "manual-input")
        flags["amass_done"] = True
        flags["subfinder_done"] = True
        flags["assetfinder_done"] = True
        save_state(state)
        start_downstream_if_ready()

    if subdomain_input:
        update_step("amass", status="skipped", message="Input is a subdomain; Amass skipped.", progress=0)
        update_step("subfinder", status="skipped", message="Input is a subdomain; Subfinder skipped.", progress=0)
        update_step("assetfinder", status="skipped", message="Input is a subdomain; Assetfinder skipped.", progress=0)
    else:
        enumerator_specs = []
        enable_subfinder = config.get("enable_subfinder", True)
        enable_assetfinder = config.get("enable_assetfinder", True)
        enable_findomain = config.get("enable_findomain", True)
        enable_sublist3r = config.get("enable_sublist3r", True)

        def maybe_add_enum(step_name: str, flag_key: str, desc: str, func, enabled: bool = True):
            if not enabled:
                update_step(step_name, status="skipped", message=f"{desc} disabled in settings.", progress=0)
                return
            if flags.get(flag_key):
                update_step(step_name, status="skipped", message=f"{desc} already completed.", progress=0)
                return
            enumerator_specs.append((step_name, flag_key, desc, func))

        if config.get("enable_amass", True):
            maybe_add_enum(
                "amass",
                "amass_done",
                "Amass",
                lambda: amass_collect_subdomains(domain, config=config, job_domain=job_domain),
            )
        else:
            update_step("amass", status="skipped", message="Amass disabled in settings.", progress=0)

        maybe_add_enum(
            "subfinder",
            "subfinder_done",
            "Subfinder",
            lambda: subfinder_enum(domain, config, job_domain=job_domain),
            enable_subfinder,
        )
        maybe_add_enum(
            "assetfinder",
            "assetfinder_done",
            "Assetfinder",
            lambda: assetfinder_enum(domain, config, job_domain=job_domain),
            enable_assetfinder,
        )
        maybe_add_enum(
            "findomain",
            "findomain_done",
            "Findomain",
            lambda: findomain_enum(domain, config, job_domain=job_domain),
            enable_findomain,
        )
        maybe_add_enum(
            "sublist3r",
            "sublist3r_done",
            "Sublist3r",
            lambda: sublist3r_enum(domain, job_domain=job_domain),
            enable_sublist3r,
        )

        if enumerator_specs:
            enum_results: Dict[str, Optional[List[str]]] = {}
            enum_errors: Dict[str, str] = {}
            lock = threading.Lock()

            def enum_worker(name: str, func) -> None:
                try:
                    subs = func() or []
                    with lock:
                        enum_results[name] = subs
                except Exception as exc:
                    log(f"{name} enumeration failed: {exc}")
                    job_log_append(job_domain, f"{name} failed: {exc}", name)
                    with lock:
                        enum_results[name] = None
                        enum_errors[name] = str(exc)

            threads = []
            for step_name, _, desc, func in enumerator_specs:
                update_step(step_name, status="running", message=f"{desc} in progress…", progress=40)
                t = threading.Thread(target=enum_worker, args=(step_name, func), daemon=True)
                threads.append((step_name, t))
                t.start()

            for _, t in threads:
                t.join()

            for step_name, flag_key, desc, _ in enumerator_specs:
                subs = enum_results.get(step_name)
                if subs is None:
                    update_step(step_name, status="error", message=f"{desc} failed: {enum_errors.get(step_name, 'Unknown error')}", progress=100)
                    continue
                current_state = load_state()
                add_subdomains_to_state(current_state, domain, subs, step_name)
                ensure_target_state(current_state, domain)["flags"][flag_key] = True
                save_state(current_state)
                job_log_append(job_domain, f"{desc} identified {len(subs)} subdomains.", step_name)
                update_step(step_name, status="completed", message=f"{desc} found {len(subs)} subdomains.", progress=100)
                start_downstream_if_ready()

    enumerators_done_event.set()
    flush_thread.join()
    start_downstream_if_ready()
    downstream_thread = downstream_thread_holder.get("thread")
    if downstream_thread:
        downstream_thread.join()
    else:
        run_downstream_pipeline(domain, wordlist, config, skip_nikto, interval, job_domain, enumerators_done_event)


# ================== JOB SCHEDULER ==================

def count_active_jobs_locked() -> int:
    return sum(1 for job in RUNNING_JOBS.values()
               if job.get("thread") and job["thread"].is_alive())


def _start_job_thread(job: Dict[str, Any]) -> None:
    domain = job["domain"]

    def runner():
        wordlist_path = job.get("wordlist") or None
        skip_nikto = job.get("skip_nikto", False)
        interval_val = job.get("interval", DEFAULT_INTERVAL)
        try:
            job_set_status(domain, "running", "Recon started.")
            run_pipeline(
                domain,
                wordlist_path,
                skip_nikto=skip_nikto,
                interval=interval_val,
                job_domain=domain,
            )
            with JOB_LOCK:
                job_record = RUNNING_JOBS.get(domain)
                had_errors = job_record_has_errors(job_record) if job_record else False
            if had_errors:
                job_set_status(domain, "completed_with_errors", "Recon finished with warnings.")
            else:
                job_set_status(domain, "completed", "Recon finished successfully.")
        except Exception as exc:
            log(f"Recon pipeline failed for {domain}: {exc}")
            job_set_status(domain, "failed", f"Fatal error: {exc}")
        finally:
            with JOB_LOCK:
                RUNNING_JOBS.pop(domain, None)
            schedule_jobs()

    thread = threading.Thread(target=runner, name=f"pipeline-{domain}", daemon=True)
    with JOB_LOCK:
        job["thread"] = thread
        job["started"] = datetime.now(timezone.utc).isoformat()
    thread.start()
    job_log_append(domain, "Job dispatched to worker.", "scheduler")


def schedule_jobs() -> None:
    to_start: List[Dict[str, Any]] = []
    with JOB_LOCK:
        while JOB_QUEUE and count_active_jobs_locked() < MAX_RUNNING_JOBS:
            domain = JOB_QUEUE.popleft()
            job = RUNNING_JOBS.get(domain)
            if not job or job.get("thread"):
                continue
            job["status"] = "dispatching"
            job["message"] = "Preparing to start."
            to_start.append(job)
    for job in to_start:
        _start_job_thread(job)


# ================== WEB COMMAND CENTER ==================


def make_step_entry(status: str = "pending", message: str = "", progress: int = 0) -> Dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "progress": progress,
    }


def init_job_steps(skip_nikto: bool) -> Dict[str, Dict[str, Any]]:
    steps = {step: make_step_entry() for step in PIPELINE_STEPS}
    if skip_nikto:
        steps["nikto"] = make_step_entry(status="skipped", message="Nikto skipped", progress=0)
    return steps


def recalc_job_progress(job: Dict[str, Any]) -> None:
    steps = job.get("steps", {})
    active = [entry for entry in steps.values() if entry.get("status") not in {"skipped"}]
    if not active:
        job["progress"] = 0
        return
    total = len(active)
    total_progress = sum(STEP_PROGRESS.get(entry.get("status"), 0) for entry in active)
    job["progress"] = min(100, max(0, int(total_progress / total)))


def job_set_status(domain: str, status: str, message: Optional[str] = None) -> None:
    if not domain:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        job["status"] = status
        if message is not None:
            job["message"] = message
        job["last_update"] = timestamp
        recalc_job_progress(job)
    if message:
        job_log_append(domain, message, source=f"{status.upper()}")


def job_step_update(domain: Optional[str], step: str, *, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
    if not domain:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        step_entry = job.setdefault("steps", {}).setdefault(step, make_step_entry())
        if status is not None:
            step_entry["status"] = status
        if message is not None:
            step_entry["message"] = message
        if progress is not None:
            step_entry["progress"] = max(0, min(100, progress))
        job["last_update"] = timestamp
        recalc_job_progress(job)
    if message:
        job_log_append(domain, f"[{step}] {message}", source=step or "step")


def job_record_has_errors(job: Dict[str, Any]) -> bool:
    return any(entry.get("status") == "error" for entry in job.get("steps", {}).values())


def append_domain_history(domain: str, entry: Dict[str, Any]) -> None:
    if not domain or not entry:
        return
    try:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        history_file = HISTORY_DIR / f"{domain}.jsonl"
        with history_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        log(f"Failed to write history for {domain}: {exc}")

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Command Center</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --bg: #020617;
  --panel: #111827;
  --panel-alt: #0f172a;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #2563eb;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:'Inter','Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,sans-serif; }
a { color:#93c5fd; text-decoration:none; }
code { background:#1e293b; padding:2px 4px; border-radius:4px; font-size:12px; }
.muted { color:var(--muted); font-size:13px; }
.app-shell { display:flex; min-height:100vh; }
.sidebar { width:250px; background:#050c1c; padding:24px 18px; display:flex; flex-direction:column; gap:24px; border-right:1px solid #0f172a; position:sticky; top:0; height:100vh; }
.brand { display:flex; align-items:center; gap:12px; }
.brand-icon { width:42px; height:42px; border-radius:14px; background:#1d4ed8; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:18px; }
.brand-title { font-size:18px; font-weight:600; line-height:1.2; }
.nav { display:flex; flex-direction:column; gap:8px; }
.nav-link { padding:10px 14px; border-radius:10px; color:var(--text); border:1px solid transparent; transition:all .2s ease; font-weight:500; display:block; }
.nav-link:hover, .nav-link.active { background:#0f172a; border-color:#1e293b; }
.sidebar-footer { margin-top:auto; font-size:12px; color:var(--muted); }
.sidebar-footer code { background:#0f172a; padding:2px 6px; border-radius:6px; }
.main-content { flex:1; padding:32px; }
.module { display:none; background:var(--panel); border-radius:18px; border:1px solid #1e293b; padding:24px; margin-bottom:28px; box-shadow:0 18px 35px rgba(0,0,0,0.3); }
.module.active { display:block; }
.module-header { display:flex; justify-content:space-between; align-items:center; gap:18px; margin-bottom:18px; }
.module-header h2 { margin:0; font-size:24px; color:#fbbf24; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.stat-card { background:var(--panel-alt); border-radius:12px; padding:16px; border:1px solid #1e293b; }
.stat-card .label { font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); margin-bottom:6px; }
.stat-card .value { font-size:26px; font-weight:600; }
.grid-two { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:18px; }
.card { background:var(--panel-alt); border-radius:12px; border:1px solid #1f2937; padding:18px; }
label { display:block; font-weight:600; margin-top:12px; }
input[type="text"], input[type="number"] { width:100%; padding:10px; border-radius:8px; border:1px solid #1f2937; background:#0b152c; color:var(--text); }
input[type="number"]::-webkit-inner-spin-button { opacity:0.4; }
.checkbox { display:flex; align-items:center; gap:8px; margin-top:12px; font-weight:600; }
button { margin-top:16px; background:var(--accent); border:none; color:white; border-radius:10px; padding:10px 18px; font-size:15px; font-weight:600; cursor:pointer; transition:background .2s ease; }
button:hover { background:#1d4ed8; }
.status { margin-top:10px; min-height:20px; }
.status.error { color:#f87171; }
.status.success { color:#4ade80; }
.section-placeholder { padding:18px; border-radius:12px; background:#0b152c; border:1px dashed #1e293b; text-align:center; color:var(--muted); }
.badge { background:#1e293b; padding:4px 8px; border-radius:999px; font-size:12px; margin-left:6px; }
.job-card, .target-card, .queue-card { border-radius:12px; border:1px solid #1e293b; background:var(--panel-alt); margin-bottom:12px; padding:18px; }
.target-card.highlight { box-shadow:0 0 0 2px #fbbf24; }
.job-summary { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:12px; }
.job-meta { display:flex; flex-wrap:wrap; gap:12px; font-size:13px; color:var(--muted); margin:12px 0; }
.job-message { font-size:13px; margin-bottom:12px; color:#fcd34d; }
.progress-bar { width:100%; height:8px; border-radius:999px; background:#1e293b; overflow:hidden; margin-top:8px; }
.progress-inner { height:100%; border-radius:999px; background:#3b82f6; transition:width .3s ease; }
.progress-inner.status-completed { background:#16a34a; }
.progress-inner.status-error, .progress-inner.status-failed { background:#dc2626; }
.status-pill { display:inline-flex; align-items:center; padding:3px 10px; border-radius:999px; font-size:12px; text-transform:capitalize; border:1px solid transparent; }
.status-running { background:rgba(37,99,235,0.2); border-color:#2563eb; color:#bfdbfe; }
.status-completed { background:rgba(22,163,74,0.2); border-color:#16a34a; color:#bbf7d0; }
.status-error, .status-failed { background:rgba(239,68,68,0.2); border-color:#ef4444; color:#fecaca; }
.status-skipped { background:rgba(148,163,184,0.2); border-color:#64748b; color:#e2e8f0; }
.job-steps { display:flex; flex-direction:column; gap:10px; }
.step-row { border:1px solid #1f2937; border-radius:10px; padding:10px 12px; background:#0b152c; }
.step-header { display:flex; justify-content:space-between; align-items:center; gap:8px; }
.step-name { font-weight:600; text-transform:uppercase; font-size:12px; letter-spacing:0.08em; }
.job-log { margin-top:16px; max-height:240px; overflow-y:auto; background:#050b18; border:1px solid #1f2937; border-radius:12px; padding:12px; font-family:'JetBrains Mono','Fira Code','SFMono-Regular',monospace; font-size:12px; }
.log-entry { margin-bottom:8px; }
.log-meta { color:var(--muted); font-size:11px; margin-bottom:2px; }
.log-text { margin:0; white-space:pre-wrap; word-break:break-word; }
.queue-card { display:flex; flex-direction:column; gap:8px; }
.queue-row { display:flex; justify-content:space-between; align-items:center; }
.queue-meta { display:flex; flex-wrap:wrap; gap:12px; font-size:13px; color:var(--muted); }
.worker-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; }
.worker-card { background:var(--panel-alt); border-radius:14px; padding:16px; border:1px solid #1f2937; box-shadow:0 10px 20px rgba(0,0,0,0.2); }
.worker-card h3 { margin:0 0 8px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.worker-card .metric { font-size:32px; font-weight:600; }
.worker-card .muted { margin-top:4px; }
.worker-progress { margin-top:10px; }
.btn { display:inline-block; padding:8px 16px; border-radius:8px; background:var(--accent); color:white; font-weight:600; border:none; cursor:pointer; transition:background .2s ease; text-decoration:none; }
.btn.secondary { background:#1f2937; }
.btn:hover { background:#1d4ed8; }
.export-actions { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:16px; }
.targets-table { width:100%; border-collapse:collapse; font-size:13px; }
.targets-table th, .targets-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.targets-table th { background:#162132; }
.reports-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
.reports-table th, .reports-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.reports-table th { background:#162132; }
.link-btn { background:none; border:none; color:#93c5fd; cursor:pointer; text-decoration:underline; padding:0; font:inherit; }
.modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(2,6,23,0.85); display:none; align-items:center; justify-content:center; z-index:1000; }
.modal-overlay.show { display:flex; }
.modal { width:90%; max-width:900px; max-height:90vh; overflow-y:auto; background:#0f172a; border:1px solid #1e293b; border-radius:16px; padding:24px; box-shadow:0 25px 60px rgba(0,0,0,0.5); }
.modal h3 { margin-top:0; color:#fbbf24; }
.modal-close { position:absolute; top:16px; right:24px; background:none; border:none; color:#f87171; font-size:24px; cursor:pointer; }
.detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:16px; margin-bottom:16px; }
.timeline { max-height:250px; overflow:auto; border:1px solid #1e293b; border-radius:12px; padding:12px; background:#050b18; }
.timeline-entry { margin-bottom:10px; }
.timeline-entry .meta { color:var(--muted); font-size:11px; margin-bottom:3px; }
.table-wrapper { overflow-x:auto; margin-top:10px; }
.settings-layout { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:18px; margin-top:18px; }
.paths-grid { display:grid; grid-template-columns:1fr; gap:12px; }
.paths-grid div { padding:10px 12px; background:#0b152c; border-radius:10px; border:1px solid #1f2937; font-size:13px; }
.tool-list { list-style:none; padding-left:0; margin:0; }
.tool-list li { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1f2937; padding:6px 0; color:var(--text); font-size:13px; }
.tool-list li:last-child { border-bottom:none; }
.tool-status { font-size:12px; display:flex; gap:6px; align-items:center; }
.tips { list-style:disc; margin:12px 0 0 18px; color:var(--muted); font-size:13px; }
@media (max-width: 900px) {
  .app-shell { flex-direction:column; }
  .sidebar { width:100%; height:auto; position:relative; }
}
</style>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-icon">🛰️</div>
      <div>
        <div class="brand-title">Recon Command Center</div>
        <div class="muted">Your bounty HQ</div>
      </div>
    </div>
    <nav class="nav">
      <a class="nav-link" data-view="overview" href="#overview">Overview</a>
      <a class="nav-link" data-view="jobs" href="#jobs">Active Jobs</a>
      <a class="nav-link" data-view="workers" href="#workers">Workers</a>
      <a class="nav-link" data-view="queue" href="#queue">Queue</a>
      <a class="nav-link" data-view="reports" href="#reports">Reports</a>
      <a class="nav-link" data-view="targets" href="#targets">Targets</a>
      <a class="nav-link" data-view="settings" href="#settings">Settings</a>
    </nav>
    <div class="sidebar-footer">
      Outputs live in <code>recon_data/</code>. Keep this UI open while jobs run.
    </div>
  </aside>
  <main class="main-content">
    <section class="module" data-view="overview">
      <div class="module-header">
        <h2>Overview</h2>
        <p class="muted" id="last-updated">Last updated: never</p>
      </div>
      <div class="module-body">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="label">Active Jobs</div>
            <div class="value" id="stat-active">0</div>
          </div>
          <div class="stat-card">
            <div class="label">Queued Jobs</div>
            <div class="value" id="stat-queued">0</div>
          </div>
          <div class="stat-card">
            <div class="label">Tracked Targets</div>
            <div class="value" id="stat-targets">0</div>
          </div>
          <div class="stat-card">
            <div class="label">Known Subdomains</div>
            <div class="value" id="stat-subdomains">0</div>
          </div>
        </div>
        <div class="grid-two">
          <div class="card">
            <h3>Launch Recon</h3>
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
          </div>
          <div class="card">
            <h3>Quick Tips</h3>
            <ul class="tips">
              <li>Jobs update this view live; queue multiple targets safely.</li>
              <li>Adjust concurrency limits in Settings to control system load.</li>
              <li>Targets reuse the shared <code>state.json</code>, so reruns pick up where they left off.</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section class="module" data-view="jobs">
      <div class="module-header"><h2>Active Jobs</h2></div>
      <div class="module-body" id="jobs-list">
        <div class="section-placeholder">No active jobs.</div>
      </div>
    </section>

    <section class="module" data-view="workers">
      <div class="module-header"><h2>Workers</h2></div>
      <div class="module-body" id="workers-body">
        <div class="section-placeholder">Loading worker data…</div>
      </div>
    </section>

    <section class="module" data-view="queue">
      <div class="module-header"><h2>Job Queue</h2></div>
      <div class="module-body">
        <p class="muted">Jobs wait here when all worker slots are busy. They start automatically.</p>
        <div id="queue-list" class="queue-list section-placeholder">Queue empty.</div>
      </div>
    </section>

    <section class="module" data-view="reports">
      <div class="module-header"><h2>Reports & Export</h2></div>
      <div class="module-body" id="reports-body">
        <div class="section-placeholder">No data yet.</div>
      </div>
    </section>

    <section class="module" data-view="targets">
      <div class="module-header"><h2>Targets</h2></div>
      <div class="module-body" id="targets-list">
        <div class="section-placeholder">No reconnaissance data yet.</div>
      </div>
    </section>

    <section class="module" data-view="settings">
      <div class="module-header"><h2>Settings & Tooling</h2></div>
      <div class="module-body">
        <div class="card" id="settings-summary">Loading settings…</div>
        <div class="settings-layout">
          <div class="card">
            <h3>Defaults & Limits</h3>
            <form id="settings-form">
              <label>Default wordlist
                <input id="settings-wordlist" type="text" name="default_wordlist" placeholder="./w.txt" />
              </label>
              <label>Default interval (seconds)
                <input id="settings-interval" type="number" name="default_interval" min="5" />
              </label>
              <label class="checkbox">
                <input id="settings-skip-nikto" type="checkbox" name="skip_nikto_by_default" />
                Skip Nikto by default
              </label>
              <label class="checkbox">
                <input id="settings-enable-screenshots" type="checkbox" name="enable_screenshots" />
                Enable screenshots
              </label>
              <label class="checkbox">
                <input id="settings-enable-amass" type="checkbox" name="enable_amass" />
                Enable Amass
              </label>
              <label>Amass timeout (seconds)
                <input id="settings-amass-timeout" type="number" name="amass_timeout" min="0" />
              </label>
              <label class="checkbox">
                <input id="settings-enable-subfinder" type="checkbox" name="enable_subfinder" />
                Enable Subfinder
              </label>
              <label class="checkbox">
                <input id="settings-enable-assetfinder" type="checkbox" name="enable_assetfinder" />
                Enable Assetfinder
              </label>
              <label class="checkbox">
                <input id="settings-enable-findomain" type="checkbox" name="enable_findomain" />
                Enable Findomain
              </label>
              <label class="checkbox">
                <input id="settings-enable-sublist3r" type="checkbox" name="enable_sublist3r" />
                Enable Sublist3r
              </label>
              <label>Subfinder threads
                <input id="settings-subfinder-threads" type="number" name="subfinder_threads" min="1" />
              </label>
              <label>Assetfinder threads
                <input id="settings-assetfinder-threads" type="number" name="assetfinder_threads" min="1" />
              </label>
              <label>Findomain threads
                <input id="settings-findomain-threads" type="number" name="findomain_threads" min="1" />
              </label>
              <label>Max concurrent jobs
                <input id="settings-max-jobs" type="number" name="max_running_jobs" min="1" />
              </label>
              <label>ffuf parallel slots
                <input id="settings-ffuf" type="number" name="max_parallel_ffuf" min="1" />
              </label>
              <label>nuclei parallel slots
                <input id="settings-nuclei" type="number" name="max_parallel_nuclei" min="1" />
              </label>
              <label>Nikto parallel slots
                <input id="settings-nikto" type="number" name="max_parallel_nikto" min="1" />
              </label>
              <label>Screenshot parallel slots
                <input id="settings-gowitness" type="number" name="max_parallel_gowitness" min="1" />
              </label>
              <button type="submit">Save Settings</button>
            </form>
            <div class="status" id="settings-status"></div>
          </div>
          <div class="card">
            <h3>Toolchain</h3>
            <ul id="tools-list" class="tool-list">
              <li class="muted">Detecting tool paths…</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  </main>
</div>
<div class="modal-overlay" id="detail-overlay">
  <div class="modal">
    <button class="modal-close" id="detail-close">&times;</button>
    <div id="detail-content"></div>
  </div>
</div>
<script>
const navLinks = document.querySelectorAll('.nav-link');
const viewSections = document.querySelectorAll('.module');
function setView(target) {
  const next = target || 'overview';
  viewSections.forEach(section => section.classList.toggle('active', section.dataset.view === next));
  navLinks.forEach(link => link.classList.toggle('active', link.dataset.view === next));
  history.replaceState(null, '', `#${next}`);
}
navLinks.forEach(link => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    setView(link.dataset.view);
  });
});
const initialView = location.hash ? location.hash.substring(1) : 'overview';
setView(initialView || 'overview');

const POLL_INTERVAL = 8000;
const launchForm = document.getElementById('launch-form');
const launchWordlist = document.getElementById('launch-wordlist');
const launchInterval = document.getElementById('launch-interval');
const launchSkipNikto = document.getElementById('launch-skip-nikto');
const launchStatus = document.getElementById('launch-status');
const jobsList = document.getElementById('jobs-list');
const queueList = document.getElementById('queue-list');
const targetsList = document.getElementById('targets-list');
const toolsList = document.getElementById('tools-list');
const workersBody = document.getElementById('workers-body');
const reportsBody = document.getElementById('reports-body');
const detailOverlay = document.getElementById('detail-overlay');
const detailContent = document.getElementById('detail-content');
const detailClose = document.getElementById('detail-close');
let latestTargetsData = {};
const historyCache = {};
const settingsForm = document.getElementById('settings-form');
const settingsWordlist = document.getElementById('settings-wordlist');
const settingsInterval = document.getElementById('settings-interval');
const settingsSkipNikto = document.getElementById('settings-skip-nikto');
const settingsEnableScreenshots = document.getElementById('settings-enable-screenshots');
const settingsEnableAmass = document.getElementById('settings-enable-amass');
const settingsAmassTimeout = document.getElementById('settings-amass-timeout');
const settingsEnableSubfinder = document.getElementById('settings-enable-subfinder');
const settingsEnableAssetfinder = document.getElementById('settings-enable-assetfinder');
const settingsEnableFindomain = document.getElementById('settings-enable-findomain');
const settingsEnableSublist3r = document.getElementById('settings-enable-sublist3r');
const settingsSubfinderThreads = document.getElementById('settings-subfinder-threads');
const settingsAssetfinderThreads = document.getElementById('settings-assetfinder-threads');
const settingsFindomainThreads = document.getElementById('settings-findomain-threads');
const settingsMaxJobs = document.getElementById('settings-max-jobs');
const settingsFFUF = document.getElementById('settings-ffuf');
const settingsNuclei = document.getElementById('settings-nuclei');
const settingsNikto = document.getElementById('settings-nikto');
const settingsGowitness = document.getElementById('settings-gowitness');
const settingsStatus = document.getElementById('settings-status');
const settingsSummary = document.getElementById('settings-summary');
const statActive = document.getElementById('stat-active');
const statQueued = document.getElementById('stat-queued');
const statTargets = document.getElementById('stat-targets');
const statSubs = document.getElementById('stat-subdomains');
let launchFormDirty = false;
let settingsFormDirty = false;

const STATUS_LABELS = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed w/ warnings',
  failed: 'Failed',
  error: 'Error',
  skipped: 'Skipped',
  pending: 'Pending'
};

function statusLabel(value) {
  if (!value) return 'Unknown';
  return STATUS_LABELS[value] || value.replace(/_/g, ' ');
}

function statusClass(value) {
  switch (value) {
    case 'completed':
      return 'status-completed';
    case 'completed_with_errors':
    case 'error':
    case 'failed':
      return 'status-error';
    case 'running':
    case 'queued':
      return 'status-running';
    case 'skipped':
    case 'pending':
    default:
      return 'status-skipped';
  }
}

function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtTime(value) {
  if (!value) return 'N/A';
  const d = new Date(value);
  if (isNaN(d.getTime())) return escapeHtml(value);
  return d.toLocaleString();
}

function renderProgress(value, status) {
  const width = Math.max(0, Math.min(100, value || 0));
  return `<div class="progress-bar"><div class="progress-inner ${statusClass(status)}" style="width:${width}%"></div></div>`;
}

function renderLogEntries(logs) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  if (!safeLogs.length) {
    return '<p class="muted">No output yet.</p>';
  }
  return safeLogs.slice(-200).map(entry => {
    return `
      <div class="log-entry">
        <div class="log-meta">${fmtTime(entry.ts)} — ${escapeHtml(entry.source || 'app')}</div>
        <pre class="log-text">${escapeHtml(entry.text || '')}</pre>
      </div>
    `;
  }).join('');
}

function renderJobStep(name, info = {}) {
  const status = info.status || 'pending';
  const message = info.message || '';
  const pct = info.progress !== undefined ? info.progress : (status === 'completed' ? 100 : 0);
  return `
    <div class="step-row">
      <div class="step-header">
        <span class="step-name">${escapeHtml(name.toUpperCase())}</span>
        <span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span>
      </div>
      <p class="muted">${escapeHtml(message)}</p>
      ${renderProgress(pct, status)}
    </div>
  `;
}

function renderJobs(jobs) {
  const all = Array.isArray(jobs) ? jobs : [];
  const running = all.filter(job => job.status !== 'queued');
  statActive.textContent = running.length;
  if (!running.length) {
    jobsList.innerHTML = '<div class="section-placeholder">No active jobs.</div>';
    return;
  }
  const cards = running.map(job => {
    const progress = Math.max(0, Math.min(100, job.progress || 0));
    const steps = job.steps || {};
    const stepsHtml = Object.keys(steps).map(step => renderJobStep(step, steps[step])).join('');
    const logsHtml = renderLogEntries(job.logs || []);
    return `
      <div class="job-card">
        <div class="job-summary">
          <div>
            <div>${escapeHtml(job.domain || '')}</div>
            <div class="muted">Started ${fmtTime(job.started)}</div>
          </div>
          <div class="job-summary-meta">
            <span class="status-pill ${statusClass(job.status)}">${statusLabel(job.status)}</span>
            <span class="badge">${progress}%</span>
          </div>
        </div>
        ${renderProgress(progress, job.status)}
        <div class="job-meta">
          <span><strong>Wordlist:</strong> ${escapeHtml(job.wordlist || 'default')}</span>
          <span><strong>Interval:</strong> ${escapeHtml(job.interval || 0)}s</span>
          <span><strong>Nikto:</strong> ${job.skip_nikto ? 'Skipped' : 'Enabled'}</span>
        </div>
        <div class="job-message">${escapeHtml(job.message || '')}</div>
        <div class="job-steps">
          ${stepsHtml || '<p class="muted">Awaiting step updates…</p>'}
        </div>
        <div class="job-log">
          ${logsHtml}
        </div>
      </div>
    `;
  });
  jobsList.innerHTML = cards.join('');
}

function renderQueue(queue) {
  const items = Array.isArray(queue) ? queue : [];
  statQueued.textContent = items.length;
  if (!items.length) {
    queueList.innerHTML = '<div class="section-placeholder">Queue empty.</div>';
    return;
  }
  const cards = items.map((job) => {
    return `
      <div class="queue-card">
        <div class="queue-row">
          <strong>${escapeHtml(job.domain || '')}</strong>
          <span class="badge">#${escapeHtml(job.position || 0)}</span>
        </div>
        <p class="muted">Queued ${fmtTime(job.queued_at)}</p>
        <div class="queue-meta">
          <span>Wordlist: ${escapeHtml(job.wordlist || 'default')}</span>
          <span>Interval: ${escapeHtml(job.interval || 0)}s</span>
          <span>Nikto: ${job.skip_nikto ? 'Skipped' : 'Enabled'}</span>
        </div>
      </div>
    `;
  }).join('');
  queueList.innerHTML = cards;
}

function renderTargets(targets) {
  latestTargetsData = targets || {};
  const entries = Object.entries(targets || {});
  statTargets.textContent = entries.length;
  if (!entries.length) {
    targetsList.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    statSubs.textContent = 0;
    return;
  }
  entries.sort((a, b) => a[0].localeCompare(b[0]));
  let subCount = 0;
  const cards = entries.map(([domain, info]) => {
    const subs = (info && info.subdomains) || {};
    const flags = (info && info.flags) || {};
    const keys = Object.keys(subs).sort();
    subCount += keys.length;
    const rows = keys.map((sub, idx) => {
      const entry = subs[sub] || {};
      const sources = Array.isArray(entry.sources) ? entry.sources.join(', ') : '';
      const httpx = entry.httpx || {};
      const httpSummary = httpx.status_code ? `${httpx.status_code} ${escapeHtml(httpx.title || '')} [${escapeHtml(httpx.webserver || '')}]` : '';
      const screenshot = entry.screenshot || {};
      const screenshotLink = screenshot.path ? `<a href="/screenshots/${escapeHtml(screenshot.path)}" target="_blank">View</a>` : '';
      const nuclei = Array.isArray(entry.nuclei) ? entry.nuclei : [];
      const nucleiBits = nuclei.map(n => `<span class="badge">${escapeHtml((n.severity || '').toUpperCase())}: ${escapeHtml(n.template_id || '')}</span>`).join(' ');
      const nikto = Array.isArray(entry.nikto) ? entry.nikto : [];
      const niktoText = nikto.length ? `${nikto.length} findings` : '';
      return `
        <tr>
          <td>${idx + 1}</td>
          <td><button class="link-btn sub-link" data-domain="${escapeHtml(domain)}" data-sub="${escapeHtml(sub)}">${escapeHtml(sub)}</button></td>
          <td>${escapeHtml(sources)}</td>
          <td>${escapeHtml(httpSummary)}</td>
          <td>${screenshotLink || '—'}</td>
          <td>${nucleiBits}</td>
          <td>${escapeHtml(niktoText)}</td>
        </tr>
      `;
    }).join('');
    const badges = `
      <span class="badge">Subdomains: ${keys.length}</span>
      <span class="badge">Amass: ${flags.amass_done ? '✅' : '⏳'}</span>
      <span class="badge">Subfinder: ${flags.subfinder_done ? '✅' : '⏳'}</span>
      <span class="badge">Assetfinder: ${flags.assetfinder_done ? '✅' : '⏳'}</span>
      <span class="badge">Findomain: ${flags.findomain_done ? '✅' : '⏳'}</span>
      <span class="badge">Sublist3r: ${flags.sublist3r_done ? '✅' : '⏳'}</span>
      <span class="badge">ffuf: ${flags.ffuf_done ? '✅' : '⏳'}</span>
      <span class="badge">httpx: ${flags.httpx_done ? '✅' : '⏳'}</span>
      <span class="badge">Screenshots: ${flags.screenshots_done ? '✅' : '⏳'}</span>
      <span class="badge">nuclei: ${flags.nuclei_done ? '✅' : '⏳'}</span>
      <span class="badge">nikto: ${flags.nikto_done ? '✅' : '⏳'}</span>
    `;
    const table = rows ? `
      <div class="table-wrapper">
        <table class="targets-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Subdomain</th>
              <th>Sources</th>
              <th>HTTP</th>
              <th>Screenshot</th>
              <th>Nuclei</th>
              <th>Nikto</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    ` : '<p class="muted">No subdomains collected yet.</p>';
    return `
      <div class="target-card" data-domain="${escapeHtml(domain)}">
        <div class="job-summary">
          <div>${escapeHtml(domain)}</div>
          <div>${badges}</div>
        </div>
        ${table}
      </div>
    `;
  });
  statSubs.textContent = subCount;
  targetsList.innerHTML = cards.join('');
}

function renderWorkers(workers) {
  if (!workers || !workers.job_slots) {
    workersBody.innerHTML = '<div class="section-placeholder">No worker data.</div>';
    return;
  }
  const job = workers.job_slots || {};
  const jobPct = job.limit ? Math.min(100, Math.round((job.active || 0) / job.limit * 100)) : 0;
  const jobCard = `
    <div class="worker-card">
      <h3>Job Slots</h3>
      <div class="metric">${job.active || 0}/${job.limit || 1}</div>
      <div class="muted">${job.queue || 0} queued</div>
      <div class="worker-progress">${renderProgress(jobPct, (job.active || 0) >= (job.limit || 1) ? 'running' : 'completed')}</div>
    </div>
  `;
  const tools = workers.tools || {};
  const toolCards = Object.keys(tools).sort().map(name => {
    const info = tools[name] || {};
    const limit = info.limit || 1;
    const active = info.active || 0;
    const pct = limit ? Math.min(100, Math.round(active / limit * 100)) : 0;
    return `
      <div class="worker-card">
        <h3>${escapeHtml(name)}</h3>
        <div class="metric">${active}/${limit}</div>
        <div class="muted">slots in use</div>
        <div class="worker-progress">${renderProgress(pct, active >= limit ? 'running' : 'completed')}</div>
      </div>
    `;
  }).join('') || '<div class="section-placeholder">No tool data.</div>';
  workersBody.innerHTML = `<div class="worker-grid">${jobCard}${toolCards}</div>`;
}

function closeDetailModal() {
  detailOverlay.classList.remove('show');
  detailContent.innerHTML = '';
}

async function openSubdomainDetail(domain, sub) {
  if (!latestTargetsData[domain] || !latestTargetsData[domain].subdomains[sub]) return;
  const info = latestTargetsData[domain].subdomains[sub];
  const history = await fetchHistory(domain);
  detailContent.innerHTML = buildDetailHtml(domain, sub, info, history);
  detailOverlay.classList.add('show');
}

async function fetchHistory(domain) {
  if (historyCache[domain]) return historyCache[domain];
  try {
    const resp = await fetch(`/api/history?domain=${encodeURIComponent(domain)}`);
    if (!resp.ok) throw new Error('Failed to fetch history');
    const data = await resp.json();
    historyCache[domain] = data.events || [];
    return historyCache[domain];
  } catch (err) {
    return [];
  }
}

function buildDetailHtml(domain, sub, info, history) {
  const sources = info.sources || [];
  const httpx = info.httpx || {};
  const screenshot = info.screenshot || {};
  const nuclei = info.nuclei || [];
  const nikto = info.nikto || [];
  const filteredHistory = history.filter(event => {
    const text = (event.text || '').toLowerCase();
    const src = (event.source || '').toLowerCase();
    const needle = (sub || '').toLowerCase();
    return needle && (text.includes(needle) || src.includes(needle));
  });
  return `
    <h3>${escapeHtml(sub)} <span class="badge">${escapeHtml(domain)}</span></h3>
    <div class="detail-grid">
      <div>
        <h4>Sources</h4>
        <p>${sources.join(', ') || 'Unknown'}</p>
      </div>
      <div>
        <h4>HTTP</h4>
        <p>${httpx.status_code || '—'} ${escapeHtml(httpx.title || '')}</p>
        <p>${escapeHtml(httpx.webserver || '')}</p>
      </div>
      <div>
        <h4>Screenshot</h4>
        ${screenshot.path ? `<p><a href="/screenshots/${escapeHtml(screenshot.path)}" target="_blank">Open image</a></p>` : '<p>None</p>'}
        ${screenshot.captured_at ? `<p class="muted">Captured ${fmtTime(screenshot.captured_at)}</p>` : ''}
      </div>
      <div>
        <h4>Nuclei Findings</h4>
        ${nuclei.length ? nuclei.map(n => `<div><strong>${escapeHtml(n.template_id || '')}</strong> (${escapeHtml((n.severity || '').toUpperCase())})<br>${escapeHtml(n.matched_at || '')}</div>`).join('') : '<p>None</p>'}
      </div>
      <div>
        <h4>Nikto Findings</h4>
        ${nikto.length ? nikto.map(n => `<div>${escapeHtml(n.msg || n.raw || '')}</div>`).join('') : '<p>None</p>'}
      </div>
    </div>
    <h4>Timeline</h4>
    <div class="timeline">
      ${filteredHistory.length ? filteredHistory.map(evt => `
        <div class="timeline-entry">
          <div class="meta">${escapeHtml(evt.ts || '')} — ${escapeHtml(evt.source || '')}</div>
          <div>${escapeHtml(evt.text || '')}</div>
        </div>
      `).join('') : '<p class="muted">No history for this subdomain yet.</p>'}
    </div>
  `;
}

function renderReports(targets) {
  const entries = Object.entries(targets || {});
  if (!entries.length) {
    reportsBody.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    return;
  }
  const rows = entries.sort((a, b) => b[1]?.subdomains ? Object.keys(b[1].subdomains || {}).length - Object.keys(a[1].subdomains || {}).length : 0).map(([domain, info]) => {
    const subs = info.subdomains || {};
    const subKeys = Object.keys(subs);
    const httpCount = subKeys.filter(key => subs[key]?.httpx).length;
    const nucleiCount = subKeys.reduce((acc, key) => acc + (Array.isArray(subs[key]?.nuclei) ? subs[key].nuclei.length : 0), 0);
    const niktoCount = subKeys.reduce((acc, key) => acc + (Array.isArray(subs[key]?.nikto) ? subs[key].nikto.length : 0), 0);
    return `
      <tr>
        <td>${escapeHtml(domain)}</td>
        <td>${subKeys.length}</td>
        <td>${httpCount}</td>
        <td>${nucleiCount}</td>
        <td>${niktoCount}</td>
        <td><button class="btn secondary" data-target-domain="${escapeHtml(domain)}">Open</button></td>
      </tr>
    `;
  }).join('');
  reportsBody.innerHTML = `
    <div class="export-actions">
      <a class="btn" href="/api/export/state" target="_blank">Download JSON</a>
      <a class="btn secondary" href="/api/export/csv" target="_blank">Download CSV</a>
    </div>
    <div class="table-wrapper">
      <table class="reports-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Subdomains</th>
            <th>HTTP entries</th>
            <th>Nuclei findings</th>
            <th>Nikto findings</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

reportsBody.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-target-domain]');
  if (!btn) return;
  const domain = btn.getAttribute('data-target-domain');
  setView('targets');
  const card = document.querySelector(`#targets-list .target-card[data-domain="${CSS.escape(domain)}"]`);
  if (card) {
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    card.classList.add('highlight');
    setTimeout(() => card.classList.remove('highlight'), 2000);
  }
});
function renderSettings(config, tools) {
  settingsSummary.innerHTML = `
    <div class="paths-grid">
      <div><strong>Results directory</strong><br><code>${escapeHtml(config.data_dir || '')}</code></div>
      <div><strong>state.json</strong><br><code>${escapeHtml(config.state_file || '')}</code></div>
      <div><strong>dashboard.html</strong><br><code>${escapeHtml(config.dashboard_file || '')}</code></div>
      <div><strong>Concurrency</strong><br>
        Jobs: ${escapeHtml(config.max_running_jobs || 1)} ·
        ffuf: ${escapeHtml(config.max_parallel_ffuf || 1)} ·
        nuclei: ${escapeHtml(config.max_parallel_nuclei || 1)} ·
        Nikto: ${escapeHtml(config.max_parallel_nikto || 1)}
      </div>
      <div><strong>Enumerators</strong><br>
        Amass: ${config.enable_amass === false ? 'disabled' : `enabled (timeout=${escapeHtml(config.amass_timeout || 600)}s)`} ·
        Subfinder: ${config.enable_subfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.subfinder_threads || 32)})`} ·
        Assetfinder: ${config.enable_assetfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.assetfinder_threads || 10)})`} ·
        Findomain: ${config.enable_findomain === false ? 'disabled' : `enabled (t=${escapeHtml(config.findomain_threads || 40)})`} ·
        Sublist3r: ${config.enable_sublist3r === false ? 'disabled' : 'enabled'}
      </div>
    </div>
  `;
  const toolItems = Object.keys(tools || {}).sort().map(name => {
    const path = tools[name];
    const pill = path ? '<span class="status-pill status-completed">Found</span>' : '<span class="status-pill status-error">Missing</span>';
    const extra = path ? `<code>${escapeHtml(path)}</code>` : '';
    return `<li><span>${escapeHtml(name)}</span><span class="tool-status">${pill} ${extra}</span></li>`;
  }).join('') || '<li class="muted">No tool data.</li>';
  toolsList.innerHTML = toolItems;

  if (!settingsFormDirty) {
    settingsWordlist.value = config.default_wordlist || '';
    settingsInterval.value = config.default_interval || 30;
    settingsSkipNikto.checked = !!config.skip_nikto_by_default;
    settingsEnableAmass.checked = config.enable_amass !== false;
    settingsAmassTimeout.value = config.amass_timeout || 600;
    settingsEnableSubfinder.checked = config.enable_subfinder !== false;
    settingsEnableAssetfinder.checked = config.enable_assetfinder !== false;
    settingsEnableFindomain.checked = config.enable_findomain !== false;
    settingsEnableSublist3r.checked = config.enable_sublist3r !== false;
    settingsSubfinderThreads.value = config.subfinder_threads || 32;
    settingsAssetfinderThreads.value = config.assetfinder_threads || 10;
    settingsFindomainThreads.value = config.findomain_threads || 40;
    settingsMaxJobs.value = config.max_running_jobs || 1;
    settingsFFUF.value = config.max_parallel_ffuf || 1;
    settingsNuclei.value = config.max_parallel_nuclei || 1;
    settingsNikto.value = config.max_parallel_nikto || 1;
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
    renderQueue(data.queued_jobs || []);
    renderTargets(data.targets || {});
    renderSettings(data.config || {}, data.tools || {});
    renderWorkers(data.workers || {});
    renderReports(data.targets || {});
  } catch (err) {
    targetsList.innerHTML = `<div class="section-placeholder">${escapeHtml(err.message)}</div>`;
  }
}

launchForm.addEventListener('input', () => { launchFormDirty = true; });
settingsForm.addEventListener('input', () => { settingsFormDirty = true; });

targetsList.addEventListener('click', (event) => {
  const btn = event.target.closest('.sub-link');
  if (!btn) return;
  event.preventDefault();
  const domain = btn.getAttribute('data-domain');
  const sub = btn.getAttribute('data-sub');
  openSubdomainDetail(domain, sub);
});

detailClose.addEventListener('click', () => closeDetailModal());
detailOverlay.addEventListener('click', (event) => {
  if (event.target === detailOverlay) closeDetailModal();
});

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
    enable_amass: settingsEnableAmass.checked,
    amass_timeout: settingsAmassTimeout.value,
    enable_subfinder: settingsEnableSubfinder.checked,
    enable_assetfinder: settingsEnableAssetfinder.checked,
    enable_findomain: settingsEnableFindomain.checked,
    enable_sublist3r: settingsEnableSublist3r.checked,
    subfinder_threads: settingsSubfinderThreads.value,
    assetfinder_threads: settingsAssetfinderThreads.value,
    findomain_threads: settingsFindomainThreads.value,
    max_running_jobs: settingsMaxJobs.value,
    max_parallel_ffuf: settingsFFUF.value,
    max_parallel_nuclei: settingsNuclei.value,
    max_parallel_nikto: settingsNikto.value,
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
            steps = {name: dict(data) for name, data in (job.get("steps") or {}).items()}
            thread_alive = bool(job.get("thread") and job["thread"].is_alive())
            logs = [dict(entry) for entry in job.get("logs", [])]
            results.append({
                "domain": domain,
                "started": job.get("started"),
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
                "status": job.get("status", "running"),
                "message": job.get("message", ""),
                "progress": job.get("progress", 0),
                "last_update": job.get("last_update"),
                "thread_alive": thread_alive,
                "steps": steps,
                "logs": logs,
            })
        return results


def job_queue_snapshot() -> List[Dict[str, Any]]:
    with JOB_LOCK:
        snapshot = []
        for position, domain in enumerate(JOB_QUEUE, start=1):
            job = RUNNING_JOBS.get(domain)
            if not job:
                continue
            snapshot.append({
                "domain": domain,
                "position": position,
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
            })
        return snapshot


def snapshot_workers() -> Dict[str, Any]:
    with JOB_LOCK:
        active_jobs = count_active_jobs_locked()
        queue_len = len(JOB_QUEUE)
    tool_stats = {
        name: gate.snapshot()
        for name, gate in TOOL_GATES.items()
    }


def build_targets_csv(state: Dict[str, Any]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["domain", "subdomains", "http_entries", "nuclei_findings", "nikto_findings"])
    targets = state.get("targets", {})
    for domain, info in sorted(targets.items()):
        subs = info.get("subdomains", {})
        sub_keys = subs.keys()
        http_count = sum(1 for data in subs.values() if data.get("httpx"))
        nuclei_count = sum(len(data.get("nuclei") or []) for data in subs.values())
        nikto_count = sum(len(data.get("nikto") or []) for data in subs.values())
        writer.writerow([domain, len(sub_keys), http_count, nuclei_count, nikto_count])
    return output.getvalue().encode("utf-8")
    return {
        "job_slots": {
            "limit": MAX_RUNNING_JOBS,
            "active": active_jobs,
            "queue": queue_len,
        },
        "tools": tool_stats,
    }


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

    with JOB_LOCK:
        if normalized in RUNNING_JOBS:
            return False, f"A job for {normalized} already exists (status: {RUNNING_JOBS[normalized].get('status')})."
        now = datetime.now(timezone.utc).isoformat()
        job_record = {
            "domain": normalized,
            "thread": None,
            "started": None,
            "queued_at": now,
            "wordlist": wordlist_path,
            "skip_nikto": skip_nikto,
            "interval": interval_val,
            "status": "queued",
            "message": "Waiting for a free slot.",
            "steps": init_job_steps(skip_nikto),
            "progress": 0,
            "last_update": now,
            "logs": [],
        }
        RUNNING_JOBS[normalized] = job_record
        if count_active_jobs_locked() < MAX_RUNNING_JOBS:
            start_now = True
        else:
            JOB_QUEUE.append(normalized)
            start_now = False

    if start_now:
        _start_job_thread(job_record)
        return True, f"Recon started for {normalized}."

    job_log_append(normalized, "Queued for execution.", "scheduler")
    return True, f"{normalized} queued; it will start when a worker is free."


def build_state_payload() -> Dict[str, Any]:
    state = load_state()
    config = get_config()
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    return {
        "last_updated": state.get("last_updated"),
        "targets": state.get("targets", {}),
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
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
        if self.path.startswith("/screenshots/"):
            rel_path = unquote(self.path[len("/screenshots/"):]).lstrip("/")
            if not rel_path:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            requested = (SCREENSHOTS_DIR / rel_path).resolve()
            base = SCREENSHOTS_DIR.resolve()
            try:
                if not str(requested).startswith(str(base)):
                    raise ValueError("Outside screenshots dir")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            if not requested.exists() or not requested.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            mime, _ = mimetypes.guess_type(str(requested))
            data = requested.read_bytes()
            self._send_bytes(data, status=HTTPStatus.OK, content_type=mime or "application/octet-stream")
            return
        if self.path.startswith("/api/history"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = (params.get("domain") or [""])[0].strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "domain parameter required"}, status=HTTPStatus.BAD_REQUEST)
                return
            history_file = HISTORY_DIR / f"{domain}.jsonl"
            events = []
            if history_file.exists():
                try:
                    with history_file.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                except Exception as exc:
                    self._send_json({"success": False, "message": f"Failed to read history: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
            self._send_json({"domain": domain, "events": events[-1000:]})
            return
        if self.path == "/api/export/state":
            data = json.dumps(load_state(), indent=2).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", 'attachment; filename="state.json"')
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api/export/csv":
            data = build_targets_csv(load_state())
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", 'attachment; filename="targets.csv"')
            self.end_headers()
            self.wfile.write(data)
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
