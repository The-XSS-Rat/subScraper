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
import copy
import csv
import io
import json
import mimetypes
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse, unquote
from urllib.request import Request, urlopen

# ====================== CONFIG ======================

DATA_DIR = Path("recon_data")
STATE_FILE = DATA_DIR / "state.json"
HTML_DASHBOARD_FILE = DATA_DIR / "dashboard.html"
LOCK_FILE = DATA_DIR / ".lock"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_DIR = DATA_DIR / "history"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
MONITORS_FILE = DATA_DIR / "monitors.json"

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
    "crtsh": "crtsh",  # Virtual tool for crt.sh API
    "github-subdomains": "github-subdomains",
    "dnsx": "dnsx",
    "ffuf": "ffuf",
    "httpx": "httpx",
    "waybackurls": "waybackurls",
    "gau": "gau",
    "nuclei": "nuclei",
    "nikto": "nikto",
    "gowitness": "gowitness",
    "nmap": "nmap",
}

CONFIG_LOCK = threading.Lock()
CONFIG: Dict[str, Any] = {}
TEMPLATE_AWARE_TOOLS = [
    "amass",
    "subfinder",
    "assetfinder",
    "findomain",
    "sublist3r",
    "crtsh",
    "github-subdomains",
    "dnsx",
    "ffuf",
    "httpx",
    "waybackurls",
    "gau",
    "nuclei",
    "nikto",
    "gowitness",
    "nmap",
]


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
    "nmap": ToolGate(1),
    "dnsx": ToolGate(1),
    "waybackurls": ToolGate(1),
    "gau": ToolGate(1),
}
JOB_QUEUE: deque = deque()
MAX_RUNNING_JOBS = 1
RUNNING_JOBS: Dict[str, Dict[str, Any]] = {}
JOB_LOCK = threading.Lock()
PIPELINE_STEPS = ["amass", "subfinder", "assetfinder", "findomain", "sublist3r", "crtsh", "github-subdomains", "dnsx", "ffuf", "httpx", "waybackurls", "gau", "screenshots", "nmap", "nuclei", "nikto"]

# Global rate limiter
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_LAST_CALL = 0.0
GLOBAL_RATE_LIMIT_DELAY = 0.0  # seconds between tool calls (0 = no rate limit)
STEP_PROGRESS = {
    "pending": 0,
    "queued": 0,
    "running": 55,
    "completed": 100,
    "skipped": 0,
    "error": 100,
    "failed": 100,
}


class JobControl:
    def __init__(self):
        self._cond = threading.Condition()
        self._pause_requested = False

    def request_pause(self) -> bool:
        with self._cond:
            if self._pause_requested:
                return False
            self._pause_requested = True
            self._cond.notify_all()
            return True

    def request_resume(self) -> bool:
        with self._cond:
            if not self._pause_requested:
                return False
            self._pause_requested = False
            self._cond.notify_all()
            return True

    def is_pause_requested(self) -> bool:
        with self._cond:
            return self._pause_requested

    def wait_until_resumed(self) -> None:
        with self._cond:
            while self._pause_requested:
                self._cond.wait()


def apply_rate_limit() -> None:
    """
    Apply global rate limiting by enforcing minimum delay between tool calls.
    """
    global RATE_LIMIT_LAST_CALL
    if GLOBAL_RATE_LIMIT_DELAY <= 0:
        return
    with RATE_LIMIT_LOCK:
        now = time.time()
        elapsed = now - RATE_LIMIT_LAST_CALL
        if elapsed < GLOBAL_RATE_LIMIT_DELAY:
            sleep_time = GLOBAL_RATE_LIMIT_DELAY - elapsed
            time.sleep(sleep_time)
        RATE_LIMIT_LAST_CALL = time.time()


JOB_CONTROLS: Dict[str, JobControl] = {}
JOB_CONTROL_LOCK = threading.Lock()
ACTIVE_PAUSED_JOBS: set = set()
MONITOR_LOCK = threading.Lock()
MONITOR_STATE: Dict[str, Dict[str, Any]] = {}
MONITOR_THREAD: Optional[threading.Thread] = None
MONITOR_POLL_INTERVAL = 10
DEFAULT_MONITOR_INTERVAL = 300
MAX_MONITOR_ENTRIES = 200


# ================== UTILITIES =======================

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts} UTC] {msg}")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def _normalize_tool_flag_templates(value: Any) -> Dict[str, str]:
    mapping = {name: "" for name in TEMPLATE_AWARE_TOOLS}
    if not isinstance(value, dict):
        return mapping
    for name in TEMPLATE_AWARE_TOOLS:
        if name in value:
            mapping[name] = str(value.get(name) or "").strip()
    return mapping


def get_tool_flag_template(tool: str, config: Optional[Dict[str, Any]] = None) -> str:
    cfg = config or get_config()
    templates = _normalize_tool_flag_templates(cfg.get("tool_flag_templates"))
    return templates.get(tool, "")


def render_template_args(template: str, context: Dict[str, Any], tool: str) -> List[str]:
    if not template or not str(template).strip():
        return []

    def replacer(match: re.Match) -> str:
        key = match.group(1).upper()
        return str(context.get(key, ""))

    try:
        expanded = re.sub(r"\$(\w+)\$", replacer, str(template))
    except re.error as exc:
        log(f"Regex error while parsing template for {tool}: {exc}")
        return []
    try:
        parsed = shlex.split(expanded)
    except ValueError as exc:
        log(f"Template parse error for {tool}: {exc}")
        parsed = expanded.split()
    return [arg for arg in parsed if str(arg).strip()]


def apply_template_flags(
    tool: str,
    cmd: List[str],
    context: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> List[str]:
    template = get_tool_flag_template(tool, config)
    extras = render_template_args(template, context, tool)
    if not extras:
        return cmd
    return cmd + extras


def apply_concurrency_limits(cfg: Dict[str, Any]) -> None:
    global MAX_RUNNING_JOBS, GLOBAL_RATE_LIMIT_DELAY
    try:
        MAX_RUNNING_JOBS = max(1, int(cfg.get("max_running_jobs", 1)))
    except (TypeError, ValueError):
        MAX_RUNNING_JOBS = 1
    
    # Apply global rate limit
    try:
        GLOBAL_RATE_LIMIT_DELAY = max(0.0, float(cfg.get("global_rate_limit", 0.0)))
    except (TypeError, ValueError):
        GLOBAL_RATE_LIMIT_DELAY = 0.0
    
    parallel_fields = {
        "ffuf": "max_parallel_ffuf",
        "nuclei": "max_parallel_nuclei",
        "nikto": "max_parallel_nikto",
        "gowitness": "max_parallel_gowitness",
        "nmap": "max_parallel_nmap",
        "dnsx": "max_parallel_dnsx",
        "waybackurls": "max_parallel_waybackurls",
        "gau": "max_parallel_gau",
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
        "screenshots_dir": str(SCREENSHOTS_DIR.resolve()),
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
        "enable_crtsh": True,
        "enable_github_subdomains": True,
        "enable_dnsx": True,
        "enable_waybackurls": True,
        "enable_gau": True,
        "wildcard_tlds": ["com", "net", "org", "io", "co", "app", "dev", "us", "uk", "in", "de"],
        "subfinder_threads": 32,
        "assetfinder_threads": 10,
        "findomain_threads": 40,
        "max_parallel_ffuf": 1,
        "max_parallel_nuclei": 1,
        "max_parallel_nikto": 1,
        "max_parallel_gowitness": 1,
        "max_parallel_nmap": 1,
        "max_parallel_dnsx": 1,
        "max_parallel_waybackurls": 1,
        "max_parallel_gau": 1,
        "enable_nmap": True,
        "nmap_timeout": 300,
        "max_nmap_output_size": 5000,
        "max_running_jobs": 1,
        "global_rate_limit": 0.0,
        "tool_flag_templates": {name: "" for name in TEMPLATE_AWARE_TOOLS},
    }


# ================== MONITOR MANAGEMENT ==================


def load_monitors_state() -> Dict[str, Any]:
    ensure_dirs()
    data = {"monitors": {}}
    if MONITORS_FILE.exists():
        try:
            with open(MONITORS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict) and isinstance(raw.get("monitors"), dict):
                data = raw
        except Exception as exc:
            log(f"Error loading monitors.json: {exc}")
    else:
        save_monitors_state()
    with MONITOR_LOCK:
        MONITOR_STATE.clear()
        MONITOR_STATE.update(data.get("monitors", {}))
    return get_monitors_snapshot()


def _save_monitors_locked() -> None:
    payload = {"monitors": MONITOR_STATE}
    tmp_path = MONITORS_FILE.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    tmp_path.replace(MONITORS_FILE)


def save_monitors_state() -> None:
    ensure_dirs()
    with MONITOR_LOCK:
        _save_monitors_locked()


def get_monitors_snapshot() -> List[Dict[str, Any]]:
    with MONITOR_LOCK:
        snapshot = copy.deepcopy(MONITOR_STATE)
    return list(snapshot.values())


def list_monitors(limit_entries: int = MAX_MONITOR_ENTRIES) -> List[Dict[str, Any]]:
    with MONITOR_LOCK:
        monitors = []
        for monitor in MONITOR_STATE.values():
            data = copy.deepcopy(monitor)
            entries_map = data.get("entries") or {}
            entry_items = list(entries_map.values())
            entry_items.sort(key=lambda item: item.get("first_seen") or "", reverse=True)
            total_entries = len(entry_items)
            data["entry_count"] = total_entries
            data["pending_entries"] = sum(1 for item in entry_items if item.get("status") != "dispatched")
            if total_entries > limit_entries:
                data["entries_truncated"] = True
                entry_items = entry_items[:limit_entries]
            else:
                data["entries_truncated"] = False
            data["entries"] = entry_items
            next_ts = data.get("next_check_ts")
            if isinstance(next_ts, (int, float)):
                data["next_check"] = datetime.fromtimestamp(next_ts, tz=timezone.utc).isoformat()
            else:
                data["next_check"] = None
            monitors.append(data)
    monitors.sort(key=lambda item: item.get("name") or item.get("url") or item.get("id") or "")
    return monitors


def add_monitor(name: str, url: str, interval: Optional[int]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    cleaned_url = str(url or "").strip()
    if not cleaned_url:
        return False, "Monitor URL is required.", None
    parsed = urlparse(cleaned_url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Monitor URL must start with http:// or https://", None
    try:
        interval_val = max(60, int(interval or DEFAULT_MONITOR_INTERVAL))
    except (TypeError, ValueError):
        return False, "Interval must be an integer >= 60 seconds.", None
    monitor_id = uuid.uuid4().hex
    now_iso = datetime.now(timezone.utc).isoformat()
    monitor = {
        "id": monitor_id,
        "name": (name or "").strip(),
        "url": cleaned_url,
        "interval": interval_val,
        "created_at": now_iso,
        "last_checked": None,
        "last_status": "pending",
        "last_error": "",
        "last_entry_count": 0,
        "last_new_entries": 0,
        "last_dispatch_count": 0,
        "entries": {},
        "next_check_ts": time.time(),
    }
    with MONITOR_LOCK:
        MONITOR_STATE[monitor_id] = monitor
        _save_monitors_locked()
    log(f"Added monitor {monitor_id} for {cleaned_url}")
    return True, "Monitor added.", copy.deepcopy(monitor)


def remove_monitor(monitor_id: str) -> Tuple[bool, str]:
    monitor_key = (monitor_id or "").strip()
    if not monitor_key:
        return False, "Monitor id is required."
    with MONITOR_LOCK:
        if monitor_key not in MONITOR_STATE:
            return False, "Monitor not found."
        MONITOR_STATE.pop(monitor_key, None)
        _save_monitors_locked()
    log(f"Removed monitor {monitor_key}")
    return True, "Monitor removed."


def parse_monitor_entries(text: str) -> List[str]:
    entries: List[str] = []
    if not text:
        return entries
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def fetch_monitor_source(url: str, timeout: int = 20) -> str:
    req = Request(url, headers={"User-Agent": "ReconMonitor/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


def process_monitor(monitor_id: str) -> None:
    cfg = get_config()
    with MONITOR_LOCK:
        monitor = MONITOR_STATE.get(monitor_id)
        if not monitor:
            return
        monitor_copy = copy.deepcopy(monitor)
    url = monitor_copy.get("url")
    interval = max(60, int(monitor_copy.get("interval") or DEFAULT_MONITOR_INTERVAL))
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        content = fetch_monitor_source(url)
    except Exception as exc:
        with MONITOR_LOCK:
            target = MONITOR_STATE.get(monitor_id)
            if target:
                target["last_checked"] = now_iso
                target["last_status"] = "error"
                target["last_error"] = str(exc)
                target["next_check_ts"] = time.time() + interval
                _save_monitors_locked()
        log(f"Monitor {monitor_id} fetch failed: {exc}")
        return
    entries = parse_monitor_entries(content)
    entries_map = monitor_copy.get("entries") or {}
    if not isinstance(entries_map, dict):
        entries_map = {}
    existing_map = {key: dict(value) for key, value in entries_map.items()}
    new_entries: List[Dict[str, Any]] = []
    for entry in entries:
        meta = existing_map.get(entry)
        if meta:
            meta["last_seen"] = now_iso
        else:
            meta = {
                "value": entry,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "status": "pending",
                "dispatch_message": "",
                "dispatch_results": [],
                "dispatched_targets": [],
                "last_dispatch": None,
            }
            existing_map[entry] = meta
            new_entries.append(meta)
    dispatched_count = 0
    skip_nikto = bool(cfg.get("skip_nikto_by_default", False))
    for meta in new_entries:
        success, message, details = start_targets_from_input(meta["value"], None, skip_nikto, None)
        meta["last_dispatch"] = now_iso
        meta["dispatch_message"] = message
        meta["dispatch_results"] = details
        meta["dispatched_targets"] = [info["target"] for info in details if info.get("success")]
        meta["status"] = "dispatched" if success else "error"
        if success:
            dispatched_count += 1
    with MONITOR_LOCK:
        monitor_ref = MONITOR_STATE.get(monitor_id)
        if not monitor_ref:
            return
        monitor_ref["entries"] = existing_map
        monitor_ref["last_checked"] = now_iso
        monitor_ref["last_status"] = "ok"
        monitor_ref["last_error"] = ""
        monitor_ref["last_entry_count"] = len(entries)
        monitor_ref["last_new_entries"] = len(new_entries)
        monitor_ref["last_dispatch_count"] = dispatched_count
        monitor_ref["next_check_ts"] = time.time() + interval
        _save_monitors_locked()


def monitor_worker_loop() -> None:
    while True:
        time.sleep(MONITOR_POLL_INTERVAL)
        with MONITOR_LOCK:
            due_ids = []
            now_ts = time.time()
            for monitor_id, monitor in MONITOR_STATE.items():
                next_ts = monitor.get("next_check_ts") or 0
                interval = max(60, int(monitor.get("interval") or DEFAULT_MONITOR_INTERVAL))
                if now_ts >= next_ts:
                    monitor["next_check_ts"] = now_ts + interval
                    due_ids.append(monitor_id)
        for monitor_id in due_ids:
            try:
                process_monitor(monitor_id)
            except Exception as exc:
                log(f"Monitor {monitor_id} processing error: {exc}")


def start_monitor_worker() -> None:
    global MONITOR_THREAD
    with MONITOR_LOCK:
        already_running = MONITOR_THREAD and MONITOR_THREAD.is_alive()
    if already_running:
        return
    load_monitors_state()
    thread = threading.Thread(target=monitor_worker_loop, name="monitor-worker", daemon=True)
    thread.start()
    with MONITOR_LOCK:
        MONITOR_THREAD = thread


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
    cfg["tool_flag_templates"] = _normalize_tool_flag_templates(cfg.get("tool_flag_templates"))
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


def _sanitize_domain_input(value: str) -> str:
    if not value:
        return ""
    cleaned = value.strip().lower()
    if not cleaned:
        return ""
    cleaned = cleaned.replace("https://", "").replace("http://", "")
    for delimiter in ("?", "#", "/"):
        if delimiter in cleaned:
            cleaned = cleaned.split(delimiter, 1)[0]
    cleaned = cleaned.strip()
    cleaned = re.sub(r"\s+", "", cleaned)
    return cleaned


def _normalize_tld_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = re.split(r"[,\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    result: List[str] = []
    seen: set = set()
    for item in raw_items:
        text = str(item or "").strip().lower().lstrip(".")
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def expand_wildcard_targets(raw: str, config: Optional[Dict[str, Any]] = None) -> List[str]:
    normalized = _sanitize_domain_input(raw)
    if not normalized:
        return []
    while normalized.startswith("*."):
        normalized = normalized[2:]
    trailing_any_tld = normalized.endswith(".*")
    if trailing_any_tld:
        normalized = normalized[:-2]
    normalized = normalized.strip(".")
    if not normalized:
        return []
    candidates: List[str] = []
    if trailing_any_tld:
        cfg = config or get_config()
        tlds = _normalize_tld_list(cfg.get("wildcard_tlds"))
        for suffix in tlds:
            if not suffix:
                continue
            candidates.append(f"{normalized}.{suffix}")
    else:
        candidates.append(normalized)
    deduped: List[str] = []
    seen: set = set()
    for candidate in candidates:
        cleaned = candidate.strip(".")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped


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

    if "wildcard_tlds" in values:
        new_tlds = _normalize_tld_list(values.get("wildcard_tlds"))
        if cfg.get("wildcard_tlds", []) != new_tlds:
            cfg["wildcard_tlds"] = new_tlds
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

    for key in ["enable_subfinder", "enable_assetfinder", "enable_findomain", "enable_sublist3r", "enable_screenshots", "enable_crtsh", "enable_github_subdomains", "enable_dnsx", "enable_waybackurls", "enable_gau"]:
        if key in values:
            new_value = bool_from_value(values.get(key), cfg.get(key, True))
            if cfg.get(key, True) != new_value:
                cfg[key] = new_value
                changed = True

    # Handle global rate limit (can be 0 or positive float)
    if "global_rate_limit" in values:
        try:
            new_rate_limit = max(0.0, float(values.get("global_rate_limit")))
        except (TypeError, ValueError):
            return False, "Global rate limit must be a number >= 0.", cfg
        if cfg.get("global_rate_limit", 0.0) != new_rate_limit:
            cfg["global_rate_limit"] = new_rate_limit
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
        "max_parallel_dnsx": "DNSx parallel slots",
        "max_parallel_waybackurls": "Waybackurls parallel slots",
        "max_parallel_gau": "GAU parallel slots",
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

    if "tool_flag_templates" in values:
        new_templates = _normalize_tool_flag_templates(values.get("tool_flag_templates"))
        if cfg.get("tool_flag_templates", {}) != new_templates:
            cfg["tool_flag_templates"] = new_templates
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
        if shutil.which("go") and tool in {"amass", "httpx", "nuclei", "subfinder", "assetfinder", "dnsx", "waybackurls", "gau", "github-subdomains"}:
            go_pkgs = {
                "amass": "github.com/owasp-amass/amass/v3/...@latest",
                "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "assetfinder": "github.com/tomnomnom/assetfinder@latest",
                "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                "waybackurls": "github.com/tomnomnom/waybackurls@latest",
                "gau": "github.com/lc/gau/v2/cmd/gau@latest",
                "github-subdomains": "github.com/gwen001/github-subdomains@latest",
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
    
    # Special case: crtsh is API-based, not a binary tool
    if tool == "crtsh":
        TOOLS[tool] = "crtsh"  # Virtual tool
        return True

    log(
        f"Could not auto-install {tool}. Please install it manually and re-run. "
        f"Checked binary name: {exe}"
    )
    return False


def ensure_required_tools() -> None:
    log("Verifying required tooling...")
    for name in TOOLS.keys():
        ensure_tool_installed(name)


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
    # Apply global rate limiting before running any tool
    apply_rate_limit()
    
    display_cmd = " ".join(cmd)
    log(f"Running: {display_cmd}")
    if job_domain:
        job_pause_point(job_domain)
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
    context = {
        "DOMAIN": domain,
        "OUTPUT_PREFIX": str(out_base),
        "OUTPUT_JSON": str(out_json),
    }
    cmd = apply_template_flags("amass", cmd, context, config)
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
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
        "THREADS": threads,
    }
    cmd = apply_template_flags("subfinder", cmd, context, config)
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
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
        "THREADS": threads,
    }
    cmd = apply_template_flags("assetfinder", cmd, context, config)
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
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
        "THREADS": threads,
    }
    cmd = apply_template_flags("findomain", cmd, context, config)
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
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("sublist3r", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="sublist3r")
    return read_lines_file(out_path) if success else []


def crtsh_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Query crt.sh for certificate transparency logs to find subdomains.
    """
    out_path = DATA_DIR / f"crtsh_{domain}.txt"
    subs = set()
    try:
        import urllib.request
        import json as json_lib
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconTool/1.0"})
        if job_domain:
            job_log_append(job_domain, f"Querying crt.sh for {domain}", source="crtsh")
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
        entries = json_lib.loads(data)
        for entry in entries:
            name = entry.get("name_value", "")
            if name:
                for line in name.split("\n"):
                    cleaned = line.strip().lower().lstrip("*.")
                    if cleaned and domain in cleaned:
                        subs.add(cleaned)
        with open(out_path, "w", encoding="utf-8") as f:
            for sub in sorted(subs):
                f.write(sub + "\n")
        if job_domain:
            job_log_append(job_domain, f"crt.sh found {len(subs)} subdomains", source="crtsh")
    except Exception as exc:
        log(f"crt.sh enumeration failed for {domain}: {exc}")
        if job_domain:
            job_log_append(job_domain, f"crt.sh error: {exc}", source="crtsh")
    return sorted(subs)


def github_subdomains_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use github-subdomains tool to find subdomains via GitHub.
    """
    if not ensure_tool_installed("github-subdomains"):
        return []
    out_path = DATA_DIR / f"github_subdomains_{domain}.txt"
    cmd = [
        TOOLS["github-subdomains"],
        "-d", domain,
        "-o", str(out_path),
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("github-subdomains", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="github-subdomains")
    return read_lines_file(out_path) if success else []


def dnsx_verify(subdomains: List[str], domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use dnsx to verify which subdomains actually resolve.
    """
    if not ensure_tool_installed("dnsx"):
        return subdomains
    if not subdomains:
        return []
    
    input_path = DATA_DIR / f"dnsx_input_{domain}.txt"
    out_path = DATA_DIR / f"dnsx_{domain}.txt"
    
    with open(input_path, "w", encoding="utf-8") as f:
        for sub in subdomains:
            f.write(sub + "\n")
    
    cmd = [
        TOOLS["dnsx"],
        "-silent",
        "-l", str(input_path),
        "-o", str(out_path),
    ]
    context = {
        "DOMAIN": domain,
        "INPUT": str(input_path),
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("dnsx", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="dnsx")
    return read_lines_file(out_path) if success else subdomains


def waybackurls_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use waybackurls to discover URLs from archive.org.
    """
    if not ensure_tool_installed("waybackurls"):
        return []
    out_path = DATA_DIR / f"waybackurls_{domain}.txt"
    cmd = [
        TOOLS["waybackurls"],
        domain,
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("waybackurls", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="waybackurls")
    return read_lines_file(out_path) if success else []


def gau_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use gau (Get All URLs) to discover URLs from various sources.
    """
    if not ensure_tool_installed("gau"):
        return []
    out_path = DATA_DIR / f"gau_{domain}.txt"
    cmd = [
        TOOLS["gau"],
        "--subs",
        domain,
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("gau", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="gau")
    return read_lines_file(out_path) if success else []


def harvest_enumerator_outputs(
    domain: str,
    config: Dict[str, Any],
    seen_cache: Dict[str, set],
    job_domain: Optional[str] = None,
) -> bool:
    job_pause_point(job_domain)
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
    process(
        "crtsh",
        config.get("enable_crtsh", True),
        DATA_DIR / f"crtsh_{domain}.txt",
        read_lines_file,
    )
    process(
        "github-subdomains",
        config.get("enable_github_subdomains", True),
        DATA_DIR / f"github_subdomains_{domain}.txt",
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
            job_sleep(job_domain, 5)

    all_subs = wait_for_subdomains()
    log(f"Total unique subdomains for {domain}: {len(all_subs)}")
    subs_file = write_subdomains_file(domain, all_subs)

    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]
    
    # ---------- dnsx (DNS verification) ----------
    if not flags.get("dnsx_done") and config.get("enable_dnsx", True):
        # Get all discovered subdomains from state
        tgt_state = ensure_target_state(state, domain)
        all_discovered_subs = sorted(tgt_state["subdomains"].keys())
        if all_discovered_subs:
            log(f"=== dnsx DNS verification for {domain} ({len(all_discovered_subs)} hosts) ===")
            update_step("dnsx", status="running", message=f"Verifying {len(all_discovered_subs)} subdomains with dnsx", progress=50)
            if job_domain:
                job_log_append(job_domain, "Waiting for dnsx slot...", "scheduler")
            with TOOL_GATES["dnsx"]:
                if job_domain:
                    job_log_append(job_domain, "dnsx slot acquired.", "scheduler")
                verified_subs = dnsx_verify(all_discovered_subs, domain, job_domain=job_domain)
            log(f"dnsx verified {len(verified_subs)} resolving subdomains.")
            flags["dnsx_done"] = True
            save_state(state)
            update_step("dnsx", status="completed", message=f"dnsx verified {len(verified_subs)}/{len(all_discovered_subs)} subdomains resolve.", progress=100)
        else:
            flags["dnsx_done"] = True
            save_state(state)
            update_step("dnsx", status="skipped", message="No subdomains to verify.", progress=0)
    elif not config.get("enable_dnsx", True):
        update_step("dnsx", status="skipped", message="dnsx disabled in settings.", progress=0)
        flags["dnsx_done"] = True
        save_state(state)
    else:
        update_step("dnsx", status="skipped", message="dnsx already completed for this target.", progress=0)

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
                subs_ffuf = ffuf_bruteforce(domain, wordlist, config=config, job_domain=job_domain)
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
        tgt_state = ensure_target_state(state, domain)
        flags = tgt_state["flags"]
        submap = tgt_state["subdomains"]
        new_hosts = [
            host for host in sorted(submap.keys())
            if host not in httpx_processed and not (submap.get(host) or {}).get("httpx")
        ]
        if not flags.get("httpx_done") and not httpx_processed:
            log(f"=== httpx scan for {domain} ({len(submap)} hosts tracked) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["httpx_done"] = True
                save_state(state)
                update_step("httpx", status="completed", message="httpx scan finished.", progress=100)
                break
            job_sleep(job_domain, 5)
            continue
        update_step("httpx", status="running", message=f"httpx scanning {len(new_hosts)} pending hosts", progress=40)
        batch_file = write_subdomains_file(domain, new_hosts, suffix="_httpx_batch")
        httpx_json = httpx_scan(batch_file, domain, config=config, job_domain=job_domain)
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
        mark_hosts_scanned(state, domain, new_hosts, "httpx")
        httpx_processed.update(new_hosts)
        save_state(state)
        job_log_append(job_domain, f"httpx scanned {len(new_hosts)} hosts.", "httpx")
    
    # ---------- waybackurls (URL discovery) ----------
    if not flags.get("waybackurls_done") and config.get("enable_waybackurls", True):
        log(f"=== waybackurls URL discovery for {domain} ===")
        update_step("waybackurls", status="running", message="Discovering URLs from archive.org", progress=50)
        if job_domain:
            job_log_append(job_domain, "Waiting for waybackurls slot...", "scheduler")
        with TOOL_GATES["waybackurls"]:
            if job_domain:
                job_log_append(job_domain, "waybackurls slot acquired.", "scheduler")
            urls = waybackurls_enum(domain, job_domain=job_domain)
        log(f"waybackurls found {len(urls)} URLs.")
        flags["waybackurls_done"] = True
        save_state(state)
        update_step("waybackurls", status="completed", message=f"waybackurls found {len(urls)} URLs.", progress=100)
    elif not config.get("enable_waybackurls", True):
        update_step("waybackurls", status="skipped", message="waybackurls disabled in settings.", progress=0)
        flags["waybackurls_done"] = True
        save_state(state)
    else:
        update_step("waybackurls", status="skipped", message="waybackurls already completed for this target.", progress=0)
    
    # ---------- gau (Get All URLs) ----------
    if not flags.get("gau_done") and config.get("enable_gau", True):
        log(f"=== gau URL discovery for {domain} ===")
        update_step("gau", status="running", message="Discovering URLs from multiple sources", progress=50)
        if job_domain:
            job_log_append(job_domain, "Waiting for gau slot...", "scheduler")
        with TOOL_GATES["gau"]:
            if job_domain:
                job_log_append(job_domain, "gau slot acquired.", "scheduler")
            urls = gau_enum(domain, job_domain=job_domain)
        log(f"gau found {len(urls)} URLs.")
        flags["gau_done"] = True
        save_state(state)
        update_step("gau", status="completed", message=f"gau found {len(urls)} URLs.", progress=100)
    elif not config.get("enable_gau", True):
        update_step("gau", status="skipped", message="gau disabled in settings.", progress=0)
        flags["gau_done"] = True
        save_state(state)
    else:
        update_step("gau", status="skipped", message="gau already completed for this target.", progress=0)

    # ---------- screenshots ----------
    if not config.get("enable_screenshots", True):
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        update_step("screenshots", status="skipped", message="Screenshots disabled in settings.", progress=0)
        flags["screenshots_done"] = True
        save_state(state)
    else:
        while True:
            state = load_state()
            tgt_state = ensure_target_state(state, domain)
            flags = tgt_state["flags"]
            screenshot_targets = gather_screenshot_targets(state, domain)
            if not screenshot_targets:
                if enumerators_done_event.is_set():
                    flags["screenshots_done"] = True
                    save_state(state)
                    update_step("screenshots", status="completed", message="Screenshot capture finished.", progress=100)
                    break
                job_sleep(job_domain, 5)
                continue
            update_step("screenshots", status="running", message=f"Capturing screenshots for {len(screenshot_targets)} hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for screenshot slot...", "scheduler")
            with TOOL_GATES["gowitness"]:
                if job_domain:
                    job_log_append(job_domain, "Screenshot slot acquired.", "scheduler")
                screenshot_map = capture_screenshots(screenshot_targets, domain, config=config, job_domain=job_domain)
            if not screenshot_map:
                job_log_append(job_domain, "Screenshot batch failed.", "screenshots")
                update_step("screenshots", status="error", message="Screenshot capture failed.", progress=100)
                break
            state = load_state()
            enrich_state_with_screenshots(state, domain, screenshot_map)
            save_state(state)
            job_log_append(job_domain, f"Captured screenshots for {len(screenshot_map)} hosts.", "screenshots")
            update_step("screenshots", status="running", message=f"Captured {len(screenshot_map)} screenshots. Waiting for new hosts…", progress=75)

    # ---------- nmap ----------
    if not config.get("enable_nmap", True):
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        update_step("nmap", status="skipped", message="Nmap disabled in settings.", progress=0)
        flags["nmap_done"] = True
        save_state(state)
    else:
        nmap_processed: set = set()
        while True:
            state = load_state()
            tgt_state = ensure_target_state(state, domain)
            flags = tgt_state["flags"]
            submap = tgt_state["subdomains"]
            # Only scan hosts with HTTP services detected
            new_hosts = [
                host for host in sorted(submap.keys())
                if host not in nmap_processed 
                and (submap.get(host) or {}).get("httpx")
                and not (submap.get(host) or {}).get("scans", {}).get("nmap")
            ]
            if not flags.get("nmap_done") and not nmap_processed:
                log(f"=== nmap scan for {domain} ({len(new_hosts)} hosts with HTTP) ===")
            if not new_hosts:
                if enumerators_done_event.is_set():
                    flags["nmap_done"] = True
                    save_state(state)
                    update_step("nmap", status="completed", message="Nmap scan finished.", progress=100)
                    break
                job_sleep(job_domain, 5)
                continue
            update_step("nmap", status="running", message=f"Nmap scanning {len(new_hosts)} pending hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for nmap slot...", "scheduler")
            with TOOL_GATES["nmap"]:
                if job_domain:
                    job_log_append(job_domain, "Nmap slot acquired.", "scheduler")
                nmap_json = nmap_scan(new_hosts, domain, config=config, job_domain=job_domain)
            if not nmap_json:
                job_log_append(job_domain, "Nmap batch failed.", "nmap")
                update_step("nmap", status="error", message="Nmap batch failed. Check logs for details.", progress=100)
                break
            enrich_state_with_nmap(state, domain, nmap_json)
            mark_hosts_scanned(state, domain, new_hosts, "nmap")
            nmap_processed.update(new_hosts)
            save_state(state)
            job_log_append(job_domain, f"Nmap scanned {len(new_hosts)} hosts.", "nmap")

    # ---------- nuclei ----------
    nuclei_processed: set = set()
    while True:
        state = load_state()
        tgt_state = ensure_target_state(state, domain)
        flags = tgt_state["flags"]
        submap = tgt_state["subdomains"]
        new_hosts = [
            host for host in sorted(submap.keys())
            if host not in nuclei_processed and not (submap.get(host) or {}).get("scans", {}).get("nuclei")
        ]
        if not flags.get("nuclei_done") and not nuclei_processed:
            log(f"=== nuclei scan for {domain} ({len(submap)} hosts tracked) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["nuclei_done"] = True
                save_state(state)
                update_step("nuclei", status="completed", message="nuclei scan finished.", progress=100)
                break
            job_sleep(job_domain, 5)
            continue
        update_step("nuclei", status="running", message=f"nuclei scanning {len(new_hosts)} pending hosts", progress=40)
        batch_file = write_subdomains_file(domain, new_hosts, suffix="_nuclei_batch")
        if job_domain:
            job_log_append(job_domain, "Waiting for nuclei slot...", "scheduler")
        with TOOL_GATES["nuclei"]:
            if job_domain:
                job_log_append(job_domain, "nuclei slot acquired.", "scheduler")
            nuclei_json = nuclei_scan(batch_file, domain, config=config, job_domain=job_domain)
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
        mark_hosts_scanned(state, domain, new_hosts, "nuclei")
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
            tgt_state = ensure_target_state(state, domain)
            flags = tgt_state["flags"]
            submap = tgt_state["subdomains"]
            new_hosts = [
                host for host in sorted(submap.keys())
                if host not in nikto_processed and not (submap.get(host) or {}).get("scans", {}).get("nikto")
            ]
            if not flags.get("nikto_done") and not nikto_processed:
                log(f"=== nikto scan for {domain} ({len(submap)} hosts tracked) ===")
            if not new_hosts:
                if enumerators_done_event.is_set():
                    flags["nikto_done"] = True
                    save_state(state)
                    update_step("nikto", status="completed", message="Nikto scan finished.", progress=100)
                    break
                job_sleep(job_domain, 5)
                continue
            update_step("nikto", status="running", message=f"Nikto scanning {len(new_hosts)} pending hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for Nikto slot...", "scheduler")
            with TOOL_GATES["nikto"]:
                if job_domain:
                    job_log_append(job_domain, "Nikto slot acquired.", "scheduler")
                nikto_json = nikto_scan(new_hosts, domain, config=config, job_domain=job_domain)
            if not nikto_json:
                job_log_append(job_domain, "Nikto batch failed.", "nikto")
                update_step("nikto", status="error", message="Nikto batch failed. Check logs for details.", progress=100)
                break
            enrich_state_with_nikto(state, domain, nikto_json)
            mark_hosts_scanned(state, domain, new_hosts, "nikto")
            nikto_processed.update(new_hosts)
            save_state(state)
            job_log_append(job_domain, f"Nikto scanned {len(new_hosts)} hosts.", "nikto")

    log("Pipeline finished for this run.")


def ffuf_bruteforce(
    domain: str,
    wordlist: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
) -> List[str]:
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
    context = {
        "DOMAIN": domain,
        "WORDLIST": wordlist,
        "OUTPUT": str(out_json),
        "TARGET_URL": f"http://{domain}",
        "HOST_HEADER": f"FUZZ.{domain}",
    }
    cmd = apply_template_flags("ffuf", cmd, context, config)
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


def httpx_scan(subs_file: Path, domain: str, config: Optional[Dict[str, Any]] = None,
               job_domain: Optional[str] = None) -> Path:
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
    context = {
        "DOMAIN": domain,
        "INPUT_FILE": str(subs_file),
        "OUTPUT": str(out_json),
    }
    cmd = apply_template_flags("httpx", cmd, context, config)
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
        if info.get("screenshot"):
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
    config: Optional[Dict[str, Any]] = None,
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
    context = {
        "DOMAIN": domain,
        "TARGETS_FILE": str(target_file),
        "OUTPUT_DIR": str(dest_dir),
        "DB_PATH": str(db_path),
    }
    cmd = apply_template_flags("gowitness", cmd, context, config)
    success = run_subprocess(cmd, job_domain=job_domain, step="screenshots")
    try:
        target_file.unlink(missing_ok=True)
    except Exception:
        pass
    if not success:
        return {}

    recent_files: Dict[str, Path] = {}
    cutoff = run_started
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


def nuclei_scan(subs_file: Path, domain: str, config: Optional[Dict[str, Any]] = None,
                job_domain: Optional[str] = None) -> Path:
    if not ensure_tool_installed("nuclei"):
        return None
    out_json = DATA_DIR / f"nuclei_{domain}.json"
    cmd = [
        TOOLS["nuclei"],
        "-l", str(subs_file),
        "-jsonl",
    ]
    context = {
        "DOMAIN": domain,
        "INPUT_FILE": str(subs_file),
        "OUTPUT": str(out_json),
    }
    cmd = apply_template_flags("nuclei", cmd, context, config)
    success = run_subprocess(cmd, outfile=out_json, job_domain=job_domain, step="nuclei")
    return out_json if success and out_json.exists() else None


def _normalize_nikto_severity(value: Any, message: Optional[str] = None) -> str:
    if value is None:
        text = ""
    else:
        text = str(value).strip().lower()
    numeric_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "LOW",
        "3": "MEDIUM",
        "4": "HIGH",
        "5": "CRITICAL",
    }
    if text in numeric_map:
        return numeric_map[text]
    allowed = {"critical", "high", "medium", "low", "info"}
    if text in allowed:
        return text.upper()
    return "INFO"


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
        lower = normalized.lower()
        skip_prefixes = (
            "target ip",
            "target hostname",
            "target port",
            "start time",
            "end time",
            "scan terminated",
            "host(s) tested",
            "nikto",
        )
        if any(lower.startswith(prefix) for prefix in skip_prefixes):
            continue
        finding: Dict[str, Any] = {
            "host": host,
            "msg": normalized,
            "severity": _normalize_nikto_severity(None, normalized),
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


def nikto_scan(subs: List[str], domain: str, config: Optional[Dict[str, Any]] = None,
               job_domain: Optional[str] = None) -> Path:
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
        context = {
            "DOMAIN": domain,
            "SUBDOMAIN": host,
            "TARGET_URL": target,
            "OUTPUT": str(out_json),
        }
        cmd = apply_template_flags("nikto", cmd, context, config)
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

        stdout_text = proc.stdout or ""
        stderr_text = proc.stderr or ""
        if job_domain and stdout_text:
            job_log_append(job_domain, stdout_text, source="nikto")
        if job_domain and stderr_text:
            job_log_append(job_domain, stderr_text, source="nikto stderr")

        host_findings = _parse_nikto_output(host, stdout_text)
        if host_findings:
            results.extend(host_findings)
        if proc.returncode != 0 and not host_findings:
            log(f"Nikto failed for {host}: {stderr_text[:300]}")
            continue

    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        log(f"Error writing Nikto JSON: {e}")
        return None

    return out_json if out_json.exists() else None


def nmap_scan(subs: List[str], domain: str, config: Optional[Dict[str, Any]] = None,
              job_domain: Optional[str] = None) -> Path:
    """
    Run nmap port scan on discovered subdomains with live HTTP services.
    """
    if not ensure_tool_installed("nmap"):
        return None
    out_json = DATA_DIR / f"nmap_{domain}.json"

    results: List[Dict[str, Any]] = []
    for host in subs:
        cmd = [
            TOOLS["nmap"],
            "-sV",  # Service version detection
            "-T4",  # Faster timing
            "--top-ports", "100",  # Scan top 100 ports
            "-oX", "-",  # Output XML to stdout
            host,
        ]
        context = {
            "DOMAIN": domain,
            "SUBDOMAIN": host,
            "OUTPUT": str(out_json),
        }
        cmd = apply_template_flags("nmap", cmd, context, config)
        log(f"Running nmap against {host}")
        if job_domain:
            job_log_append(job_domain, f"Nmap scanning {host}", source="nmap")
        
        # Get configurable timeout, default to 300 seconds (5 minutes)
        nmap_timeout = 300
        if config:
            try:
                nmap_timeout = max(60, int(config.get("nmap_timeout", 300)))
            except (TypeError, ValueError):
                nmap_timeout = 300
        
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=nmap_timeout,
            )
        except FileNotFoundError:
            log("Nmap binary not found during run.")
            return None
        except subprocess.TimeoutExpired:
            log(f"Nmap timeout for {host}")
            if job_domain:
                job_log_append(job_domain, f"Nmap timeout for {host}", source="nmap")
            continue
        except Exception as e:
            log(f"Nmap error for {host}: {e}")
            if job_domain:
                job_log_append(job_domain, f"Nmap error for {host}: {e}", source="nmap")
            continue

        stdout_text = proc.stdout or ""
        stderr_text = proc.stderr or ""
        if job_domain and stderr_text:
            job_log_append(job_domain, stderr_text, source="nmap stderr")

        # Store nmap XML output (raw format for future parsing)
        # Output is stored as-is; consider implementing XML parsing for structured data extraction
        if stdout_text.strip():
            max_output_size = config.get("max_nmap_output_size", 5000) if config else 5000
            results.append({
                "host": host,
                "scan_output": stdout_text[:max_output_size],  # Limit output size to prevent excessive storage
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            if job_domain:
                # Log a summary instead of full output
                log_summary = f"Nmap completed for {host} ({len(stdout_text)} bytes)"
                job_log_append(job_domain, log_summary, source="nmap")

    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        log(f"Error writing Nmap JSON: {e}")
        return None

    return out_json if out_json.exists() else None


# ================== STATE ENRICHMENT ==================


def make_subdomain_entry() -> Dict[str, Any]:
    return {
        "sources": [],
        "httpx": None,
        "nuclei": [],
        "nikto": [],
        "nmap": None,
        "screenshot": None,
        "scans": {},
    }


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
            "nmap_done": False,
            "nuclei_done": False,
            "nikto_done": False,
        }
    })
    # Normalize missing keys
    tgt.setdefault("subdomains", {})
    tgt.setdefault("flags", {})
    tgt.setdefault("options", {})
    for k in ["amass_done", "subfinder_done", "assetfinder_done", "findomain_done", "sublist3r_done",
              "ffuf_done", "httpx_done", "screenshots_done", "nmap_done", "nuclei_done", "nikto_done"]:
        tgt["flags"].setdefault(k, False)
    for sub, entry in list(tgt["subdomains"].items()):
        if not isinstance(entry, dict):
            tgt["subdomains"][sub] = make_subdomain_entry()
            continue
        entry.setdefault("sources", [])
        entry.setdefault("httpx", None)
        entry.setdefault("nuclei", [])
        entry.setdefault("nikto", [])
        entry.setdefault("nmap", None)
        entry.setdefault("screenshot", None)
        entry.setdefault("scans", {})
    return tgt


def add_subdomains_to_state(state: Dict[str, Any], domain: str, subs: List[str], source: str) -> None:
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for s in subs:
        s = s.strip().lower()
        if not s:
            continue
        entry = submap.setdefault(s, make_subdomain_entry())
        entry.setdefault("sources", [])
        entry.setdefault("screenshot", None)
        entry.setdefault("scans", {})
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
                entry = submap.setdefault(host, make_subdomain_entry())
                entry.setdefault("screenshot", None)
                entry.setdefault("scans", {})
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
                entry = submap.setdefault(host, make_subdomain_entry())
                entry.setdefault("screenshot", None)
                entry.setdefault("scans", {})
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
            entry = submap.setdefault(host, make_subdomain_entry())
            entry.setdefault("screenshot", None)
            entry.setdefault("scans", {})
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
                        "severity": _normalize_nikto_severity(v.get("risk"), v.get("msg") or v.get("description") or v.get("message")),
                    })
                else:
                    normalized_vulns.append({"raw": str(v), "severity": _normalize_nikto_severity(None, str(v))})
            entry.setdefault("nikto", []).extend(normalized_vulns)
    except Exception as e:
        log(f"Error enriching state with nikto data: {e}")


def enrich_state_with_nmap(state: Dict[str, Any], domain: str, nmap_json: Path) -> None:
    if not nmap_json or not nmap_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        data = json.loads(nmap_json.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = [data]
        for obj in data:
            host = obj.get("host")
            if not host:
                continue
            host = str(host).lower()
            entry = submap.setdefault(host, make_subdomain_entry())
            entry.setdefault("scans", {})
            # Store nmap scan data
            entry["nmap"] = {
                "scan_output": obj.get("scan_output", ""),
                "timestamp": obj.get("timestamp"),
            }
    except Exception as e:
        log(f"Error enriching state with nmap data: {e}")


def enrich_state_with_screenshots(state: Dict[str, Any], domain: str, mapping: Dict[str, Dict[str, Any]]) -> None:
    if not mapping:
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for host, data in mapping.items():
        entry = submap.setdefault(host, make_subdomain_entry())
        entry.setdefault("scans", {})
        entry["screenshot"] = data


def mark_hosts_scanned(state: Dict[str, Any], domain: str, hosts: List[str], step: str) -> None:
    if not hosts:
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    timestamp = datetime.now(timezone.utc).isoformat()
    for host in hosts:
        host_norm = (host or "").strip().lower()
        if not host_norm:
            continue
        entry = submap.setdefault(host_norm, make_subdomain_entry())
        scans = entry.setdefault("scans", {})
        scans[step] = timestamp


def target_has_pending_work(target: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> bool:
    flags = target.get("flags", {})
    if any(not bool(value) for value in flags.values()):
        return True
    submap = target.get("subdomains", {})
    enable_screenshots = True if config is None else config.get("enable_screenshots", True)
    options = target.get("options", {}) or {}
    skip_nikto = options.get("skip_nikto")
    if skip_nikto is None and config is not None:
        skip_nikto = bool(config.get("skip_nikto_by_default", False))
    else:
        skip_nikto = bool(skip_nikto)
    for entry in submap.values():
        if not isinstance(entry, dict):
            return True
        scans = entry.get("scans") or {}
        if not entry.get("httpx"):
            return True
        if enable_screenshots and entry.get("httpx") and not entry.get("screenshot"):
            return True
        if not scans.get("nuclei"):
            return True
        if not skip_nikto and not scans.get("nikto"):
            return True
    return False


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
    options = tgt.setdefault("options", {})
    if options.get("skip_nikto") != skip_nikto:
        options["skip_nikto"] = skip_nikto
        save_state(state)

    enumerators_done_event = threading.Event()
    downstream_started = threading.Event()
    downstream_thread_holder: Dict[str, threading.Thread] = {}
    seen_cache = {
        "amass": set(),
        "subfinder": set(),
        "assetfinder": set(),
        "findomain": set(),
        "sublist3r": set(),
        "crtsh": set(),
        "github-subdomains": set(),
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
            job_sleep(job_domain, 30)
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
        update_step("crtsh", status="skipped", message="Input is a subdomain; crt.sh skipped.", progress=0)
        update_step("github-subdomains", status="skipped", message="Input is a subdomain; GitHub subdomains skipped.", progress=0)
    else:
        enumerator_specs = []
        enable_subfinder = config.get("enable_subfinder", True)
        enable_assetfinder = config.get("enable_assetfinder", True)
        enable_findomain = config.get("enable_findomain", True)
        enable_sublist3r = config.get("enable_sublist3r", True)
        enable_crtsh = config.get("enable_crtsh", True)
        enable_github_subdomains = config.get("enable_github_subdomains", True)

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
        maybe_add_enum(
            "crtsh",
            "crtsh_done",
            "crt.sh",
            lambda: crtsh_enum(domain, job_domain=job_domain),
            enable_crtsh,
        )
        maybe_add_enum(
            "github-subdomains",
            "github_subdomains_done",
            "GitHub Subdomains",
            lambda: github_subdomains_enum(domain, job_domain=job_domain),
            enable_github_subdomains,
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
            cleanup_job_control(domain)

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


def load_domain_history(domain: str) -> List[Dict[str, Any]]:
    history_file = HISTORY_DIR / f"{domain}.jsonl"
    events: List[Dict[str, Any]] = []
    if not history_file.exists():
        return events
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
        raise RuntimeError(f"Failed to read history for {domain}: {exc}") from exc
    return events


def ensure_job_control(domain: Optional[str]) -> Optional[JobControl]:
    if not domain:
        return None
    with JOB_CONTROL_LOCK:
        ctrl = JOB_CONTROLS.get(domain)
        if ctrl is None:
            ctrl = JobControl()
            JOB_CONTROLS[domain] = ctrl
        return ctrl


def get_job_control(domain: Optional[str]) -> Optional[JobControl]:
    if not domain:
        return None
    with JOB_CONTROL_LOCK:
        return JOB_CONTROLS.get(domain)


def cleanup_job_control(domain: Optional[str]) -> None:
    if not domain:
        return
    with JOB_CONTROL_LOCK:
        JOB_CONTROLS.pop(domain, None)
        ACTIVE_PAUSED_JOBS.discard(domain)


def job_pause_point(domain: Optional[str]) -> None:
    if not domain:
        return
    ctrl = get_job_control(domain)
    if not ctrl or not ctrl.is_pause_requested():
        return
    should_notify = False
    with JOB_CONTROL_LOCK:
        if domain not in ACTIVE_PAUSED_JOBS:
            ACTIVE_PAUSED_JOBS.add(domain)
            should_notify = True
    if should_notify:
        job_set_status(domain, "paused", "Job paused by user.")
        job_log_append(domain, "Job paused by user.", "scheduler")
    ctrl.wait_until_resumed()
    removed = False
    with JOB_CONTROL_LOCK:
        if domain in ACTIVE_PAUSED_JOBS:
            ACTIVE_PAUSED_JOBS.remove(domain)
            removed = True
    if removed:
        job_set_status(domain, "running", "Job resumed.")
        job_log_append(domain, "Job resumed by user.", "scheduler")


def job_sleep(job_domain: Optional[str], seconds: float, chunk: float = 1.0) -> None:
    if seconds <= 0:
        return
    end_time = time.time() + seconds
    while True:
        remaining = end_time - time.time()
        if remaining <= 0:
            break
        job_pause_point(job_domain)
        time.sleep(min(chunk, max(0.1, remaining)))

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
.status-paused { background:rgba(250,204,21,0.15); border-color:#facc15; color:#fef3c7; }
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
.job-actions { margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; }
.queue-card { display:flex; flex-direction:column; gap:8px; }
.queue-row { display:flex; justify-content:space-between; align-items:center; }
.queue-meta { display:flex; flex-wrap:wrap; gap:12px; font-size:13px; color:var(--muted); }
.worker-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; }
.worker-card { background:var(--panel-alt); border-radius:14px; padding:16px; border:1px solid #1f2937; box-shadow:0 10px 20px rgba(0,0,0,0.2); }
.worker-card h3 { margin:0 0 8px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.worker-card .metric { font-size:32px; font-weight:600; }
.worker-card .muted { margin-top:4px; }
.worker-progress { margin-top:10px; }
.workflow-stage { margin-bottom:24px; }
.workflow-stage-title { font-size:13px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; margin-bottom:12px; display:flex; align-items:center; gap:8px; }
.workflow-stage-title::before { content:'▸'; color:#3b82f6; }
.workflow-tools { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
.workflow-tool { background:#0b152c; border:1px solid #1f2937; border-radius:8px; padding:8px 14px; font-size:12px; font-weight:500; color:#e2e8f0; display:inline-flex; align-items:center; gap:6px; }
.workflow-tool.enumeration { border-color:#8b5cf6; background:rgba(139,92,246,0.1); color:#c4b5fd; }
.workflow-tool.brute-force { border-color:#f59e0b; background:rgba(245,158,11,0.1); color:#fcd34d; }
.workflow-tool.probing { border-color:#06b6d4; background:rgba(6,182,212,0.1); color:#a5f3fc; }
.workflow-tool.url-discovery { border-color:#ec4899; background:rgba(236,72,153,0.1); color:#f9a8d4; }
.workflow-tool.scanning { border-color:#10b981; background:rgba(16,185,129,0.1); color:#a7f3d0; }
.workflow-tool.capture { border-color:#6366f1; background:rgba(99,102,241,0.1); color:#c7d2fe; }
.workflow-arrow { color:#64748b; font-size:18px; }
.workflow-description { font-size:12px; color:var(--muted); margin-top:8px; margin-left:20px; }
.btn { display:inline-block; padding:8px 16px; border-radius:8px; background:var(--accent); color:white; font-weight:600; border:none; cursor:pointer; transition:background .2s ease; text-decoration:none; }
.btn.secondary { background:#1f2937; }
.btn.small { padding:6px 12px; font-size:13px; }
.btn:hover { background:#1d4ed8; }
.export-actions { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:16px; }
.targets-table { width:100%; border-collapse:collapse; font-size:13px; }
.targets-table th, .targets-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.targets-table th { background:#162132; }
.reports-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
.reports-table th, .reports-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.reports-table th { background:#162132; }
.reports-layout { display:grid; grid-template-columns:280px 1fr; gap:20px; align-items:flex-start; }
.reports-nav { display:flex; flex-direction:column; gap:12px; }
.report-nav-card { border:1px solid #1f2937; border-radius:12px; padding:14px; background:var(--panel-alt); cursor:pointer; transition:border-color .2s ease, background .2s ease; }
.report-nav-card .domain-row { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:6px; }
.report-nav-card .domain { font-weight:600; }
.report-nav-card .meta { font-size:12px; color:var(--muted); display:flex; flex-wrap:wrap; gap:8px; }
.report-nav-card .stat { font-weight:600; color:#e2e8f0; }
.report-nav-card .pending { color:#facc15; }
.report-nav-card.active { border-color:var(--accent); box-shadow:0 0 0 1px rgba(37,99,235,0.4); background:#0b152c; }
.report-detail { background:var(--panel-alt); border:1px solid #1f2937; border-radius:16px; padding:22px; min-height:300px; }
.report-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
.report-header .report-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.report-stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-top:16px; }
.report-stat { background:#050b18; border:1px solid #1f2937; border-radius:12px; padding:12px; }
.report-stat .label { font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); margin-bottom:4px; }
.report-stat .value { font-size:20px; font-weight:600; }
.report-section { margin-top:24px; }
.filter-bar { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-bottom:12px; }
.filter-group { display:flex; flex-wrap:wrap; gap:8px; }
.filter-group label { font-size:12px; display:flex; align-items:center; gap:4px; background:#0b152c; padding:4px 8px; border-radius:8px; border:1px solid #1f2937; }
.filter-group input[type="checkbox"] { accent-color:#2563eb; }
.report-search { padding:8px 10px; border-radius:8px; border:1px solid #1f2937; background:#050b18; color:var(--text); min-width:200px; }
.report-badge { display:inline-flex; align-items:center; padding:4px 8px; border-radius:999px; font-size:12px; border:1px solid transparent; }
.report-badge.pending { border-color:#facc15; color:#facc15; }
.report-badge.complete { border-color:#16a34a; color:#86efac; }
.command-list { list-style:none; margin:0; padding:0; border:1px solid #1f2937; border-radius:12px; background:#050b18; max-height:240px; overflow:auto; }
.command-item { padding:8px 12px; border-bottom:1px solid #1f2937; font-family:'JetBrains Mono','Fira Code','SFMono-Regular',monospace; font-size:12px; }
.command-item:last-child { border-bottom:none; }
.command-time { color:var(--muted); margin-right:8px; }
.command-text { color:#e2e8f0; word-break:break-all; }
.severity-pill { display:inline-flex; align-items:center; padding:2px 6px; border-radius:999px; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; margin-right:4px; }
.severity-pill.CRITICAL { background:rgba(239,68,68,0.2); color:#fecaca; }
.severity-pill.HIGH { background:rgba(249,115,22,0.2); color:#fed7aa; }
.severity-pill.MEDIUM { background:rgba(234,179,8,0.2); color:#fde68a; }
.severity-pill.LOW { background:rgba(34,197,94,0.2); color:#bbf7d0; }
.severity-pill.INFO { background:rgba(59,130,246,0.2); color:#bfdbfe; }
.severity-pill.NONE { background:rgba(148,163,184,0.2); color:#e2e8f0; }
.severity-flag { display:inline-flex; align-items:center; padding:2px 10px; border-radius:999px; font-size:11px; font-weight:600; letter-spacing:0.04em; text-transform:uppercase; border:1px solid transparent; }
.severity-flag.CRITICAL { background:rgba(239,68,68,0.15); border-color:rgba(239,68,68,0.4); color:#fecaca; }
.severity-flag.HIGH { background:rgba(249,115,22,0.15); border-color:rgba(249,115,22,0.4); color:#fed7aa; }
.severity-flag.MEDIUM { background:rgba(234,179,8,0.15); border-color:rgba(234,179,8,0.4); color:#fde68a; }
.severity-flag.LOW { background:rgba(34,197,94,0.15); border-color:rgba(34,197,94,0.4); color:#bbf7d0; }
.severity-flag.INFO { background:rgba(59,130,246,0.15); border-color:rgba(59,130,246,0.4); color:#bfdbfe; }
.severity-flag.NONE { background:transparent; border-color:#1f2937; color:#94a3b8; }
.report-table-note { font-size:12px; color:var(--muted); margin-top:6px; }
.collapsible { border:1px solid #1f2937; border-radius:14px; margin-top:16px; overflow:hidden; background:#050b18; }
.collapsible-header { width:100%; background:none; border:none; padding:14px 18px; display:flex; justify-content:space-between; align-items:center; font-size:16px; font-weight:600; color:#e2e8f0; cursor:pointer; }
.collapsible-header .chevron { transition:transform .2s ease; }
.collapsible.open .collapsible-header .chevron { transform:rotate(90deg); }
.collapsible-body { max-height:0; overflow:hidden; transition:max-height .25s ease, padding .25s ease; padding:0 18px; }
.collapsible.open .collapsible-body { padding:0 18px 18px 18px; max-height:4000px; }
.collapsible:first-of-type { margin-top:0; }
.table-pagination { display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:flex-end; margin-top:10px; font-size:12px; }
.table-pagination button { border:1px solid #1f2937; background:#0b152c; color:#e2e8f0; border-radius:6px; padding:4px 10px; cursor:pointer; font-size:12px; }
.table-pagination button[disabled] { opacity:0.4; cursor:not-allowed; }
.table-pagination .page-info { color:var(--muted); margin-right:auto; }
.progress-track { margin:12px 0; }
.progress-track .label { font-size:12px; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:4px; }
.progress-track .progress-bar { height:10px; background:#1e293b; border-radius:999px; overflow:hidden; }
.progress-track .progress-inner { height:100%; background:#3b82f6; border-radius:999px; transition:width .3s ease; }
.step-checklist { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-top:14px; }
.step-checklist .step { padding:8px 10px; border:1px solid #1f2937; border-radius:10px; background:#0b152c; display:flex; justify-content:space-between; align-items:center; font-size:12px; }
.step-checklist .step span { text-transform:capitalize; }
.monitor-list { margin-top:18px; display:flex; flex-direction:column; gap:16px; }
.monitor-card { border:1px solid #1f2937; border-radius:16px; padding:18px; background:#050b18; }
.monitor-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
.monitor-meta { font-size:13px; color:var(--muted); margin-top:4px; }
.monitor-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.monitor-stats { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0; font-size:13px; }
.monitor-stats span { background:#0b152c; padding:6px 10px; border-radius:10px; border:1px solid #1f2937; }
.monitor-entry-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
.monitor-entry-table th, .monitor-entry-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.monitor-entry-table th { background:#162132; }
.monitor-entry-note { font-size:12px; color:var(--muted); margin-top:6px; }
.monitor-list { margin-top:18px; display:flex; flex-direction:column; gap:16px; }
.monitor-card { border:1px solid #1f2937; border-radius:16px; padding:18px; background:#050b18; }
.monitor-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
.monitor-meta { font-size:13px; color:var(--muted); margin-top:4px; }
.monitor-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.monitor-stats { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0; font-size:13px; }
.monitor-stats span { background:#0b152c; padding:6px 10px; border-radius:10px; border:1px solid #1f2937; }
.monitor-entry-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
.monitor-entry-table th, .monitor-entry-table td { border:1px solid #1f2937; padding:6px 8px; text-align:left; }
.monitor-entry-table th { background:#162132; }
.monitor-entry-note { font-size:12px; color:var(--muted); margin-top:6px; }
@media (max-width: 900px) {
  .reports-layout { grid-template-columns:1fr; }
}
.link-btn { background:none; border:none; color:#93c5fd; cursor:pointer; text-decoration:underline; padding:0; font:inherit; }
.modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(2,6,23,0.85); display:none; align-items:center; justify-content:center; z-index:1000; }
.modal-overlay.show { display:flex; }
.modal { width:90%; max-width:900px; max-height:90vh; overflow-y:auto; background:#0f172a; border:1px solid #1e293b; border-radius:16px; padding:24px; box-shadow:0 25px 60px rgba(0,0,0,0.5); }
.modal h3 { margin-top:0; color:#fbbf24; }
.modal-close { position:absolute; top:16px; right:24px; background:none; border:none; color:#f87171; font-size:24px; cursor:pointer; }
.detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:16px; margin-bottom:16px; }
.detail-section { margin-bottom:24px; padding:16px; background:#050b18; border:1px solid #1e293b; border-radius:12px; }
.detail-section h4 { margin-top:0; margin-bottom:12px; color:#fbbf24; font-size:16px; }
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
.template-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin-top:10px; }
.template-input { width:100%; min-height:56px; background:#0b152c; border:1px solid #1f2937; color:var(--text); border-radius:8px; padding:10px; font-family:'JetBrains Mono','Fira Code','SFMono-Regular',monospace; font-size:12px; }
.template-note { margin:8px 0 0; color:var(--muted); font-size:12px; }
.settings-tabs { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:18px; border-bottom:2px solid #1e293b; padding-bottom:4px; }
.settings-tab { background:none; border:none; color:var(--muted); cursor:pointer; padding:10px 16px; border-radius:8px 8px 0 0; font-size:14px; font-weight:600; transition:all .2s ease; }
.settings-tab:hover { background:#0b152c; color:var(--text); }
.settings-tab.active { background:#0f172a; color:#fbbf24; border-bottom:2px solid #fbbf24; }
.settings-subtab-content { display:none; }
.settings-subtab-content.active { display:block; }
.error-source { color:#f87171; font-weight:600; }
.sort-indicator { margin-left:4px; font-size:10px; color:var(--muted); }
.filter-bar select, .filter-bar input[type="search"] { width:100%; padding:8px; border-radius:8px; border:1px solid #1f2937; background:#0b152c; color:var(--text); }
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
      <a class="nav-link" data-view="launch" href="#launch">Launch Scan</a>
      <a class="nav-link" data-view="jobs" href="#jobs">Active Jobs</a>
      <a class="nav-link" data-view="workers" href="#workers">Workers</a>
      <a class="nav-link" data-view="queue" href="#queue">Queue</a>
      <a class="nav-link" data-view="reports" href="#reports">Reports</a>
      <a class="nav-link" data-view="logs" href="#logs">Logs</a>
      <a class="nav-link" data-view="monitors" href="#monitors">Monitors</a>
      <a class="nav-link" data-view="targets" href="#targets">Targets</a>
      <a class="nav-link" data-view="settings" href="#settings">Settings</a>
      <a class="nav-link" data-view="guide" href="#guide">User Guide</a>
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
        <div class="card" style="margin: 24px 0;">
          <h3>Workflow Pipeline</h3>
          <p class="muted">Visual representation of how data flows through the reconnaissance tools</p>
          <div id="workflow-diagram" style="margin-top: 20px;"></div>
        </div>
      </div>
    </section>

    <section class="module" data-view="launch">
      <div class="module-header"><h2>Launch Scan</h2></div>
      <div class="module-body">
        <div class="grid-two">
          <div class="card">
            <h3>Start New Recon</h3>
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
              <li>Enter a domain like <code>example.com</code> or use a wildcard suffix such as <code>example.*</code> to fan out across configured TLDs.</li>
              <li>Prefix with <code>*.</code> to scan a sub-scope, e.g., <code>*.apps.example.com</code>.</li>
              <li>Provide a wordlist path if you want ffuf vhost brute-forcing; leave it blank to skip ffuf automatically.</li>
              <li>Jobs queue safely when worker slots are full. Configure concurrency limits in Settings.</li>
              <li>Targets reuse the shared <code>state.json</code>, so reruns pick up where they left off.</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section class="module" data-view="jobs">
      <div class="module-header">
        <h2>Active Jobs</h2>
        <button class="btn secondary small" id="resume-all-btn" style="margin-left: auto;">Resume All Paused</button>
      </div>
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

    <section class="module" data-view="logs">
      <div class="module-header">
        <h2>System Logs</h2>
        <p class="muted">View all system logs with advanced filtering and sorting</p>
      </div>
      <div class="module-body">
        <div class="card" style="margin-bottom: 20px;">
          <h3>Filter & Search</h3>
          <div class="filter-bar" style="display: flex; gap: 12px; flex-wrap: wrap; align-items: end;">
            <label style="flex: 1; min-width: 200px;">
              Search logs
              <input type="search" id="log-search" placeholder="Search by text..." />
            </label>
            <label style="flex: 0 0 auto; min-width: 150px;">
              Source
              <select id="log-source-filter">
                <option value="">All sources</option>
              </select>
            </label>
            <label style="flex: 0 0 auto; min-width: 120px;">
              Level
              <select id="log-level-filter">
                <option value="">All levels</option>
                <option value="system">System</option>
                <option value="command">Command</option>
                <option value="error">Error</option>
                <option value="stderr">Stderr</option>
              </select>
            </label>
            <button id="log-clear-filters" class="btn small">Clear Filters</button>
          </div>
        </div>
        <div class="table-wrapper">
          <table class="targets-table" id="logs-table">
            <thead>
              <tr>
                <th data-sort-key="timestamp" data-sort-type="text">Timestamp <span class="sort-indicator"></span></th>
                <th data-sort-key="source" data-sort-type="text">Source <span class="sort-indicator"></span></th>
                <th data-sort-key="text" data-sort-type="text">Message <span class="sort-indicator"></span></th>
              </tr>
            </thead>
            <tbody id="logs-tbody">
              <tr><td colspan="3" class="muted">Loading logs...</td></tr>
            </tbody>
          </table>
        </div>
        <div class="table-pagination" id="logs-pagination"></div>
        <div style="margin-top: 16px; text-align: right;">
          <span class="muted" id="logs-count">0 logs</span>
        </div>
      </div>
    </section>

    <section class="module" data-view="monitors">
      <div class="module-header"><h2>Monitors</h2></div>
      <div class="module-body" id="monitors-body">
        <div class="grid-two">
          <div class="card">
            <h3>Add Monitor</h3>
            <form id="monitor-form">
              <label>Name (optional)
                <input id="monitor-name" type="text" name="name" placeholder="Marketing domains" />
              </label>
              <label>Source URL
                <input id="monitor-url" type="url" name="url" placeholder="https://example.com/domains.txt" required />
              </label>
              <label>Check interval (seconds)
                <input id="monitor-interval" type="number" name="interval" min="60" value="300" />
              </label>
              <button type="submit">Add Monitor</button>
            </form>
            <div class="status" id="monitor-status"></div>
          </div>
          <div class="card">
            <h3>How it works</h3>
            <ul class="tips">
              <li>Provide a newline-delimited list of targets (supports patterns such as <code>example.*</code> or <code>*.apps.example.com</code>).</li>
              <li>New entries trigger recon jobs automatically with your default settings.</li>
              <li>Monitors poll in the background; status updates appear below.</li>
            </ul>
          </div>
        </div>
        <div id="monitors-list" class="monitor-list section-placeholder">No monitors configured yet.</div>
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
        
        <div class="settings-tabs">
          <button class="settings-tab active" data-tab="general">General</button>
          <button class="settings-tab" data-tab="toggles">Tool Toggles</button>
          <button class="settings-tab" data-tab="concurrency">Concurrency</button>
          <button class="settings-tab" data-tab="templates">Tool Templates</button>
          <button class="settings-tab" data-tab="toolchain">Toolchain</button>
        </div>

        <form id="settings-form">
          <div class="settings-subtab-content active" data-tab-content="general">
            <div class="card">
              <h3>General Settings</h3>
              <label>Default wordlist
                <input id="settings-wordlist" type="text" name="default_wordlist" placeholder="./w.txt" />
              </label>
              <label>Default interval (seconds)
                <input id="settings-interval" type="number" name="default_interval" min="5" />
              </label>
              <label>Wildcard TLDs (comma-separated)
                <input id="settings-wildcard-tlds" type="text" name="wildcard_tlds" placeholder="com,net,org" />
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
            </div>
          </div>

          <div class="settings-subtab-content" data-tab-content="toggles">
            <div class="card">
              <h3>Tool Toggle Controls</h3>
              <h4>Subdomain Enumeration Tools</h4>
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
              <label class="checkbox">
                <input id="settings-enable-crtsh" type="checkbox" name="enable_crtsh" />
                Enable crt.sh
              </label>
              <label class="checkbox">
                <input id="settings-enable-github-subdomains" type="checkbox" name="enable_github_subdomains" />
                Enable GitHub Subdomains
              </label>
              <label class="checkbox">
                <input id="settings-enable-dnsx" type="checkbox" name="enable_dnsx" />
                Enable DNSx
              </label>
              <h4>URL Discovery Tools</h4>
              <label class="checkbox">
                <input id="settings-enable-waybackurls" type="checkbox" name="enable_waybackurls" />
                Enable Waybackurls
              </label>
              <label class="checkbox">
                <input id="settings-enable-gau" type="checkbox" name="enable_gau" />
                Enable GAU
              </label>
            </div>
          </div>

          <div class="settings-subtab-content" data-tab-content="concurrency">
            <div class="card">
              <h3>Concurrency & Rate Limiting</h3>
              <label>Max concurrent jobs
                <input id="settings-max-jobs" type="number" name="max_running_jobs" min="1" />
              </label>
              <label>Global rate limit (seconds between tool calls, 0 = disabled)
                <input id="settings-global-rate-limit" type="number" name="global_rate_limit" min="0" step="0.1" />
              </label>
              <h4>Per-Tool Thread Controls</h4>
              <label>Subfinder threads
                <input id="settings-subfinder-threads" type="number" name="subfinder_threads" min="1" />
              </label>
              <label>Assetfinder threads
                <input id="settings-assetfinder-threads" type="number" name="assetfinder_threads" min="1" />
              </label>
              <label>Findomain threads
                <input id="settings-findomain-threads" type="number" name="findomain_threads" min="1" />
              </label>
              <h4>Per-Tool Parallel Slots</h4>
              <label>FFUF parallel slots
                <input id="settings-ffuf" type="number" name="max_parallel_ffuf" min="1" />
              </label>
              <label>Nuclei parallel slots
                <input id="settings-nuclei" type="number" name="max_parallel_nuclei" min="1" />
              </label>
              <label>Nikto parallel slots
                <input id="settings-nikto" type="number" name="max_parallel_nikto" min="1" />
              </label>
              <label>Screenshot parallel slots
                <input id="settings-gowitness" type="number" name="max_parallel_gowitness" min="1" />
              </label>
              <label>DNSx parallel slots
                <input id="settings-dnsx" type="number" name="max_parallel_dnsx" min="1" />
              </label>
              <label>Waybackurls parallel slots
                <input id="settings-waybackurls" type="number" name="max_parallel_waybackurls" min="1" />
              </label>
              <label>GAU parallel slots
                <input id="settings-gau" type="number" name="max_parallel_gau" min="1" />
              </label>
            </div>
          </div>

          <div class="settings-subtab-content" data-tab-content="templates">
            <div class="card">
              <h3>Command Flag Templates</h3>
              <p class="muted">Customize flags for each tool with variables such as <code>$DOMAIN$</code>, <code>$WORDLIST$</code>, <code>$OUTPUT$</code>, <code>$OUTPUT_JSON$</code>, <code>$INPUT_FILE$</code>, <code>$TARGET_URL$</code>, <code>$SUBDOMAIN$</code>, <code>$TARGETS_FILE$</code>, <code>$OUTPUT_PREFIX$</code>, <code>$OUTPUT_DIR$</code>, <code>$DB_PATH$</code>, <code>$THREADS$</code>, and <code>$HOST_HEADER$</code>.</p>
              <div class="template-grid">
                <label>Amass flags
                  <textarea id="template-amass" class="template-input" placeholder="-passive"></textarea>
                </label>
                <label>Subfinder flags
                  <textarea id="template-subfinder" class="template-input" placeholder="-all"></textarea>
                </label>
                <label>Assetfinder flags
                  <textarea id="template-assetfinder" class="template-input" placeholder=""></textarea>
                </label>
                <label>Findomain flags
                  <textarea id="template-findomain" class="template-input" placeholder=""></textarea>
                </label>
                <label>Sublist3r flags
                  <textarea id="template-sublist3r" class="template-input" placeholder=""></textarea>
                </label>
                <label>crt.sh flags
                  <textarea id="template-crtsh" class="template-input" placeholder=""></textarea>
                </label>
                <label>GitHub Subdomains flags
                  <textarea id="template-github-subdomains" class="template-input" placeholder=""></textarea>
                </label>
                <label>DNSx flags
                  <textarea id="template-dnsx" class="template-input" placeholder="-silent"></textarea>
                </label>
                <label>FFUF flags
                  <textarea id="template-ffuf" class="template-input" placeholder="-rate 50"></textarea>
                </label>
                <label>HTTPX flags
                  <textarea id="template-httpx" class="template-input" placeholder="-silent"></textarea>
                </label>
                <label>Waybackurls flags
                  <textarea id="template-waybackurls" class="template-input" placeholder=""></textarea>
                </label>
                <label>GAU flags
                  <textarea id="template-gau" class="template-input" placeholder=""></textarea>
                </label>
                <label>Nuclei flags
                  <textarea id="template-nuclei" class="template-input" placeholder="-severity medium,high"></textarea>
                </label>
                <label>Nikto flags
                  <textarea id="template-nikto" class="template-input" placeholder=""></textarea>
                </label>
                <label>Screenshot flags (gowitness)
                  <textarea id="template-gowitness" class="template-input" placeholder=""></textarea>
                </label>
                <label>Nmap flags
                  <textarea id="template-nmap" class="template-input" placeholder=""></textarea>
                </label>
              </div>
              <p class="template-note">Tip: leave a field blank to use the built-in defaults. Need examples? Visit the User Guide from the sidebar.</p>
            </div>
          </div>

          <div class="settings-subtab-content" data-tab-content="toolchain">
            <div class="card">
              <h3>Detected Toolchain</h3>
              <p class="muted">Binary paths detected on your system for reconnaissance tools</p>
              <ul id="tools-list" class="tool-list">
                <li class="muted">Detecting tool paths…</li>
              </ul>
            </div>
          </div>

          <button type="submit">Save Settings</button>
          <div class="status" id="settings-status"></div>
        </form>
      </div>
    </section>

    <section class="module" data-view="guide">
      <div class="module-header"><h2>User Guide</h2></div>
      <div class="module-body">
        <div class="card">
          <h3>Launching targets</h3>
          <ul class="tips">
            <li>Enter a domain like <code>example.com</code> or use a wildcard suffix such as <code>example.*</code> to fan out across configured TLDs. Configure the allowed TLD list under <strong>Settings → Wildcard TLDs</strong>.</li>
            <li>Prefix with <code>*.</code> to scan a sub-scope, e.g., <code>*.apps.example.com</code> will recurse under that subdomain while still honoring wildcard TLD expansion when paired with <code>.*</code>.</li>
            <li>Provide a wordlist path if you want ffuf vhost brute-forcing; leave it blank to skip ffuf automatically.</li>
          </ul>
        </div>
        <div class="card">
          <h3>Templated tool flags</h3>
          <p>Each tool runs with built-in safe defaults. Any text you add in the Command templates settings will be appended to the underlying command <em>after</em> placeholder expansion. Leave a template blank to keep defaults.</p>
          <p>Supported placeholders are replaced per run: <code>$DOMAIN$</code>, <code>$SUBDOMAIN$</code>, <code>$WORDLIST$</code>, <code>$OUTPUT$</code>, <code>$OUTPUT_JSON$</code>, <code>$OUTPUT_PREFIX$</code>, <code>$INPUT_FILE$</code>, <code>$TARGET_URL$</code>, <code>$TARGETS_FILE$</code>, <code>$OUTPUT_DIR$</code>, <code>$DB_PATH$</code>, <code>$THREADS$</code>, and <code>$HOST_HEADER$</code>.</p>
          <div class="table-wrapper">
            <table class="monitor-entry-table">
              <thead><tr><th>Tool</th><th>Context variables you can use</th></tr></thead>
              <tbody>
                <tr><td>Amass</td><td><code>$DOMAIN$</code>, <code>$OUTPUT_PREFIX$</code>, <code>$OUTPUT_JSON$</code></td></tr>
                <tr><td>Subfinder</td><td><code>$DOMAIN$</code>, <code>$OUTPUT$</code>, <code>$THREADS$</code></td></tr>
                <tr><td>Assetfinder</td><td><code>$DOMAIN$</code>, <code>$OUTPUT$</code>, <code>$THREADS$</code></td></tr>
                <tr><td>Findomain</td><td><code>$DOMAIN$</code>, <code>$OUTPUT$</code>, <code>$THREADS$</code></td></tr>
                <tr><td>Sublist3r</td><td><code>$DOMAIN$</code>, <code>$OUTPUT$</code></td></tr>
                <tr><td>ffuf</td><td><code>$DOMAIN$</code>, <code>$WORDLIST$</code>, <code>$OUTPUT$</code>, <code>$TARGET_URL$</code>, <code>$HOST_HEADER$</code></td></tr>
                <tr><td>httpx</td><td><code>$DOMAIN$</code>, <code>$INPUT_FILE$</code>, <code>$OUTPUT$</code></td></tr>
                <tr><td>nuclei</td><td><code>$DOMAIN$</code>, <code>$INPUT_FILE$</code>, <code>$OUTPUT$</code></td></tr>
                <tr><td>Nikto</td><td><code>$DOMAIN$</code>, <code>$SUBDOMAIN$</code>, <code>$TARGET_URL$</code>, <code>$OUTPUT$</code></td></tr>
                <tr><td>Gowitness (screenshots)</td><td><code>$DOMAIN$</code>, <code>$TARGETS_FILE$</code>, <code>$OUTPUT_DIR$</code>, <code>$DB_PATH$</code></td></tr>
              </tbody>
            </table>
          </div>
          <p class="template-note">Examples: add <code>-passive</code> to Amass, <code>-rate 50</code> to ffuf, or <code>-severity medium,high,critical</code> to nuclei. Use <code>$OUTPUT$</code> to change where a tool writes extra logs.</p>
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
const SEVERITY_SCALE = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE'];
const SEVERITY_RANK = SEVERITY_SCALE.reduce((acc, label, idx) => {
  acc[label] = idx;
  return acc;
}, {});
function setView(target) {
  const next = target || 'overview';
  viewSections.forEach(section => section.classList.toggle('active', section.dataset.view === next));
  navLinks.forEach(link => link.classList.toggle('active', link.dataset.view === next));
  history.replaceState(null, '', `#${next}`);
  
  // Update logs when switching to logs view
  if (next === 'logs') {
    updateLogsView();
  }
}
navLinks.forEach(link => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    setView(link.dataset.view);
  });
});
const initialView = location.hash ? location.hash.substring(1) : 'overview';
setView(initialView || 'overview');

// Settings tabs handler
const settingsTabs = document.querySelectorAll('.settings-tab');
const settingsTabContents = document.querySelectorAll('.settings-subtab-content');
function setSettingsTab(tabName) {
  settingsTabs.forEach(tab => tab.classList.toggle('active', tab.dataset.tab === tabName));
  settingsTabContents.forEach(content => content.classList.toggle('active', content.dataset.tabContent === tabName));
}
settingsTabs.forEach(tab => {
  tab.addEventListener('click', () => setSettingsTab(tab.dataset.tab));
});

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
const monitorsList = document.getElementById('monitors-list');
const detailOverlay = document.getElementById('detail-overlay');
const detailContent = document.getElementById('detail-content');
const detailClose = document.getElementById('detail-close');
let latestTargetsData = {};
let latestConfig = {};
const historyCache = {};
const commandHistoryCache = {};
let selectedReportDomain = null;
let latestRunningJobs = [];
let latestQueuedJobs = [];
const settingsForm = document.getElementById('settings-form');
const settingsWordlist = document.getElementById('settings-wordlist');
const settingsInterval = document.getElementById('settings-interval');
const settingsWildcardTlds = document.getElementById('settings-wildcard-tlds');
const settingsSkipNikto = document.getElementById('settings-skip-nikto');
const settingsEnableScreenshots = document.getElementById('settings-enable-screenshots');
const settingsEnableAmass = document.getElementById('settings-enable-amass');
const settingsAmassTimeout = document.getElementById('settings-amass-timeout');
const settingsEnableSubfinder = document.getElementById('settings-enable-subfinder');
const settingsEnableAssetfinder = document.getElementById('settings-enable-assetfinder');
const settingsEnableFindomain = document.getElementById('settings-enable-findomain');
const settingsEnableSublist3r = document.getElementById('settings-enable-sublist3r');
const settingsEnableCrtsh = document.getElementById('settings-enable-crtsh');
const settingsEnableGithubSubdomains = document.getElementById('settings-enable-github-subdomains');
const settingsEnableDnsx = document.getElementById('settings-enable-dnsx');
const settingsEnableWaybackurls = document.getElementById('settings-enable-waybackurls');
const settingsEnableGau = document.getElementById('settings-enable-gau');
const settingsSubfinderThreads = document.getElementById('settings-subfinder-threads');
const settingsAssetfinderThreads = document.getElementById('settings-assetfinder-threads');
const settingsFindomainThreads = document.getElementById('settings-findomain-threads');
const settingsGlobalRateLimit = document.getElementById('settings-global-rate-limit');
const settingsMaxJobs = document.getElementById('settings-max-jobs');
const settingsFFUF = document.getElementById('settings-ffuf');
const settingsNuclei = document.getElementById('settings-nuclei');
const settingsNikto = document.getElementById('settings-nikto');
const settingsGowitness = document.getElementById('settings-gowitness');
const settingsDnsx = document.getElementById('settings-dnsx');
const settingsWaybackurls = document.getElementById('settings-waybackurls');
const settingsGau = document.getElementById('settings-gau');
const settingsStatus = document.getElementById('settings-status');
const settingsSummary = document.getElementById('settings-summary');
const templateInputs = {
  amass: document.getElementById('template-amass'),
  subfinder: document.getElementById('template-subfinder'),
  assetfinder: document.getElementById('template-assetfinder'),
  findomain: document.getElementById('template-findomain'),
  sublist3r: document.getElementById('template-sublist3r'),
  crtsh: document.getElementById('template-crtsh'),
  'github-subdomains': document.getElementById('template-github-subdomains'),
  dnsx: document.getElementById('template-dnsx'),
  ffuf: document.getElementById('template-ffuf'),
  httpx: document.getElementById('template-httpx'),
  waybackurls: document.getElementById('template-waybackurls'),
  gau: document.getElementById('template-gau'),
  nuclei: document.getElementById('template-nuclei'),
  nikto: document.getElementById('template-nikto'),
  gowitness: document.getElementById('template-gowitness'),
  nmap: document.getElementById('template-nmap'),
};
const monitorForm = document.getElementById('monitor-form');
const monitorName = document.getElementById('monitor-name');
const monitorUrl = document.getElementById('monitor-url');
const monitorInterval = document.getElementById('monitor-interval');
const monitorStatus = document.getElementById('monitor-status');
const statActive = document.getElementById('stat-active');
const statQueued = document.getElementById('stat-queued');
const statTargets = document.getElementById('stat-targets');
const statSubs = document.getElementById('stat-subdomains');
let launchFormDirty = false;
let settingsFormDirty = false;
let monitorsData = [];
let allLogs = [];
let filteredLogs = [];
const logsTable = document.getElementById('logs-table');
const logsTbody = document.getElementById('logs-tbody');
const logsPagination = document.getElementById('logs-pagination');
const logsCount = document.getElementById('logs-count');
const logSearch = document.getElementById('log-search');
const logSourceFilter = document.getElementById('log-source-filter');
const logLevelFilter = document.getElementById('log-level-filter');
const logClearFilters = document.getElementById('log-clear-filters');
const STEP_SEQUENCE = [
  { flag: 'amass_done', label: 'Amass' },
  { flag: 'subfinder_done', label: 'Subfinder' },
  { flag: 'assetfinder_done', label: 'Assetfinder' },
  { flag: 'findomain_done', label: 'Findomain' },
  { flag: 'sublist3r_done', label: 'Sublist3r' },
  { flag: 'crtsh_done', label: 'crt.sh' },
  { flag: 'github_subdomains_done', label: 'GitHub Subdomains' },
  { flag: 'dnsx_done', label: 'DNSx' },
  { flag: 'ffuf_done', label: 'ffuf' },
  { flag: 'httpx_done', label: 'httpx' },
  { flag: 'waybackurls_done', label: 'Waybackurls' },
  { flag: 'gau_done', label: 'GAU' },
  { flag: 'screenshots_done', label: 'Screenshots', skipWhen: () => latestConfig.enable_screenshots === false },
  { flag: 'nmap_done', label: 'nmap' },
  { flag: 'nuclei_done', label: 'Nuclei' },
  { flag: 'nikto_done', label: 'Nikto', skipWhen: (info) => shouldSkipNikto(info) },
];
const DEFAULT_PAGE_SIZE = 50;

const STATUS_LABELS = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed w/ warnings',
  failed: 'Failed',
  error: 'Error',
  dispatched: 'Dispatched',
  skipped: 'Skipped',
  pending: 'Pending',
  paused: 'Paused',
  pausing: 'Pausing'
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
    case 'dispatched':
      return 'status-running';
    case 'paused':
    case 'pausing':
      return 'status-paused';
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

function normalizeSeverity(value, fallback = 'INFO') {
  if (value === undefined || value === null) return fallback;
  const text = String(value).trim().toUpperCase();
  if (!text) return fallback;
  if (SEVERITY_RANK[text] === undefined) return fallback;
  return text;
}

function severityRank(value) {
  const key = value || 'INFO';
  if (SEVERITY_RANK[key] === undefined) return SEVERITY_RANK.INFO;
  return SEVERITY_RANK[key];
}

function severityIsHigher(candidate, current) {
  return severityRank(candidate) < severityRank(current);
}

function formatSeverityLabel(value) {
  if (!value || value === 'NONE') return 'None';
  return value.charAt(0) + value.slice(1).toLowerCase();
}

function getPaginationState(table) {
  return table && table._paginationState;
}

function initPagination(table, pagerEl, pageSize = DEFAULT_PAGE_SIZE) {
  if (!table || !pagerEl) return;
  const state = {
    table,
    pagerEl,
    pageSize: Math.max(1, pageSize || DEFAULT_PAGE_SIZE),
    currentPage: 1,
    totalPages: 1,
  };
  if (pagerEl._paginationHandler) {
    pagerEl.removeEventListener('click', pagerEl._paginationHandler);
  }
  const handleClick = (event) => {
    const btn = event.target.closest('[data-page-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-page-action');
    if (action === 'prev') {
      state.currentPage = Math.max(1, state.currentPage - 1);
    } else if (action === 'next') {
      state.currentPage = Math.min(state.totalPages, state.currentPage + 1);
    } else if (action === 'first') {
      state.currentPage = 1;
    } else if (action === 'last') {
      state.currentPage = state.totalPages;
    }
    refreshPagination(table);
  };
  pagerEl._paginationHandler = handleClick;
  pagerEl.addEventListener('click', handleClick);
  table._paginationState = state;
  refreshPagination(table);
}

function refreshPagination(table) {
  const state = getPaginationState(table);
  if (!state) return;
  const rows = Array.from(table.tBodies[0] ? table.tBodies[0].rows : []);
  let visibleCount = 0;
  rows.forEach(row => {
    if (row.dataset.filterHidden === undefined) {
      row.dataset.filterHidden = 'false';
    }
    if (row.dataset.filterHidden === 'true') {
      row.style.display = 'none';
    }
  });
  rows.forEach(row => {
    if (row.dataset.filterHidden === 'true') return;
    visibleCount += 1;
  });
  state.totalPages = Math.max(1, Math.ceil(visibleCount / state.pageSize));
  if (state.currentPage > state.totalPages) {
    state.currentPage = state.totalPages;
  }
  let visibleIndex = 0;
  const start = (state.currentPage - 1) * state.pageSize;
  const end = start + state.pageSize;
  rows.forEach(row => {
    if (row.dataset.filterHidden === 'true') {
      row.style.display = 'none';
      return;
    }
    const inPage = visibleIndex >= start && visibleIndex < end;
    row.style.display = inPage ? '' : 'none';
    visibleIndex += 1;
  });
  const pagerEl = state.pagerEl;
  if (!pagerEl) return;
  if (state.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  pagerEl.innerHTML = `
    <span class="page-info">${visibleCount} rows</span>
    <button data-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

function makeSortable(table) {
  if (!table) return;
  const headers = table.querySelectorAll('th[data-sort-key]');
  headers.forEach((th, index) => {
    th.addEventListener('click', () => {
      const nextDir = th.dataset.sortDir === 'asc' ? 'desc' : 'asc';
      headers.forEach(header => delete header.dataset.sortDir);
      th.dataset.sortDir = nextDir;
      const type = th.dataset.sortType || 'text';
      const multiplier = nextDir === 'asc' ? 1 : -1;
      const rows = Array.from(table.tBodies[0].rows);
      rows.sort((a, b) => {
        const aVal = getCellSortValue(a.cells[index], type);
        const bVal = getCellSortValue(b.cells[index], type);
        if (aVal < bVal) return -1 * multiplier;
        if (aVal > bVal) return 1 * multiplier;
        return 0;
      });
      rows.forEach(row => table.tBodies[0].appendChild(row));
      refreshPagination(table);
    });
  });
}

function getCellSortValue(cell, type) {
  if (!cell) return '';
  const raw = cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent.trim();
  if (type === 'number') {
    const num = parseFloat(raw);
    return isNaN(num) ? 0 : num;
  }
  return raw.toLowerCase();
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

function renderJobControls(job) {
  if (!job || !job.domain) return '';
  if (job.status === 'running') {
    return `<div class="job-actions"><button class="btn secondary small" data-pause-job="${escapeHtml(job.domain)}">Pause</button></div>`;
  }
  if (job.status === 'paused' || job.status === 'pausing') {
    return `<div class="job-actions"><button class="btn small" data-resume-job="${escapeHtml(job.domain)}">Resume</button></div>`;
  }
  return '';
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
        ${renderJobControls(job)}
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
  
  // Add export buttons at the top
  const exportButtons = `
    <div class="export-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
      <a class="btn secondary small" href="/api/export/state" target="_blank">Export JSON</a>
      <a class="btn secondary small" href="/api/export/csv" target="_blank">Export CSV</a>
    </div>
  `;
  
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
          <td><a href="/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(sub)}" class="link-btn">${escapeHtml(sub)}</a></td>
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
      <span class="badge">crt.sh: ${flags.crtsh_done ? '✅' : '⏳'}</span>
      <span class="badge">GitHub: ${flags.github_subdomains_done ? '✅' : '⏳'}</span>
      <span class="badge">DNSx: ${flags.dnsx_done ? '✅' : '⏳'}</span>
      <span class="badge">ffuf: ${flags.ffuf_done ? '✅' : '⏳'}</span>
      <span class="badge">httpx: ${flags.httpx_done ? '✅' : '⏳'}</span>
      <span class="badge">Wayback: ${flags.waybackurls_done ? '✅' : '⏳'}</span>
      <span class="badge">GAU: ${flags.gau_done ? '✅' : '⏳'}</span>
      <span class="badge">Screenshots: ${flags.screenshots_done ? '✅' : '⏳'}</span>
      <span class="badge">nmap: ${flags.nmap_done ? '✅' : '⏳'}</span>
      <span class="badge">nuclei: ${flags.nuclei_done ? '✅' : '⏳'}</span>
      <span class="badge">nikto: ${flags.nikto_done ? '✅' : '⏳'}</span>
    `;
    const tableId = `targets-table-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const paginationId = `targets-pagination-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const table = rows ? `
      <div class="table-wrapper">
        <table class="targets-table" id="${tableId}">
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
      <div class="table-pagination" id="${paginationId}"></div>
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
  targetsList.innerHTML = exportButtons + cards.join('');
  
  // Initialize pagination for each target's table
  entries.forEach(([domain]) => {
    const tableId = `targets-table-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const paginationId = `targets-pagination-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const table = document.getElementById(tableId);
    const pagerEl = document.getElementById(paginationId);
    if (table && pagerEl) {
      initPagination(table, pagerEl, DEFAULT_PAGE_SIZE);
    }
  });
}

function renderWorkflowDiagram() {
  const diagram = document.getElementById('workflow-diagram');
  if (!diagram) return;
  
  const html = `
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 1: Subdomain Enumeration</div>
      <div class="workflow-tools">
        <span class="workflow-tool enumeration">Amass</span>
        <span class="workflow-tool enumeration">Subfinder</span>
        <span class="workflow-tool enumeration">Assetfinder</span>
        <span class="workflow-tool enumeration">Findomain</span>
        <span class="workflow-tool enumeration">Sublist3r</span>
        <span class="workflow-tool enumeration">crt.sh</span>
        <span class="workflow-tool enumeration">GitHub-Subdomains</span>
        <span class="workflow-tool enumeration">DNSx</span>
      </div>
      <div class="workflow-description">Passive and active subdomain discovery using multiple data sources</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 2: Subdomain Brute Force</div>
      <div class="workflow-tools">
        <span class="workflow-tool brute-force">FFUF</span>
      </div>
      <div class="workflow-description">DNS brute-forcing using wordlist to discover additional subdomains</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 3: HTTP Probing</div>
      <div class="workflow-tools">
        <span class="workflow-tool probing">HTTPX</span>
      </div>
      <div class="workflow-description">Probe subdomains for live HTTP services and gather response metadata</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 4: URL Discovery</div>
      <div class="workflow-tools">
        <span class="workflow-tool url-discovery">Waybackurls</span>
        <span class="workflow-tool url-discovery">GAU</span>
      </div>
      <div class="workflow-description">Discover historical URLs and endpoints from web archives and other sources</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 5: Visual Capture</div>
      <div class="workflow-tools">
        <span class="workflow-tool capture">Gowitness</span>
      </div>
      <div class="workflow-description">Capture screenshots of live web applications for visual analysis</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 6: Port Scanning</div>
      <div class="workflow-tools">
        <span class="workflow-tool scanning">Nmap</span>
      </div>
      <div class="workflow-description">Port and service detection on hosts with live HTTP services</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 7: Vulnerability Scanning</div>
      <div class="workflow-tools">
        <span class="workflow-tool scanning">Nuclei</span>
        <span class="workflow-tool scanning">Nikto</span>
      </div>
      <div class="workflow-description">Automated vulnerability scanning and security checks on discovered targets</div>
    </div>
  `;
  
  diagram.innerHTML = html;
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
    const limit = info.limit;
    const active = info.active || 0;
    
    // Handle tools with and without concurrency gates
    if (limit == null) {
      // Tool without gate - just show as available
      return `
        <div class="worker-card">
          <h3>${escapeHtml(name)}</h3>
          <div class="metric">Available</div>
          <div class="muted">no concurrency limit</div>
        </div>
      `;
    } else {
      // Tool with gate - show active/limit
      const pct = limit ? Math.min(100, Math.round(active / limit * 100)) : 0;
      return `
        <div class="worker-card">
          <h3>${escapeHtml(name)}</h3>
          <div class="metric">${active}/${limit}</div>
          <div class="muted">slots in use</div>
          <div class="worker-progress">${renderProgress(pct, active >= limit ? 'running' : 'completed')}</div>
        </div>
      `;
    }
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
  
  // Metadata section
  const metadataHtml = `
    <div class="detail-section">
      <h4>Metadata</h4>
      <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px;">
        <div>
          <strong>Parent Domain:</strong><br>
          <span class="badge">${escapeHtml(domain)}</span>
        </div>
        <div>
          <strong>Discovery Sources:</strong><br>
          ${sources.length ? sources.map(s => `<span class="badge">${escapeHtml(s)}</span>`).join(' ') : '<span class="muted">Unknown</span>'}
        </div>
      </div>
    </div>
  `;
  
  // HTTP section - full details
  const httpHtml = `
    <div class="detail-section">
      <h4>HTTP Response</h4>
      ${Object.keys(httpx).length ? `
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px;">
          <div><strong>URL:</strong><br>${escapeHtml(httpx.url || '—')}</div>
          <div><strong>Status Code:</strong><br>${httpx.status_code || '—'}</div>
          <div><strong>Title:</strong><br>${escapeHtml(httpx.title || '—')}</div>
          <div><strong>Server:</strong><br>${escapeHtml(httpx.webserver || httpx.server || '—')}</div>
          <div><strong>Content-Type:</strong><br>${escapeHtml(httpx.content_type || '—')}</div>
          <div><strong>Tech Stack:</strong><br>${escapeHtml((httpx.tech || httpx.technologies || []).join(', ') || '—')}</div>
        </div>
      ` : '<p class="muted">No HTTP data available</p>'}
    </div>
  `;
  
  // Screenshot section - inline display
  const screenshotHtml = `
    <div class="detail-section">
      <h4>Screenshot</h4>
      ${screenshot.path ? `
        <div style="margin-top:8px;">
          <img src="/screenshots/${escapeHtml(screenshot.path)}" style="max-width:100%; border-radius:8px; border:1px solid #1f2937;" alt="Screenshot of ${escapeHtml(sub)}" />
          ${screenshot.captured_at ? `<p class="muted" style="margin-top:8px;">Captured ${fmtTime(screenshot.captured_at)}</p>` : ''}
        </div>
      ` : '<p class="muted">No screenshot available</p>'}
    </div>
  `;
  
  // URLs section - placeholder for future implementation
  const urlsHtml = `
    <div class="detail-section">
      <h4>Discovered URLs</h4>
      <p class="muted">URL discovery from Waybackurls and GAU is performed at the domain level. Per-subdomain URL tracking coming soon.</p>
    </div>
  `;
  
  // Nuclei section - detailed findings table
  let nucleiHtml = '<div class="detail-section"><h4>Nuclei Findings</h4>';
  if (nuclei.length) {
    nucleiHtml += `
      <div class="table-wrapper">
        <table class="targets-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Template</th>
              <th>Name</th>
              <th>Matched At</th>
            </tr>
          </thead>
          <tbody>
            ${nuclei.map(finding => {
              const severity = normalizeSeverity(finding.severity, 'INFO');
              const templateId = finding.template_id || finding['template-id'] || 'N/A';
              const name = finding.name || '';
              const matchedAt = finding.matched_at || finding['matched-at'] || finding.url || '';
              return `
                <tr>
                  <td><span class="severity-pill ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                  <td>${escapeHtml(templateId)}</td>
                  <td>${escapeHtml(name)}</td>
                  <td>${escapeHtml(matchedAt)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  } else {
    nucleiHtml += '<p class="muted">No Nuclei findings</p>';
  }
  nucleiHtml += '</div>';
  
  // Nikto section - detailed findings table
  let niktoHtml = '<div class="detail-section"><h4>Nikto Findings</h4>';
  if (nikto.length) {
    niktoHtml += `
      <div class="table-wrapper">
        <table class="targets-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Message</th>
              <th>Reference</th>
            </tr>
          </thead>
          <tbody>
            ${nikto.map(finding => {
              const severity = normalizeSeverity(finding.severity || finding.risk, 'INFO');
              const message = finding.msg || finding.description || finding.raw || '';
              const reference = finding.uri || (finding.osvdb ? `OSVDB-${finding.osvdb}` : '') || '—';
              return `
                <tr>
                  <td><span class="severity-pill ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                  <td>${escapeHtml(message)}</td>
                  <td>${escapeHtml(reference)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  } else {
    niktoHtml += '<p class="muted">No Nikto findings</p>';
  }
  niktoHtml += '</div>';
  
  // Timeline section
  const timelineHtml = `
    <div class="detail-section">
      <h4>Timeline (Filtered Events)</h4>
      <div class="timeline">
        ${filteredHistory.length ? filteredHistory.map(evt => `
          <div class="timeline-entry">
            <div class="meta">${escapeHtml(evt.ts || '')} — ${escapeHtml(evt.source || '')}</div>
            <div>${escapeHtml(evt.text || '')}</div>
          </div>
        `).join('') : '<p class="muted">No history for this subdomain yet.</p>'}
      </div>
    </div>
  `;
  
  return `
    <h3>${escapeHtml(sub)} <span class="badge">${escapeHtml(domain)}</span></h3>
    ${metadataHtml}
    ${httpHtml}
    ${screenshotHtml}
    ${urlsHtml}
    ${nucleiHtml}
    ${niktoHtml}
    ${timelineHtml}
  `;
}

function computeReportStats(info) {
  const subs = Object.values(info && info.subdomains || {});
  let httpCount = 0;
  let nucleiCount = 0;
  let niktoCount = 0;
  let screenshotCount = 0;
  let maxSeverity = 'NONE';
  let maxNucleiSeverity = 'NONE';
  let maxNiktoSeverity = 'NONE';
  let processedSubdomains = 0;
  let pendingSubdomains = 0;
  let pendingHttp = 0;
  let pendingScreenshots = 0;
  let pendingNuclei = 0;
  let pendingNikto = 0;
  const cfg = latestConfig || {};
  const enableScreenshots = cfg.enable_screenshots !== false;
  const skipNiktoDefault = !!cfg.skip_nikto_by_default;
  const options = info && info.options || {};
  const skipNikto = options.skip_nikto !== undefined ? !!options.skip_nikto : skipNiktoDefault;
  subs.forEach(entry => {
    const scans = entry && entry.scans || {};
    const httpDone = !!(entry && entry.httpx) || !!scans.httpx;
    const screenshotDone = !enableScreenshots || !!(entry && entry.screenshot) || !!scans.screenshots;
    const nucleiDone = !!scans.nuclei;
    const niktoRequired = !skipNikto;
    const niktoDone = !niktoRequired || !!scans.nikto;
    if (entry && entry.httpx) httpCount += 1;
    nucleiCount += Array.isArray(entry && entry.nuclei) ? entry.nuclei.length : 0;
    niktoCount += Array.isArray(entry && entry.nikto) ? entry.nikto.length : 0;
    if (entry && entry.screenshot) screenshotCount += 1;
    if (!httpDone) pendingHttp += 1;
    if (enableScreenshots && !screenshotDone) pendingScreenshots += 1;
    if (!nucleiDone) pendingNuclei += 1;
    if (niktoRequired && !niktoDone) pendingNikto += 1;
    if (httpDone && screenshotDone && nucleiDone && niktoDone) {
      processedSubdomains += 1;
    } else {
      pendingSubdomains += 1;
    }
    (entry && entry.nuclei || []).forEach(finding => {
      const sev = normalizeSeverity(finding && finding.severity, 'INFO');
      if (severityIsHigher(sev, maxSeverity)) {
        maxSeverity = sev;
      }
      if (severityIsHigher(sev, maxNucleiSeverity)) {
        maxNucleiSeverity = sev;
      }
    });
    (entry && entry.nikto || []).forEach(finding => {
      const sev = normalizeSeverity(finding && finding.severity, 'INFO');
      if (severityIsHigher(sev, maxSeverity)) {
        maxSeverity = sev;
      }
      if (severityIsHigher(sev, maxNiktoSeverity)) {
        maxNiktoSeverity = sev;
      }
    });
  });
  return {
    subdomains: subs.length,
    http: httpCount,
    nuclei: nucleiCount,
    nikto: niktoCount,
    screenshots: screenshotCount,
    maxSeverity,
    maxNucleiSeverity,
    maxNiktoSeverity,
    processed_subdomains: processedSubdomains,
    pending_subdomains: pendingSubdomains,
    pending_http: pendingHttp,
    pending_screenshots: pendingScreenshots,
    pending_nuclei: pendingNuclei,
    pending_nikto: pendingNikto,
    progress: subs.length ? Math.min(100, Math.round((processedSubdomains / subs.length) * 100)) : (info && info.flags && Object.values(info.flags).every(Boolean) ? 100 : 0),
  };
}

function hasActiveJob(domain) {
  if (!domain) return false;
  return latestRunningJobs.some(job => job.domain === domain) ||
    latestQueuedJobs.some(job => job.domain === domain);
}

function renderReports(targets) {
  latestTargetsData = targets || {};
  const entries = Object.entries(latestTargetsData);
  if (!entries.length) {
    reportsBody.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    selectedReportDomain = null;
    return;
  }
  entries.sort((a, b) => {
    const aInfo = a[1] || {};
    const bInfo = b[1] || {};
    if (!!aInfo.pending !== !!bInfo.pending) {
      return aInfo.pending ? -1 : 1;
    }
    const aSubs = Object.keys(aInfo.subdomains || {}).length;
    const bSubs = Object.keys(bInfo.subdomains || {}).length;
    if (aSubs !== bSubs) return bSubs - aSubs;
    return a[0].localeCompare(b[0]);
  });
  if (!selectedReportDomain || !latestTargetsData[selectedReportDomain]) {
    selectedReportDomain = entries[0][0];
  }
  const cards = entries.map(([domain, info]) => {
    const stats = computeReportStats(info || {});
    const badge = info && info.pending
      ? '<span class="report-badge pending">Pending</span>'
      : '<span class="report-badge complete">Complete</span>';
    const severity = stats.maxSeverity || 'NONE';
    const severityText = formatSeverityLabel(severity);
    const severityFlag = `<span class="severity-flag ${escapeHtml(severity)}">Max: ${escapeHtml(severityText)}</span>`;
    return `
      <div class="report-nav-card" data-report-domain="${escapeHtml(domain)}">
        <div class="domain-row">
          <div class="domain">${escapeHtml(domain)}</div>
          ${severityFlag}
        </div>
        <div class="meta">
          <span>Subs <span class="stat">${stats.subdomains}</span></span>
          <span>HTTP <span class="stat">${stats.http}</span></span>
          <span>Findings <span class="stat">${stats.nuclei + stats.nikto}</span></span>
        </div>
        ${badge}
      </div>
    `;
  }).join('');
  reportsBody.innerHTML = `
    <div class="export-actions">
      <a class="btn" href="/api/export/state" target="_blank">Download JSON</a>
      <a class="btn secondary" href="/api/export/csv" target="_blank">Download CSV</a>
    </div>
    <div class="reports-layout">
      <div class="reports-nav" id="reports-nav">${cards}</div>
      <div class="report-detail" id="report-detail"></div>
    </div>
  `;
  renderReportDetail(selectedReportDomain);
}

function shouldSkipNikto(info) {
  const options = info && info.options || {};
  if (options.skip_nikto !== undefined) {
    return !!options.skip_nikto;
  }
  return !!(latestConfig && latestConfig.skip_nikto_by_default);
}

function renderCollapsibleSection(id, title, body, open = false) {
  return `
    <div class="collapsible ${open ? 'open' : ''}" data-collapsible="${escapeHtml(id)}">
      <button class="collapsible-header" type="button">
        <span>${escapeHtml(title)}</span>
        <span class="chevron">▶</span>
      </button>
      <div class="collapsible-body">
        ${body}
      </div>
    </div>
  `;
}

function buildStepChecklist(info) {
  const flags = info && info.flags ? info.flags : {};
  return STEP_SEQUENCE.map(step => {
    const skipped = step.skipWhen ? step.skipWhen(info) : false;
    const status = skipped ? 'skipped' : (flags[step.flag] ? 'completed' : 'pending');
    return `
      <div class="step">
        <span>${escapeHtml(step.label)}</span>
        <span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span>
      </div>
    `;
  }).join('');
}

function monitorStatusClass(value) {
  switch (value) {
    case 'ok':
      return 'status-completed';
    case 'error':
      return 'status-error';
    case 'pending':
      return 'status-running';
    default:
      return 'status-skipped';
  }
}

function monitorStatusLabel(value) {
  if (!value) return 'Unknown';
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderMonitorEntries(entries) {
  if (!entries || !entries.length) {
    return '<tr><td colspan="5">No entries observed yet.</td></tr>';
  }
  return entries.map(entry => {
    const targets = (entry.dispatched_targets || []).join(', ') || '—';
    const status = entry.status || 'pending';
    return `
      <tr>
        <td>${escapeHtml(entry.value || '')}</td>
        <td>${escapeHtml(targets)}</td>
        <td><span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span></td>
        <td>${fmtTime(entry.last_seen)}</td>
        <td>${escapeHtml(entry.dispatch_message || '—')}</td>
      </tr>
    `;
  }).join('');
}

function renderMonitors(monitors) {
  if (!monitorsList) return;
  monitorsData = Array.isArray(monitors) ? monitors : [];
  if (!monitorsData.length) {
    monitorsList.innerHTML = '<div class="section-placeholder">No monitors configured yet.</div>';
    return;
  }
  const cards = monitorsData.map(monitor => {
    const entries = Array.isArray(monitor.entries) ? monitor.entries : [];
    const entryRows = renderMonitorEntries(entries);
    const truncatedNote = monitor.entries_truncated ? '<p class="monitor-entry-note">Showing most recent entries.</p>' : '';
    const statusClassName = monitorStatusClass(monitor.last_status);
    const statusText = monitorStatusLabel(monitor.last_status);
    const errorMessage = monitor.last_error ? `<p class="status error">${escapeHtml(monitor.last_error)}</p>` : '';
    const nextCheck = monitor.next_check ? fmtTime(monitor.next_check) : 'Scheduled';
    return `
      <div class="monitor-card" data-monitor-id="${escapeHtml(monitor.id || '')}">
        <div class="monitor-header">
          <div>
            <h3>${escapeHtml(monitor.name || monitor.url || 'Monitor')}</h3>
            <div class="monitor-meta">
              <a href="${escapeHtml(monitor.url || '#')}" target="_blank">${escapeHtml(monitor.url || '')}</a><br>
              Interval: ${escapeHtml(monitor.interval || 0)}s · Last check: ${fmtTime(monitor.last_checked)} · Next check: ${nextCheck}
            </div>
          </div>
          <div class="monitor-actions">
            <span class="status-pill ${statusClassName}">${statusText}</span>
            <button class="btn secondary small" data-remove-monitor="${escapeHtml(monitor.id || '')}">Remove</button>
          </div>
        </div>
        <div class="monitor-stats">
          <span>Entries: ${escapeHtml(monitor.entry_count || 0)}</span>
          <span>Pending: ${escapeHtml(monitor.pending_entries || 0)}</span>
          <span>Last new: ${escapeHtml(monitor.last_new_entries || 0)}</span>
          <span>Last dispatched: ${escapeHtml(monitor.last_dispatch_count || 0)}</span>
        </div>
        ${errorMessage}
        <div class="table-wrapper">
          <table class="monitor-entry-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Targets</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>${entryRows}</tbody>
          </table>
        </div>
        ${truncatedNote}
      </div>
    `;
  }).join('');
  monitorsList.innerHTML = cards;
}

async function deleteMonitor(id, button) {
  if (!id) return;
  const original = button ? button.textContent : null;
  if (button) {
    button.disabled = true;
    button.textContent = 'Removing…';
  }
  try {
    const resp = await fetch('/api/monitors/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const data = await resp.json();
    if (!data.success) {
      throw new Error(data.message || 'Failed to remove monitor.');
    }
    if (monitorStatus) {
      monitorStatus.textContent = data.message || 'Monitor removed.';
      monitorStatus.className = 'status success';
    }
    fetchState();
  } catch (err) {
    if (monitorStatus) {
      monitorStatus.textContent = err.message || 'Failed to remove monitor.';
      monitorStatus.className = 'status error';
    }
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

function updateReportNavSelection() {
  const nav = document.getElementById('reports-nav');
  if (!nav) return;
  nav.querySelectorAll('.report-nav-card').forEach(card => {
    card.classList.toggle('active', card.dataset.reportDomain === selectedReportDomain);
  });
}

function buildSubdomainRows(info) {
  const subs = info.subdomains || {};
  const hosts = Object.keys(subs).sort();
  return hosts.map(host => {
    const entry = subs[host] || {};
    const httpx = entry.httpx || {};
    const statusCode = httpx.status_code !== undefined && httpx.status_code !== null ? String(httpx.status_code) : '';
    return {
      host,
      sources: entry.sources || [],
      statusCode,
      title: httpx.title || '',
      server: httpx.webserver || '',
      screenshot: entry.screenshot,
      nucleiCount: Array.isArray(entry.nuclei) ? entry.nuclei.length : 0,
      niktoCount: Array.isArray(entry.nikto) ? entry.nikto.length : 0,
      url: httpx.url || '',
    };
  });
}

function buildStatusFilterOptions(rows) {
  const statuses = new Set();
  rows.forEach(row => statuses.add(row.statusCode || 'none'));
  return Array.from(statuses).sort((a, b) => {
    if (a === 'none') return 1;
    if (b === 'none') return -1;
    return Number(a) - Number(b);
  });
}

function buildNucleiRows(info) {
  const rows = [];
  const subs = info.subdomains || {};
  Object.entries(subs).forEach(([host, entry]) => {
    (entry.nuclei || []).forEach(finding => {
      const severity = normalizeSeverity(finding && finding.severity, 'INFO');
      rows.push({
        host,
        severity,
        template: finding.template_id || finding["template-id"] || 'N/A',
        name: finding.name || '',
        location: finding.matched_at || finding["matched-at"] || finding.url || '',
      });
    });
  });
  return rows;
}

function buildNiktoRows(info) {
  const rows = [];
  const subs = info.subdomains || {};
  Object.entries(subs).forEach(([host, entry]) => {
    (entry.nikto || []).forEach(finding => {
      const severity = normalizeSeverity((finding && (finding.severity || finding.risk)) || 'INFO', 'INFO');
      rows.push({
        host,
        severity,
        message: finding.msg || finding.description || finding.raw || '',
        reference: finding.uri || (finding.osvdb ? `OSVDB-${finding.osvdb}` : ''),
      });
    });
  });
  return rows;
}

function renderReportDetail(domain) {
  const detail = document.getElementById('report-detail');
  if (!detail) return;
  const info = latestTargetsData[domain];
  if (!info) {
    detail.innerHTML = '<div class="section-placeholder">Select a program to view its report.</div>';
    return;
  }
  selectedReportDomain = domain;
  const stats = computeReportStats(info);
  const badge = info.pending
    ? '<span class="report-badge pending">Pending</span>'
    : '<span class="report-badge complete">Complete</span>';
  const maxSeverity = stats.maxSeverity || 'NONE';
  const maxSeverityText = formatSeverityLabel(maxSeverity);
  const maxSeverityFlag = `<span class="severity-flag ${escapeHtml(maxSeverity)}">Max: ${escapeHtml(maxSeverityText)}</span>`;
  const maxNucleiSeverity = stats.maxNucleiSeverity || 'NONE';
  const maxNucleiSeverityText = formatSeverityLabel(maxNucleiSeverity);
  const maxNucleiSeverityFlag = `<span class="severity-flag ${escapeHtml(maxNucleiSeverity)}">Nuclei: ${escapeHtml(maxNucleiSeverityText)}</span>`;
  const maxNiktoSeverity = stats.maxNiktoSeverity || 'NONE';
  const maxNiktoSeverityText = formatSeverityLabel(maxNiktoSeverity);
  const maxNiktoSeverityFlag = `<span class="severity-flag ${escapeHtml(maxNiktoSeverity)}">Nikto: ${escapeHtml(maxNiktoSeverityText)}</span>`;
  const activeJob = hasActiveJob(domain);
  const canResume = info.pending && !activeJob;
  const resumeButton = canResume ? `<button class="btn small" data-resume-target="${escapeHtml(domain)}">Resume Scan</button>` : '';
  const resumeNotice = info.pending && activeJob ? '<span class="muted">Scan already active for this program.</span>' : '';
  const subRows = buildSubdomainRows(info);
  const statusOptions = buildStatusFilterOptions(subRows);
  const statusFilters = statusOptions.length
    ? statusOptions.map(code => {
        const label = code === 'none' ? 'No status' : code;
        return `<label><input type="checkbox" value="${escapeHtml(code)}" checked />${escapeHtml(label)}</label>`;
      }).join('')
    : '<span class="muted">No HTTP data yet.</span>';
  const subTableRows = subRows.length
    ? subRows.map(row => {
        const statusCode = row.statusCode || '';
        const screenshotLink = row.screenshot && row.screenshot.path
          ? `<a href="/screenshots/${escapeHtml(row.screenshot.path)}" target="_blank">View</a>`
          : '—';
        return `
          <tr data-status-code="${statusCode || 'none'}" data-host="${escapeHtml(row.host.toLowerCase())}" data-title="${escapeHtml((row.title || '').toLowerCase())}">
            <td data-sort-value="${escapeHtml(row.host)}"><a href="/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(row.host)}" class="link-btn">${escapeHtml(row.host)}</a></td>
            <td data-sort-value="${statusCode || '0'}">${statusCode || '—'}</td>
            <td data-sort-value="${escapeHtml((row.title || '').toLowerCase())}">${escapeHtml(row.title || '—')}</td>
            <td data-sort-value="${escapeHtml((row.server || '').toLowerCase())}">${escapeHtml(row.server || '—')}</td>
            <td data-sort-value="${row.screenshot ? '1' : '0'}">${screenshotLink}</td>
            <td data-sort-value="${row.nucleiCount}">${row.nucleiCount ? `${row.nucleiCount} findings` : '—'}</td>
            <td data-sort-value="${row.niktoCount}">${row.niktoCount ? `${row.niktoCount} findings` : '—'}</td>
            <td data-sort-value="${escapeHtml((row.sources || []).join(', ').toLowerCase())}">${escapeHtml((row.sources || []).join(', ')) || '—'}</td>
          </tr>
        `;
      }).join('')
    : '<tr><td colspan="8">No subdomains collected yet.</td></tr>';
  const nucleiRows = buildNucleiRows(info);
  const nucleiSeverities = Array.from(new Set(nucleiRows.map(row => row.severity))).sort();
  const nucleiFilters = nucleiSeverities.length
    ? nucleiSeverities.map(sev => `<label><input type="checkbox" value="${escapeHtml(sev)}" checked />${escapeHtml(sev)}</label>`).join('')
    : '';
  const nucleiTableRows = nucleiRows.length
    ? nucleiRows.map(row => `
        <tr data-severity="${escapeHtml(row.severity)}">
          <td data-sort-value="${escapeHtml(row.severity)}"><span class="severity-pill ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
          <td data-sort-value="${escapeHtml(row.host.toLowerCase())}">${escapeHtml(row.host)}</td>
          <td data-sort-value="${escapeHtml((row.template || '').toLowerCase())}">${escapeHtml(row.template || 'N/A')}</td>
          <td data-sort-value="${escapeHtml((row.name || '').toLowerCase())}">${escapeHtml(row.name || '—')}</td>
          <td data-sort-value="${escapeHtml((row.location || '').toLowerCase())}">${escapeHtml(row.location || '—')}</td>
        </tr>
      `).join('')
    : '';
  const niktoRows = buildNiktoRows(info);
  const niktoSeverities = Array.from(new Set(niktoRows.map(row => row.severity))).sort();
  const niktoFilters = niktoSeverities.length
    ? niktoSeverities.map(sev => `<label><input type="checkbox" value="${escapeHtml(sev)}" checked />${escapeHtml(sev)}</label>`).join('')
    : '';
  const niktoTableRows = niktoRows.length
    ? niktoRows.map(row => `
        <tr data-severity="${escapeHtml(row.severity)}">
          <td data-sort-value="${escapeHtml(row.severity)}"><span class="severity-pill ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
          <td data-sort-value="${escapeHtml(row.host.toLowerCase())}">${escapeHtml(row.host)}</td>
          <td data-sort-value="${escapeHtml((row.message || '').toLowerCase())}">${escapeHtml(row.message || '—')}</td>
          <td data-sort-value="${escapeHtml((row.reference || '').toLowerCase())}">${escapeHtml(row.reference || '—')}</td>
        </tr>
      `).join('')
    : '';
  const overviewBody = `
    <div class="progress-track">
      <div class="label">Run progress</div>
      <div class="progress-bar"><div class="progress-inner" style="width:${stats.progress}%"></div></div>
      <div class="muted">${stats.progress}% complete (${stats.processed_subdomains}/${stats.subdomains || 0} fully processed)</div>
    </div>
    <div class="report-stats-grid">
      <div class="report-stat">
        <div class="label">Subdomains</div>
        <div class="value">${stats.subdomains}</div>
      </div>
      <div class="report-stat">
        <div class="label">HTTP entries</div>
        <div class="value">${stats.http}</div>
      </div>
      <div class="report-stat">
        <div class="label">Nuclei findings</div>
        <div class="value">${stats.nuclei}</div>
      </div>
      <div class="report-stat">
        <div class="label">Nikto findings</div>
        <div class="value">${stats.nikto}</div>
      </div>
      <div class="report-stat">
        <div class="label">Screenshots</div>
        <div class="value">${stats.screenshots}</div>
      </div>
      <div class="report-stat">
        <div class="label">Max severity (Overall)</div>
        <div class="value">${maxSeverityFlag}</div>
      </div>
      <div class="report-stat">
        <div class="label">Highest Nuclei</div>
        <div class="value">${maxNucleiSeverityFlag}</div>
      </div>
      <div class="report-stat">
        <div class="label">Highest Nikto</div>
        <div class="value">${maxNiktoSeverityFlag}</div>
      </div>
    </div>
    <div class="report-stats-grid">
      <div class="report-stat">
        <div class="label">Pending subdomains</div>
        <div class="value">${stats.pending_subdomains}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending HTTP</div>
        <div class="value">${stats.pending_http}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending screenshots</div>
        <div class="value">${stats.pending_screenshots}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending nuclei</div>
        <div class="value">${stats.pending_nuclei}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending nikto</div>
        <div class="value">${stats.pending_nikto}</div>
      </div>
    </div>
    <div class="step-checklist">
      ${buildStepChecklist(info)}
    </div>
  `;
  const subPaginationId = 'subdomains-pagination';
  const nucleiPaginationId = 'nuclei-pagination';
  const niktoPaginationId = 'nikto-pagination';
  const subdomainsTitle = `Subdomains (${stats.subdomains})`;
  const nucleiTitle = `Nuclei Findings (${nucleiRows.length})`;
  const niktoTitle = `Nikto Findings (${niktoRows.length})`;
  const subdomainsBody = `
    <div class="filter-bar">
      <div class="filter-group" data-status-filter>
        ${statusFilters}
      </div>
      <input type="search" class="report-search" placeholder="Search subdomains…" data-sub-search />
    </div>
    <div class="table-wrapper">
      <table class="targets-table" id="subdomains-table">
        <thead>
          <tr>
            <th data-sort-key="host">Subdomain</th>
            <th data-sort-key="status" data-sort-type="number">Status</th>
            <th data-sort-key="title">Title</th>
            <th data-sort-key="server">Server</th>
            <th data-sort-key="screenshot" data-sort-type="number">Screenshot</th>
            <th data-sort-key="nuclei" data-sort-type="number">Nuclei</th>
            <th data-sort-key="nikto" data-sort-type="number">Nikto</th>
            <th data-sort-key="sources">Sources</th>
          </tr>
        </thead>
        <tbody>${subTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${subPaginationId}"></div>
    <p class="report-table-note">Click a subdomain to explore its detailed timeline.</p>
  `;
  const nucleiContent = nucleiRows.length ? `
    ${nucleiRows.length ? `<div class="filter-bar" data-nuclei-filter><div class="filter-group">${nucleiFilters}</div></div>` : ''}
    <div class="table-wrapper">
      <table class="targets-table" id="nuclei-table">
        <thead>
          <tr>
            <th data-sort-key="severity">Severity</th>
            <th data-sort-key="host">Host</th>
            <th data-sort-key="template">Template</th>
            <th data-sort-key="name">Name</th>
            <th data-sort-key="location">Matched</th>
          </tr>
        </thead>
        <tbody>${nucleiTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${nucleiPaginationId}"></div>
  ` : '<p class="muted">No nuclei findings recorded.</p>';
  const niktoContent = niktoRows.length ? `
    ${niktoRows.length ? `<div class="filter-bar" data-nikto-filter><div class="filter-group">${niktoFilters}</div></div>` : ''}
    <div class="table-wrapper">
      <table class="targets-table" id="nikto-table">
        <thead>
          <tr>
            <th data-sort-key="severity">Severity</th>
            <th data-sort-key="host">Host</th>
            <th data-sort-key="message">Message</th>
            <th data-sort-key="reference">Reference</th>
          </tr>
        </thead>
        <tbody>${niktoTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${niktoPaginationId}"></div>
  ` : '<p class="muted">No Nikto findings recorded.</p>';
  const commandsBody = `
    <div data-command-log data-command-domain="${escapeHtml(domain)}">
      <p class="muted">Loading command history…</p>
    </div>
  `;
  detail.innerHTML = `
    <div class="report-header">
      <div>
        <h3>${escapeHtml(domain)}</h3>
        ${badge}
      </div>
      <div class="report-actions">
        ${stats.screenshots > 0 ? `<a href="/gallery/${encodeURIComponent(domain)}" class="btn secondary small" target="_blank">View Screenshots Gallery</a>` : ''}
        ${resumeButton}
        ${resumeNotice}
      </div>
    </div>
    ${renderCollapsibleSection('overview', 'Overview', overviewBody, true)}
    ${renderCollapsibleSection('subdomains', subdomainsTitle, subdomainsBody, true)}
    ${renderCollapsibleSection('nuclei', nucleiTitle, nucleiContent, nucleiRows.length > 0)}
    ${renderCollapsibleSection('nikto', niktoTitle, niktoContent, false)}
    ${renderCollapsibleSection('commands', 'Command History', commandsBody, false)}
  `;
  makeSortable(detail.querySelector('#subdomains-table'));
  makeSortable(detail.querySelector('#nuclei-table'));
  makeSortable(detail.querySelector('#nikto-table'));
  initPagination(detail.querySelector('#subdomains-table'), detail.querySelector('#' + subPaginationId), DEFAULT_PAGE_SIZE);
  initPagination(detail.querySelector('#nuclei-table'), detail.querySelector('#' + nucleiPaginationId), DEFAULT_PAGE_SIZE);
  initPagination(detail.querySelector('#nikto-table'), detail.querySelector('#' + niktoPaginationId), DEFAULT_PAGE_SIZE);
  attachSubdomainFilters(detail);
  attachSeverityFilter(detail.querySelector('[data-nuclei-filter]'), detail.querySelector('#nuclei-table'));
  attachSeverityFilter(detail.querySelector('[data-nikto-filter]'), detail.querySelector('#nikto-table'));
  hydrateCommandLog(domain);
  updateReportNavSelection();
}

function attachSubdomainFilters(detailEl) {
  const table = detailEl.querySelector('#subdomains-table');
  if (!table) return;
  const statusGroup = detailEl.querySelector('[data-status-filter]');
  const searchInput = detailEl.querySelector('[data-sub-search]');
  const apply = () => {
    const activeStatuses = statusGroup
      ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]'))
          .filter(input => input.checked)
          .map(input => input.value)
      : [];
    const allowed = activeStatuses.length ? new Set(activeStatuses) : null;
    const query = (searchInput && searchInput.value || '').trim().toLowerCase();
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const status = row.dataset.statusCode || 'none';
      const host = row.dataset.host || '';
      const title = row.dataset.title || '';
      const matchesStatus = !allowed || allowed.has(status);
      const matchesSearch = !query || host.includes(query) || title.includes(query);
      row.dataset.filterHidden = matchesStatus && matchesSearch ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  if (statusGroup) {
    statusGroup.querySelectorAll('input[type="checkbox"]').forEach(input => input.addEventListener('change', apply));
  }
  if (searchInput) {
    searchInput.addEventListener('input', apply);
  }
  apply();
}

function attachSeverityFilter(wrapper, table) {
  if (!wrapper || !table) return;
  const checkboxes = wrapper.querySelectorAll('input[type="checkbox"]');
  if (!checkboxes.length) return;
  const apply = () => {
    const allowed = new Set(Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value));
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const sev = row.dataset.severity || 'INFO';
      row.dataset.filterHidden = allowed.has(sev) ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  checkboxes.forEach(cb => cb.addEventListener('change', apply));
  apply();
}

async function fetchCommandHistory(domain) {
  if (commandHistoryCache[domain]) {
    return commandHistoryCache[domain];
  }
  try {
    const resp = await fetch(`/api/history/commands?domain=${encodeURIComponent(domain)}&limit=400`);
    if (!resp.ok) throw new Error('Failed to fetch commands');
    const data = await resp.json();
    const commands = Array.isArray(data.commands) ? data.commands : [];
    commandHistoryCache[domain] = commands;
    return commands;
  } catch (err) {
    return [];
  }
}

async function hydrateCommandLog(domain) {
  const container = document.querySelector('[data-command-log]');
  if (!container) return;
  const targetDomain = container.getAttribute('data-command-domain');
  if (targetDomain !== domain) return;
  container.innerHTML = '<p class="muted">Loading command history…</p>';
  const commands = await fetchCommandHistory(domain);
  if (container.getAttribute('data-command-domain') !== domain) {
    return;
  }
  if (!commands.length) {
    container.innerHTML = '<p class="muted">No commands recorded yet.</p>';
    return;
  }
  const items = commands.map(entry => `
    <li class="command-item">
      <span class="command-time">${escapeHtml(entry.ts || '')}</span>
      <span class="command-text">${escapeHtml(entry.text || '')}</span>
    </li>
  `).join('');
  container.innerHTML = `<ul class="command-list">${items}</ul>`;
}

async function handleResumeTarget(domain, button) {
  if (!domain || !button) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Resuming…';
  try {
    const resp = await fetch('/api/targets/resume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await resp.json();
    button.textContent = data.message || original;
    if (data.success) {
      fetchState();
    }
  } catch (err) {
    button.textContent = err.message || 'Failed';
  } finally {
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 2000);
  }
}

async function handleJobControl(action, domain, button) {
  if (!domain || !button) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = action === 'pause' ? 'Pausing…' : 'Resuming…';
  try {
    const resp = await fetch(`/api/jobs/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await resp.json();
    button.textContent = data.message || original;
    if (data.success) {
      fetchState();
    }
  } catch (err) {
    button.textContent = err.message || 'Failed';
  } finally {
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 2000);
  }
}

reportsBody.addEventListener('click', (event) => {
  const subBtn = event.target.closest('.sub-link');
  if (subBtn) {
    event.preventDefault();
    const domain = subBtn.getAttribute('data-domain');
    const sub = subBtn.getAttribute('data-sub');
    openSubdomainDetail(domain, sub);
    return;
  }
  const resumeBtn = event.target.closest('[data-resume-target]');
  if (resumeBtn) {
    const domain = resumeBtn.getAttribute('data-resume-target');
    handleResumeTarget(domain, resumeBtn);
    return;
  }
  const card = event.target.closest('.report-nav-card');
  if (card) {
    const domain = card.getAttribute('data-report-domain');
    if (domain) {
      renderReportDetail(domain);
    }
  }
});

jobsList.addEventListener('click', (event) => {
  const pauseBtn = event.target.closest('[data-pause-job]');
  if (pauseBtn) {
    const domain = pauseBtn.getAttribute('data-pause-job');
    handleJobControl('pause', domain, pauseBtn);
    return;
  }
  const resumeBtn = event.target.closest('[data-resume-job]');
  if (resumeBtn) {
    const domain = resumeBtn.getAttribute('data-resume-job');
    handleJobControl('resume', domain, resumeBtn);
  }
});

// Resume All button handler
const resumeAllBtn = document.getElementById('resume-all-btn');
if (resumeAllBtn) {
  resumeAllBtn.addEventListener('click', async () => {
    const original = resumeAllBtn.textContent;
    resumeAllBtn.disabled = true;
    resumeAllBtn.textContent = 'Resuming...';
    try {
      const resp = await fetch('/api/jobs/resume-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await resp.json();
      resumeAllBtn.textContent = data.message || 'Done';
      if (data.success) {
        fetchState();
      }
    } catch (err) {
      resumeAllBtn.textContent = err.message || 'Failed';
    } finally {
      setTimeout(() => {
        resumeAllBtn.textContent = original;
        resumeAllBtn.disabled = false;
      }, 2000);
    }
  });
}

document.addEventListener('click', (event) => {
  const header = event.target.closest('.collapsible-header');
  if (!header) return;
  const container = header.closest('.collapsible');
  if (!container) return;
  container.classList.toggle('open');
  const body = container.querySelector('.collapsible-body');
  if (!body) return;
  if (!container.classList.contains('open')) {
    body.scrollTop = 0;
  }
});
function renderSettings(config, tools) {
  settingsSummary.innerHTML = `
    <div class="paths-grid">
      <div><strong>Results directory</strong><br><code>${escapeHtml(config.data_dir || '')}</code></div>
      <div><strong>state.json</strong><br><code>${escapeHtml(config.state_file || '')}</code></div>
      <div><strong>dashboard.html</strong><br><code>${escapeHtml(config.dashboard_file || '')}</code></div>
      <div><strong>screenshots</strong><br><code>${escapeHtml(config.screenshots_dir || '')}</code></div>
      <div><strong>Concurrency</strong><br>
        Jobs: ${escapeHtml(config.max_running_jobs || 1)} ·
        ffuf: ${escapeHtml(config.max_parallel_ffuf || 1)} ·
        nuclei: ${escapeHtml(config.max_parallel_nuclei || 1)} ·
        Nikto: ${escapeHtml(config.max_parallel_nikto || 1)} ·
        Screenshots: ${escapeHtml(config.max_parallel_gowitness || 1)}
      </div>
      <div><strong>Enumerators</strong><br>
        Amass: ${config.enable_amass === false ? 'disabled' : `enabled (timeout=${escapeHtml(config.amass_timeout || 600)}s)`} ·
        Subfinder: ${config.enable_subfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.subfinder_threads || 32)})`} ·
        Assetfinder: ${config.enable_assetfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.assetfinder_threads || 10)})`} ·
        Findomain: ${config.enable_findomain === false ? 'disabled' : `enabled (t=${escapeHtml(config.findomain_threads || 40)})`} ·
        Sublist3r: ${config.enable_sublist3r === false ? 'disabled' : 'enabled'} ·
        Screenshots: ${config.enable_screenshots === false ? 'disabled' : 'enabled'}
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
    settingsWildcardTlds.value = (config.wildcard_tlds || []).join(', ');
    settingsSkipNikto.checked = !!config.skip_nikto_by_default;
    settingsEnableScreenshots.checked = config.enable_screenshots !== false;
    settingsEnableAmass.checked = config.enable_amass !== false;
    settingsAmassTimeout.value = config.amass_timeout || 600;
    settingsEnableSubfinder.checked = config.enable_subfinder !== false;
    settingsEnableAssetfinder.checked = config.enable_assetfinder !== false;
    settingsEnableFindomain.checked = config.enable_findomain !== false;
    settingsEnableSublist3r.checked = config.enable_sublist3r !== false;
    settingsEnableCrtsh.checked = config.enable_crtsh !== false;
    settingsEnableGithubSubdomains.checked = config.enable_github_subdomains !== false;
    settingsEnableDnsx.checked = config.enable_dnsx !== false;
    settingsEnableWaybackurls.checked = config.enable_waybackurls !== false;
    settingsEnableGau.checked = config.enable_gau !== false;
    settingsSubfinderThreads.value = config.subfinder_threads || 32;
    settingsAssetfinderThreads.value = config.assetfinder_threads || 10;
    settingsFindomainThreads.value = config.findomain_threads || 40;
    settingsGlobalRateLimit.value = config.global_rate_limit || 0;
    settingsMaxJobs.value = config.max_running_jobs || 1;
    settingsFFUF.value = config.max_parallel_ffuf || 1;
    settingsNuclei.value = config.max_parallel_nuclei || 1;
    settingsNikto.value = config.max_parallel_nikto || 1;
    settingsGowitness.value = config.max_parallel_gowitness || 1;
    settingsDnsx.value = config.max_parallel_dnsx || 1;
    settingsWaybackurls.value = config.max_parallel_waybackurls || 1;
    settingsGau.value = config.max_parallel_gau || 1;
    const templateValues = config.tool_flag_templates || {};
    Object.entries(templateInputs).forEach(([key, el]) => {
      if (!el) return;
      el.value = templateValues[key] || '';
    });
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
    latestConfig = data.config || {};
    latestRunningJobs = data.running_jobs || [];
    latestQueuedJobs = data.queued_jobs || [];
    latestTargetsData = data.targets || {};
    document.getElementById('last-updated').textContent = 'Last updated: ' + (data.last_updated || 'never');
    renderJobs(data.running_jobs || []);
    renderQueue(data.queued_jobs || []);
    renderTargets(data.targets || {});
    renderSettings(data.config || {}, data.tools || {});
    renderWorkers(data.workers || {});
    renderReports(data.targets || {});
    renderMonitors(data.monitors || []);
    
    // Update logs view if visible
    const logsSection = document.querySelector('[data-view="logs"]');
    if (logsSection && logsSection.classList.contains('active')) {
      await updateLogsView();
    }
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
    wildcard_tlds: settingsWildcardTlds.value,
    skip_nikto_by_default: settingsSkipNikto.checked,
    enable_screenshots: settingsEnableScreenshots.checked,
    enable_amass: settingsEnableAmass.checked,
    amass_timeout: settingsAmassTimeout.value,
    enable_subfinder: settingsEnableSubfinder.checked,
    enable_assetfinder: settingsEnableAssetfinder.checked,
    enable_findomain: settingsEnableFindomain.checked,
    enable_sublist3r: settingsEnableSublist3r.checked,
    enable_crtsh: settingsEnableCrtsh.checked,
    enable_github_subdomains: settingsEnableGithubSubdomains.checked,
    enable_dnsx: settingsEnableDnsx.checked,
    enable_waybackurls: settingsEnableWaybackurls.checked,
    enable_gau: settingsEnableGau.checked,
    subfinder_threads: settingsSubfinderThreads.value,
    assetfinder_threads: settingsAssetfinderThreads.value,
    findomain_threads: settingsFindomainThreads.value,
    global_rate_limit: settingsGlobalRateLimit.value,
    max_running_jobs: settingsMaxJobs.value,
    max_parallel_ffuf: settingsFFUF.value,
    max_parallel_nuclei: settingsNuclei.value,
    max_parallel_nikto: settingsNikto.value,
    max_parallel_gowitness: settingsGowitness.value,
    max_parallel_dnsx: settingsDnsx.value,
    max_parallel_waybackurls: settingsWaybackurls.value,
    max_parallel_gau: settingsGau.value,
  };
  const templatePayload = {};
  Object.entries(templateInputs).forEach(([key, el]) => {
    if (!el) return;
    templatePayload[key] = el.value || '';
  });
  payload.tool_flag_templates = templatePayload;
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

if (monitorForm) {
  monitorForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
      name: monitorName ? monitorName.value : '',
      url: monitorUrl ? monitorUrl.value : '',
      interval: monitorInterval ? monitorInterval.value : '',
    };
    if (monitorStatus) {
      monitorStatus.textContent = 'Saving...';
      monitorStatus.className = 'status';
    }
    try {
      const resp = await fetch('/api/monitors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (monitorStatus) {
        monitorStatus.textContent = data.message || 'Saved';
        monitorStatus.className = 'status ' + (data.success ? 'success' : 'error');
      }
      if (data.success) {
        monitorForm.reset();
        fetchState();
      }
    } catch (err) {
      if (monitorStatus) {
        monitorStatus.textContent = err.message;
        monitorStatus.className = 'status error';
      }
    }
  });
}

if (monitorsList) {
  monitorsList.addEventListener('click', (event) => {
    const removeBtn = event.target.closest('[data-remove-monitor]');
    if (removeBtn) {
      const id = removeBtn.getAttribute('data-remove-monitor');
      deleteMonitor(id, removeBtn);
    }
  });
}

// ================== LOGS VIEW ==================

function saveLogFilters() {
  const filters = {
    search: logSearch ? logSearch.value : '',
    source: logSourceFilter ? logSourceFilter.value : '',
    level: logLevelFilter ? logLevelFilter.value : ''
  };
  try {
    localStorage.setItem('logFilters', JSON.stringify(filters));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadLogFilters() {
  try {
    const saved = localStorage.getItem('logFilters');
    if (saved) {
      const filters = JSON.parse(saved);
      if (logSearch) logSearch.value = filters.search || '';
      if (logSourceFilter) logSourceFilter.value = filters.source || '';
      if (logLevelFilter) logLevelFilter.value = filters.level || '';
      return filters;
    }
  } catch (e) {
    // Ignore localStorage errors
  }
  return { search: '', source: '', level: '' };
}

async function fetchAllLogs() {
  // Collect logs from all running jobs and history
  let logs = [];
  
  // Get logs from currently running jobs
  latestRunningJobs.forEach(job => {
    const jobLogs = job.logs || [];
    jobLogs.forEach(entry => {
      logs.push({
        timestamp: entry.ts || '',
        source: entry.source || 'unknown',
        text: entry.text || '',
        domain: job.domain || ''
      });
    });
  });
  
  // Get logs from history for all targets
  const targets = Object.keys(latestTargetsData);
  for (const domain of targets) {
    try {
      const resp = await fetch(`/api/history?domain=${encodeURIComponent(domain)}`);
      if (resp.ok) {
        const data = await resp.json();
        const events = data.events || [];
        events.forEach(entry => {
          logs.push({
            timestamp: entry.ts || '',
            source: entry.source || 'unknown',
            text: entry.text || '',
            domain: domain
          });
        });
      }
    } catch (err) {
      // Ignore fetch errors for individual domains
    }
  }
  
  // Sort by timestamp descending (newest first)
  logs.sort((a, b) => {
    const dateA = new Date(a.timestamp || 0);
    const dateB = new Date(b.timestamp || 0);
    return dateB - dateA;
  });
  
  return logs;
}

function filterLogs() {
  const searchTerm = (logSearch ? logSearch.value : '').toLowerCase();
  const sourceFilter = logSourceFilter ? logSourceFilter.value : '';
  const levelFilter = logLevelFilter ? logLevelFilter.value : '';
  
  filteredLogs = allLogs.filter(log => {
    // Text search
    if (searchTerm && !log.text.toLowerCase().includes(searchTerm) && !log.domain.toLowerCase().includes(searchTerm)) {
      return false;
    }
    
    // Source filter
    if (sourceFilter && log.source !== sourceFilter) {
      return false;
    }
    
    // Level filter (matches source for common cases)
    if (levelFilter) {
      const source = log.source.toLowerCase();
      if (levelFilter === 'error' && !source.includes('error')) {
        return false;
      }
      if (levelFilter === 'stderr' && !source.includes('stderr')) {
        return false;
      }
      if (levelFilter === 'command' && !log.text.startsWith('$')) {
        return false;
      }
      if (levelFilter === 'system' && source !== 'system' && source !== 'scheduler') {
        return false;
      }
    }
    
    return true;
  });
  
  saveLogFilters();
  renderLogs();
}

function renderLogs() {
  if (!logsTbody) return;
  
  if (filteredLogs.length === 0) {
    logsTbody.innerHTML = '<tr><td colspan="3" class="muted">No logs match your filters.</td></tr>';
    if (logsCount) logsCount.textContent = '0 logs';
    return;
  }
  
  const rows = filteredLogs.map(log => {
    const timestamp = fmtTime(log.timestamp);
    const sourceClass = log.source.toLowerCase().includes('error') || log.source.toLowerCase().includes('stderr') ? 'error-source' : '';
    return `
      <tr>
        <td data-sort-value="${escapeHtml(log.timestamp)}">${escapeHtml(timestamp)}</td>
        <td data-sort-value="${escapeHtml(log.source)}" class="${sourceClass}">
          <span title="${escapeHtml(log.domain)}">${escapeHtml(log.source)}</span>
        </td>
        <td data-sort-value="${escapeHtml(log.text)}" style="max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.text)}">
          ${escapeHtml(log.text)}
        </td>
      </tr>
    `;
  }).join('');
  
  logsTbody.innerHTML = rows;
  if (logsCount) logsCount.textContent = `${filteredLogs.length} logs (of ${allLogs.length} total)`;
  
  // Apply pagination if available
  if (logsPagination && logsTable) {
    initPagination(logsTable, logsPagination, DEFAULT_PAGE_SIZE);
  }
}

function populateLogSourceFilter() {
  if (!logSourceFilter) return;
  
  const sources = new Set();
  allLogs.forEach(log => {
    if (log.source) sources.add(log.source);
  });
  
  const currentValue = logSourceFilter.value;
  const sortedSources = Array.from(sources).sort();
  
  logSourceFilter.innerHTML = '<option value="">All sources</option>' +
    sortedSources.map(source => `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`).join('');
  
  // Restore previous selection if it still exists
  if (currentValue && sortedSources.includes(currentValue)) {
    logSourceFilter.value = currentValue;
  }
}

async function updateLogsView() {
  allLogs = await fetchAllLogs();
  populateLogSourceFilter();
  filterLogs();
}

// Event listeners for logs
if (logSearch) {
  logSearch.addEventListener('input', filterLogs);
}

if (logSourceFilter) {
  logSourceFilter.addEventListener('change', filterLogs);
}

if (logLevelFilter) {
  logLevelFilter.addEventListener('change', filterLogs);
}

if (logClearFilters) {
  logClearFilters.addEventListener('click', () => {
    if (logSearch) logSearch.value = '';
    if (logSourceFilter) logSourceFilter.value = '';
    if (logLevelFilter) logLevelFilter.value = '';
    filterLogs();
  });
}

// Load saved filters on page load
loadLogFilters();

renderWorkflowDiagram();
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
    # Include all tools with their gate information if they have one
    tool_stats = {}
    for name in TOOLS.keys():
        if name in TOOL_GATES:
            # Tool has a gate, show active/limit
            tool_stats[name] = TOOL_GATES[name].snapshot()
        else:
            # Tool without gate, show as available but no concurrency limit
            tool_stats[name] = {
                "limit": None,
                "active": 0,
            }
    return {
        "job_slots": {
            "limit": MAX_RUNNING_JOBS,
            "active": active_jobs,
            "queue": queue_len,
        },
        "tools": tool_stats,
    }


def build_targets_csv(state: Dict[str, Any]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["domain", "subdomains", "http_entries", "nuclei_findings", "nikto_findings", "screenshots"])
    targets = state.get("targets", {})
    for domain, info in sorted(targets.items()):
        subs = info.get("subdomains", {})
        sub_keys = subs.keys()
        http_count = sum(1 for data in subs.values() if data.get("httpx"))
        nuclei_count = sum(len(data.get("nuclei") or []) for data in subs.values())
        nikto_count = sum(len(data.get("nikto") or []) for data in subs.values())
        screenshot_count = sum(1 for data in subs.values() if data.get("screenshot"))
        writer.writerow([domain, len(sub_keys), http_count, nuclei_count, nikto_count, screenshot_count])
    return output.getvalue().encode("utf-8")


def pause_job(domain: str) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if not job:
            return False, f"No active job for {normalized}."
        thread = job.get("thread")
    if not thread or not thread.is_alive():
        return False, f"Job thread for {normalized} is not running."
    ctrl = ensure_job_control(normalized)
    if not ctrl.request_pause():
        return False, f"{normalized} is already paused."
    job_set_status(normalized, "pausing", "Pause requested; waiting for pipeline to acknowledge.")
    job_log_append(normalized, "Pause requested by user.", "scheduler")
    return True, f"{normalized} will pause momentarily."


def resume_job(domain: str) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if not job:
            return False, f"No active job for {normalized}."
        thread = job.get("thread")
    if not thread or not thread.is_alive():
        return False, f"Job thread for {normalized} is not running."
    ctrl = get_job_control(normalized)
    if not ctrl:
        return False, f"{normalized} is not currently paused."
    if not ctrl.request_resume():
        return False, f"{normalized} is not paused."
    job_set_status(normalized, "running", "Resume requested by user.")
    job_log_append(normalized, "Resume requested by user.", "scheduler")
    return True, f"{normalized} resumed."


def resume_all_paused_jobs() -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Resume all paused jobs at once."""
    with JOB_LOCK:
        paused_domains = []
        for domain, job in RUNNING_JOBS.items():
            status = job.get("status", "")
            if status in ("paused", "pausing"):
                thread = job.get("thread")
                if thread and thread.is_alive():
                    paused_domains.append(domain)
    
    if not paused_domains:
        return False, "No paused jobs found.", []
    
    results = []
    resumed_count = 0
    for domain in paused_domains:
        success, message = resume_job(domain)
        results.append({
            "domain": domain,
            "success": success,
            "message": message,
        })
        if success:
            resumed_count += 1
    
    if resumed_count == 0:
        return False, "Failed to resume any jobs.", results
    elif resumed_count < len(paused_domains):
        return True, f"Resumed {resumed_count} of {len(paused_domains)} paused jobs.", results
    else:
        return True, f"Resumed all {resumed_count} paused jobs.", results


def resume_target_scan(domain: str, wordlist: Optional[str] = None,
                       skip_nikto: Optional[bool] = None) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    cfg = get_config()
    state = load_state()
    target = state.get("targets", {}).get(normalized)
    if not target:
        return False, f"No stored reconnaissance data for {normalized}."
    if not target_has_pending_work(target, cfg):
        return False, f"{normalized} already completed all steps."
    options = target.get("options") or {}
    if skip_nikto is None:
        if "skip_nikto" in options:
            skip_flag = bool(options.get("skip_nikto"))
        else:
            skip_flag = bool(cfg.get("skip_nikto_by_default", False))
    else:
        skip_flag = bool(skip_nikto)
    wordlist_val = None
    if wordlist:
        cleaned = str(wordlist).strip()
        if cleaned:
            wordlist_val = cleaned
    return start_pipeline_job(normalized, wordlist_val, skip_flag, None)


def start_targets_from_input(domain_input: str, wordlist: Optional[str],
                             skip_nikto: bool, interval: Optional[int]) -> Tuple[bool, str, List[Dict[str, Any]]]:
    cfg = get_config()
    cleaned = _sanitize_domain_input(domain_input)
    requested_any_tld = bool(cleaned.endswith(".*"))
    targets = expand_wildcard_targets(domain_input, cfg)
    if not targets:
        if requested_any_tld:
            return False, "Wildcard TLD requested but no TLDs are configured. Update wildcard TLDs in Settings.", []
        return False, "Domain is required.", []
    details: List[Dict[str, Any]] = []
    success_any = False
    for target in targets:
        success, message = start_pipeline_job(target, wordlist, skip_nikto, interval)
        if success:
            success_any = True
        details.append({
            "target": target,
            "success": success,
            "message": message,
        })
    if len(details) == 1:
        result = details[0]
        return result["success"], result["message"], details
    summary_parts: List[str] = []
    dispatched = [entry["target"] for entry in details if entry["success"]]
    if dispatched:
        summary_parts.append(f"Dispatched {len(dispatched)} job(s): {', '.join(dispatched)}.")
    failures = [entry["message"] for entry in details if not entry["success"]]
    if failures:
        summary_parts.append(" ".join(failures))
    if not summary_parts:
        summary_parts.append("No jobs were dispatched.")
    return success_any, " ".join(summary_parts).strip(), details


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
        ensure_job_control(normalized)
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
    targets = state.get("targets", {})
    for info in targets.values():
        try:
            info["pending"] = target_has_pending_work(info, config)
        except Exception:
            info["pending"] = True
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    return {
        "last_updated": state.get("last_updated"),
        "targets": targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
    }


def generate_subdomain_detail_page(domain: str, subdomain: str) -> str:
    """Generate a standalone page for subdomain details."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Subdomain Detail: {subdomain}</title>
<style>
body {{
  margin: 0;
  padding: 20px;
  font-family: system-ui, -apple-system, sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  line-height: 1.6;
}}
.container {{
  max-width: 1200px;
  margin: 0 auto;
}}
.header {{
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 2px solid #1e293b;
}}
.back-link {{
  display: inline-block;
  margin-bottom: 12px;
  color: #60a5fa;
  text-decoration: none;
}}
.back-link:hover {{
  text-decoration: underline;
}}
h1 {{
  margin: 0 0 8px 0;
  font-size: 2rem;
  color: #f1f5f9;
}}
.subtitle {{
  color: #94a3b8;
  font-size: 0.95rem;
}}
.section {{
  background: #1e293b;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
}}
.section h2 {{
  margin: 0 0 16px 0;
  font-size: 1.25rem;
  color: #f1f5f9;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}}
.field {{
  padding: 12px;
  background: #0f172a;
  border-radius: 6px;
}}
.field strong {{
  display: block;
  color: #94a3b8;
  font-size: 0.85rem;
  margin-bottom: 4px;
}}
.field-value {{
  color: #e2e8f0;
  word-break: break-word;
}}
.badge {{
  display: inline-block;
  padding: 4px 8px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.85rem;
  margin: 2px;
}}
.severity-pill {{
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 600;
  text-transform: uppercase;
}}
.severity-pill.CRITICAL {{ background: #dc2626; color: white; }}
.severity-pill.HIGH {{ background: #ea580c; color: white; }}
.severity-pill.MEDIUM {{ background: #f59e0b; color: white; }}
.severity-pill.LOW {{ background: #eab308; color: #1e293b; }}
.severity-pill.INFO {{ background: #3b82f6; color: white; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
}}
th, td {{
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #334155;
}}
th {{
  background: #0f172a;
  color: #94a3b8;
  font-weight: 600;
}}
img {{
  max-width: 100%;
  border-radius: 8px;
  border: 1px solid #334155;
}}
.muted {{
  color: #64748b;
  font-style: italic;
}}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="subdomain-title">Loading...</h1>
    <div class="subtitle">Subdomain Details</div>
  </div>
  <div id="content">
    <div class="loading">Loading subdomain details...</div>
  </div>
</div>
<script>
const domain = {repr(domain)};
const subdomain = {repr(subdomain)};

function escapeHtml(text) {{
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}}

function fmtTime(iso) {{
  if (!iso) return '—';
  try {{
    const date = new Date(iso);
    return date.toLocaleString();
  }} catch (_) {{
    return iso;
  }}
}}

async function loadSubdomainDetail() {{
  try {{
    const resp = await fetch(`/api/subdomain/${{encodeURIComponent(domain)}}/${{encodeURIComponent(subdomain)}}`);
    if (!resp.ok) throw new Error('Failed to load subdomain data');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    document.getElementById('subdomain-title').textContent = subdomain;
    renderSubdomainDetail(data.data, data.history);
  }} catch (err) {{
    document.getElementById('content').innerHTML = `<div class="section"><p class="muted">Error: ${{escapeHtml(err.message)}}</p></div>`;
  }}
}}

function renderSubdomainDetail(info, history) {{
  const sources = info.sources || [];
  const httpx = info.httpx || {{}};
  const screenshot = info.screenshot || {{}};
  const nuclei = info.nuclei || [];
  const nikto = info.nikto || [];
  
  let html = '';
  
  // Metadata section
  html += `
    <div class="section">
      <h2>Metadata</h2>
      <div class="grid">
        <div class="field">
          <strong>Parent Domain</strong>
          <div class="field-value"><span class="badge">${{escapeHtml(domain)}}</span></div>
        </div>
        <div class="field">
          <strong>Discovery Sources</strong>
          <div class="field-value">${{sources.length ? sources.map(s => `<span class="badge">${{escapeHtml(s)}}</span>`).join(' ') : '<span class="muted">Unknown</span>'}}</div>
        </div>
      </div>
    </div>
  `;
  
  // HTTP section
  html += `
    <div class="section">
      <h2>HTTP Response</h2>
      ${{Object.keys(httpx).length ? `
        <div class="grid">
          <div class="field"><strong>URL</strong><div class="field-value">${{escapeHtml(httpx.url || '—')}}</div></div>
          <div class="field"><strong>Status Code</strong><div class="field-value">${{httpx.status_code || '—'}}</div></div>
          <div class="field"><strong>Title</strong><div class="field-value">${{escapeHtml(httpx.title || '—')}}</div></div>
          <div class="field"><strong>Server</strong><div class="field-value">${{escapeHtml(httpx.webserver || httpx.server || '—')}}</div></div>
          <div class="field"><strong>Content-Type</strong><div class="field-value">${{escapeHtml(httpx.content_type || '—')}}</div></div>
          <div class="field"><strong>Tech Stack</strong><div class="field-value">${{escapeHtml((httpx.tech || httpx.technologies || []).join(', ') || '—')}}</div></div>
        </div>
      ` : '<p class="muted">No HTTP data available</p>'}}
    </div>
  `;
  
  // Screenshot section
  html += `
    <div class="section">
      <h2>Screenshot</h2>
      ${{screenshot.path ? `
        <div>
          <img src="/screenshots/${{escapeHtml(screenshot.path)}}" alt="Screenshot of ${{escapeHtml(subdomain)}}" />
          ${{screenshot.captured_at ? `<p class="muted" style="margin-top: 12px;">Captured ${{fmtTime(screenshot.captured_at)}}</p>` : ''}}
        </div>
      ` : '<p class="muted">No screenshot available</p>'}}
    </div>
  `;
  
  // Nuclei section
  html += `<div class="section"><h2>Nuclei Findings (${{nuclei.length}})</h2>`;
  if (nuclei.length) {{
    html += `
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Template</th>
            <th>Name</th>
            <th>Matched At</th>
          </tr>
        </thead>
        <tbody>
          ${{nuclei.map(finding => {{
            const severity = (finding.severity || 'INFO').toUpperCase();
            const templateId = finding.template_id || finding['template-id'] || 'N/A';
            const name = finding.name || '';
            const matchedAt = finding.matched_at || finding['matched-at'] || finding.url || '';
            return `
              <tr>
                <td><span class="severity-pill ${{severity}}">${{escapeHtml(severity)}}</span></td>
                <td>${{escapeHtml(templateId)}}</td>
                <td>${{escapeHtml(name)}}</td>
                <td>${{escapeHtml(matchedAt)}}</td>
              </tr>
            `;
          }}).join('')}}
        </tbody>
      </table>
    `;
  }} else {{
    html += '<p class="muted">No Nuclei findings</p>';
  }}
  html += '</div>';
  
  // Nikto section
  html += `<div class="section"><h2>Nikto Findings (${{nikto.length}})</h2>`;
  if (nikto.length) {{
    html += `
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Message</th>
            <th>Reference</th>
          </tr>
        </thead>
        <tbody>
          ${{nikto.map(finding => {{
            const severity = ((finding.severity || finding.risk) || 'INFO').toUpperCase();
            const message = finding.msg || finding.description || finding.raw || '';
            const reference = finding.uri || (finding.osvdb ? `OSVDB-${{finding.osvdb}}` : '') || '—';
            return `
              <tr>
                <td><span class="severity-pill ${{severity}}">${{escapeHtml(severity)}}</span></td>
                <td>${{escapeHtml(message)}}</td>
                <td>${{escapeHtml(reference)}}</td>
              </tr>
            `;
          }}).join('')}}
        </tbody>
      </table>
    `;
  }} else {{
    html += '<p class="muted">No Nikto findings</p>';
  }}
  html += '</div>';
  
  document.getElementById('content').innerHTML = html;
}}

loadSubdomainDetail();
</script>
</body>
</html>
"""


def generate_screenshots_gallery_page(domain: str) -> str:
    """Generate a standalone page for screenshots gallery."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Screenshots Gallery: {domain}</title>
<style>
body {{
  margin: 0;
  padding: 20px;
  font-family: system-ui, -apple-system, sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  line-height: 1.6;
}}
.container {{
  max-width: 1400px;
  margin: 0 auto;
}}
.header {{
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 2px solid #1e293b;
}}
.back-link {{
  display: inline-block;
  margin-bottom: 12px;
  color: #60a5fa;
  text-decoration: none;
}}
.back-link:hover {{
  text-decoration: underline;
}}
h1 {{
  margin: 0 0 8px 0;
  font-size: 2rem;
  color: #f1f5f9;
}}
.subtitle {{
  color: #94a3b8;
  font-size: 0.95rem;
}}
.gallery {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 20px;
}}
.screenshot-card {{
  background: #1e293b;
  border-radius: 8px;
  overflow: hidden;
  transition: transform 0.2s;
}}
.screenshot-card:hover {{
  transform: translateY(-4px);
}}
.screenshot-image {{
  width: 100%;
  height: 200px;
  object-fit: cover;
  cursor: pointer;
  background: #0f172a;
  transition: opacity 0.3s;
}}
.screenshot-image[data-src] {{
  opacity: 0.3;
}}
.screenshot-image.loaded {{
  opacity: 1;
}}
.screenshot-info {{
  padding: 16px;
}}
.screenshot-subdomain {{
  font-weight: 600;
  color: #f1f5f9;
  margin-bottom: 8px;
  word-break: break-all;
}}
.screenshot-url {{
  color: #60a5fa;
  text-decoration: none;
  font-size: 0.85rem;
  word-break: break-all;
}}
.screenshot-url:hover {{
  text-decoration: underline;
}}
.screenshot-meta {{
  margin-top: 8px;
  font-size: 0.8rem;
  color: #94a3b8;
}}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.75rem;
  margin-right: 4px;
}}
.status-badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.status-2xx {{ background: #059669; color: white; }}
.status-3xx {{ background: #3b82f6; color: white; }}
.status-4xx {{ background: #f59e0b; color: white; }}
.status-5xx {{ background: #dc2626; color: white; }}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
.empty {{
  text-align: center;
  padding: 60px 20px;
  color: #64748b;
  font-style: italic;
}}
.modal {{
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.9);
  z-index: 1000;
  align-items: center;
  justify-content: center;
  padding: 20px;
}}
.modal.show {{
  display: flex;
}}
.modal img {{
  max-width: 100%;
  max-height: 90vh;
  border-radius: 8px;
}}
.modal-close {{
  position: absolute;
  top: 20px;
  right: 20px;
  color: white;
  font-size: 2rem;
  cursor: pointer;
  background: rgba(0, 0, 0, 0.5);
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="gallery-title">Screenshots Gallery</h1>
    <div class="subtitle" id="gallery-subtitle">Loading...</div>
  </div>
  <div id="gallery" class="gallery">
    <div class="loading">Loading screenshots...</div>
  </div>
</div>
<div id="modal" class="modal">
  <div class="modal-close" onclick="closeModal()">×</div>
  <img id="modal-image" src="" alt="Screenshot" />
</div>
<script>
const domain = {repr(domain)};

function escapeHtml(text) {{
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}}

function fmtTime(iso) {{
  if (!iso) return '—';
  try {{
    const date = new Date(iso);
    return date.toLocaleString();
  }} catch (_) {{
    return iso;
  }}
}}

function getStatusClass(code) {{
  if (!code) return '';
  if (code >= 200 && code < 300) return 'status-2xx';
  if (code >= 300 && code < 400) return 'status-3xx';
  if (code >= 400 && code < 500) return 'status-4xx';
  if (code >= 500) return 'status-5xx';
  return '';
}}

function openModal(src) {{
  document.getElementById('modal-image').src = src;
  document.getElementById('modal').classList.add('show');
}}

function closeModal() {{
  document.getElementById('modal').classList.remove('show');
}}

document.getElementById('modal').addEventListener('click', (e) => {{
  if (e.target.id === 'modal') closeModal();
}});

async function loadGallery() {{
  try {{
    const resp = await fetch(`/api/gallery/${{encodeURIComponent(domain)}}`);
    if (!resp.ok) throw new Error('Failed to load screenshots');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    document.getElementById('gallery-title').textContent = `Screenshots Gallery: ${{domain}}`;
    document.getElementById('gallery-subtitle').textContent = `${{data.screenshots.length}} screenshots`;
    renderGallery(data.screenshots);
  }} catch (err) {{
    document.getElementById('gallery').innerHTML = `<div class="empty">Error: ${{escapeHtml(err.message)}}</div>`;
  }}
}}

function renderGallery(screenshots) {{
  if (screenshots.length === 0) {{
    document.getElementById('gallery').innerHTML = '<div class="empty">No screenshots available for this domain.</div>';
    return;
  }}
  
  const html = screenshots.map(shot => {{
    const statusClass = getStatusClass(shot.status_code);
    const statusBadge = shot.status_code ? `<span class="status-badge ${{statusClass}}">${{shot.status_code}}</span>` : '';
    
    return `
      <div class="screenshot-card">
        <img class="screenshot-image" data-src="/screenshots/${{escapeHtml(shot.path)}}" alt="${{escapeHtml(shot.subdomain)}}" onclick="openModal('/screenshots/${{escapeHtml(shot.path)}}')"/>
        <div class="screenshot-info">
          <div class="screenshot-subdomain">${{escapeHtml(shot.subdomain)}}</div>
          <a href="${{escapeHtml(shot.url)}}" target="_blank" class="screenshot-url">${{escapeHtml(shot.url)}}</a>
          <div class="screenshot-meta">
            ${{statusBadge}}
            ${{shot.title ? `<span class="badge">${{escapeHtml(shot.title)}}</span>` : ''}}
            <br>
            <span>Captured: ${{fmtTime(shot.captured_at)}}</span>
          </div>
        </div>
      </div>
    `;
  }}).join('');
  
  document.getElementById('gallery').innerHTML = html;
  
  // Set up lazy loading with Intersection Observer
  const images = document.querySelectorAll('.screenshot-image[data-src]');
  const imageObserver = new IntersectionObserver((entries, observer) => {{
    entries.forEach(entry => {{
      if (entry.isIntersecting) {{
        const img = entry.target;
        img.src = img.getAttribute('data-src');
        img.removeAttribute('data-src');
        img.addEventListener('load', () => {{
          img.classList.add('loaded');
        }});
        observer.unobserve(img);
      }}
    }});
  }}, {{
    rootMargin: '50px'
  }});
  
  images.forEach(img => imageObserver.observe(img));
}}

loadGallery();
</script>
</body>
</html>
"""


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
        
        # Subdomain detail page route
        if self.path.startswith("/subdomain/"):
            parts = self.path[len("/subdomain/"):].split("/", 1)
            if len(parts) == 2:
                domain = unquote(parts[0]).strip().lower()
                subdomain = unquote(parts[1]).strip().lower()
                self._send_bytes(generate_subdomain_detail_page(domain, subdomain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # Screenshots gallery page route
        if self.path.startswith("/gallery/"):
            domain = unquote(self.path[len("/gallery/"):]).strip().lower()
            if domain:
                self._send_bytes(generate_screenshots_gallery_page(domain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # API endpoint for subdomain detail data
        if self.path.startswith("/api/subdomain/"):
            parts = self.path[len("/api/subdomain/"):].split("/", 1)
            if len(parts) == 2:
                domain = unquote(parts[0]).strip().lower()
                subdomain = unquote(parts[1]).strip().lower()
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target or not target.get("subdomains", {}).get(subdomain):
                    self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                sub_data = target["subdomains"][subdomain]
                try:
                    history = load_domain_history(domain)
                except Exception:
                    history = []
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "subdomain": subdomain,
                    "data": sub_data,
                    "history": history
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        
        # API endpoint for screenshots gallery data
        if self.path.startswith("/api/gallery/"):
            domain = unquote(self.path[len("/api/gallery/"):]).strip().lower()
            if domain:
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target:
                    self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                screenshots = []
                subdomains = target.get("subdomains", {})
                for sub, data in subdomains.items():
                    screenshot = data.get("screenshot")
                    if screenshot and screenshot.get("path"):
                        httpx = data.get("httpx", {})
                        screenshots.append({
                            "subdomain": sub,
                            "path": screenshot["path"],
                            "url": httpx.get("url", f"http://{sub}"),
                            "title": httpx.get("title", ""),
                            "status_code": httpx.get("status_code"),
                            "captured_at": screenshot.get("captured_at"),
                        })
                screenshots.sort(key=lambda x: x.get("captured_at") or "", reverse=True)
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "screenshots": screenshots
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        
        if self.path == "/api/state":
            self._send_json(build_state_payload())
            return
        if self.path == "/api/settings":
            self._send_json({"config": get_config()})
            return
        if self.path == "/api/monitors":
            self._send_json({"monitors": list_monitors()})
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
        if self.path.startswith("/api/history/commands"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = (params.get("domain") or [""])[0].strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "domain parameter required"}, status=HTTPStatus.BAD_REQUEST)
                return
            limit_param = params.get("limit")
            limit = 200
            if limit_param:
                try:
                    limit = max(1, min(2000, int(limit_param[0])))
                except (TypeError, ValueError):
                    limit = 200
            try:
                events = load_domain_history(domain)
            except RuntimeError as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            commands = [evt for evt in events if str(evt.get("text", "")).lstrip().startswith("$")]
            payload = {"domain": domain, "commands": commands[-limit:]}
            self._send_json(payload)
            return

        if self.path.startswith("/api/history"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = (params.get("domain") or [""])[0].strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "domain parameter required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                events = load_domain_history(domain)
            except RuntimeError as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
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
        allowed = {
            "/api/run",
            "/api/settings",
            "/api/jobs/pause",
            "/api/jobs/resume",
            "/api/jobs/resume-all",
            "/api/targets/resume",
            "/api/monitors",
            "/api/monitors/delete",
        }
        if self.path not in allowed:
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

        if self.path == "/api/jobs/pause":
            domain = payload.get("domain", "")
            success, message = pause_job(domain)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/jobs/resume":
            domain = payload.get("domain", "")
            success, message = resume_job(domain)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/jobs/resume-all":
            success, message, results = resume_all_paused_jobs()
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "results": results}, status=status)
            return

        if self.path == "/api/targets/resume":
            domain = payload.get("domain", "")
            skip_value = payload.get("skip_nikto")
            skip_flag = None
            if skip_value is not None and skip_value != "":
                skip_flag = bool_from_value(skip_value, False)
            wordlist = payload.get("wordlist")
            success, message = resume_target_scan(domain, wordlist=wordlist, skip_nikto=skip_flag)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
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

            success, message, _ = start_targets_from_input(domain, wordlist, skip_nikto, interval_int)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/monitors":
            name = payload.get("name", "")
            url = payload.get("url", "")
            interval = payload.get("interval")
            success, message, monitor = add_monitor(name, url, interval)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "monitor": monitor}, status=status)
            return

        if self.path == "/api/monitors/delete":
            monitor_id = payload.get("id") or payload.get("monitor_id") or ""
            success, message = remove_monitor(monitor_id)
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
    start_monitor_worker()
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

    ensure_dirs()
    ensure_required_tools()

    if args.domain:
        cfg = get_config()
        targets = expand_wildcard_targets(args.domain, cfg)
        if not targets:
            cleaned = _sanitize_domain_input(args.domain)
            if cleaned.endswith(".*"):
                log("Wildcard TLD requested but no TLDs are configured. Update wildcard settings in the web UI.")
            else:
                log("No valid targets resolved from input.")
            return
        for target in targets:
            log(f"Running single pipeline execution for {target}.")
            try:
                run_pipeline(target, args.wordlist, skip_nikto=args.skip_nikto, interval=args.interval)
            except KeyboardInterrupt:
                log("Interrupted by user.")
                return
            except Exception as e:
                log(f"Fatal error while processing {target}: {e}")
        return

    log("Launching Recon Command Center web server.")
    run_server(args.host, args.port, args.interval)


if __name__ == "__main__":
    main()
