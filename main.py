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
import hashlib
import io
import json
import mimetypes
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
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

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. System resource monitoring will be disabled.")

# ====================== CONFIG ======================

DATA_DIR = Path("recon_data")
DB_FILE = DATA_DIR / "recon.db"
STATE_FILE = DATA_DIR / "state.json"
HTML_DASHBOARD_FILE = DATA_DIR / "dashboard.html"
LOCK_FILE = DATA_DIR / ".lock"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_DIR = DATA_DIR / "history"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
MONITORS_FILE = DATA_DIR / "monitors.json"
BACKUPS_DIR = DATA_DIR / "backups"
COMPLETED_JOBS_FILE = DATA_DIR / "completed_jobs.json"

# SQLite connection pool
DB_LOCK = threading.Lock()
DB_CONN: Optional[sqlite3.Connection] = None

DEFAULT_INTERVAL = 30
HTML_REFRESH_SECONDS = DEFAULT_INTERVAL  # default; can be overridden
MAX_JOB_LOG_LINES = 400
MAX_JOB_LOG_LINE_LENGTH = 500

# API Key provider lists
AMASS_PROVIDERS = ["shodan", "virustotal", "securitytrails", "censys", "passivetotal", "binaryedge", "bevigil"]
SUBFINDER_PROVIDERS = ["shodan", "censys", "virustotal", "binaryedge", "securitytrails", "passivetotal", "github"]

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
]


class ToolGate:
    """
    Concurrency gate for tools with backlog queue support.
    
    When the tool is at capacity, work items are queued and processed
    when capacity becomes available. This prevents jobs from blocking
    indefinitely and allows them to proceed with other tools.
    """
    def __init__(self, limit: int):
        self._limit = max(1, int(limit))
        self._count = 0
        self._cond = threading.Condition()
        self._queue: deque = deque()  # Backlog queue for pending work
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_worker = False
        self._start_worker()
    
    def _start_worker(self) -> None:
        """Start background worker thread to process queued work."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._stop_worker = False
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name=f"ToolGate-Worker",
                daemon=True
            )
            self._worker_thread.start()
    
    def _worker_loop(self) -> None:
        """Background worker that processes queued work items."""
        while not self._stop_worker:
            work_item = None
            with self._cond:
                # Wait for work or until stopped
                while not self._queue and not self._stop_worker:
                    self._cond.wait(timeout=1.0)
                
                if self._stop_worker:
                    break
                
                # Wait for available capacity
                while self._count >= self._limit and not self._stop_worker:
                    self._cond.wait(timeout=1.0)
                
                if self._stop_worker:
                    break
                
                # Get work from queue if available
                if self._queue:
                    work_item = self._queue.popleft()
                    self._count += 1
            
            # Execute work outside the lock
            if work_item:
                try:
                    func, result_callback, error_callback = work_item
                    result = func()
                    if result_callback:
                        result_callback(result)
                except Exception as exc:
                    if error_callback:
                        error_callback(exc)
                finally:
                    with self._cond:
                        if self._count > 0:
                            self._count -= 1
                        self._cond.notify_all()
    
    def stop_worker(self) -> None:
        """Stop the background worker thread."""
        with self._cond:
            self._stop_worker = True
            self._cond.notify_all()
    
    def enqueue(self, func, result_callback=None, error_callback=None) -> None:
        """
        Enqueue a work item to be executed when capacity is available.
        
        Args:
            func: Callable to execute (no arguments)
            result_callback: Optional callback for successful result
            error_callback: Optional callback for exceptions
        """
        with self._cond:
            self._queue.append((func, result_callback, error_callback))
            self._cond.notify_all()
    
    def acquire(self) -> None:
        """Acquire a slot (blocking). For backward compatibility."""
        with self._cond:
            while self._count >= self._limit:
                self._cond.wait()
            self._count += 1

    def release(self) -> None:
        """Release a slot. For backward compatibility."""
        with self._cond:
            if self._count > 0:
                self._count -= 1
            self._cond.notify_all()

    def update_limit(self, limit: int) -> None:
        """Update the concurrency limit."""
        with self._cond:
            self._limit = max(1, int(limit))
            self._cond.notify_all()

    def snapshot(self) -> Dict[str, int]:
        """Get current status snapshot."""
        with self._cond:
            return {
                "limit": self._limit,
                "active": self._count,
                "queued": len(self._queue),
            }

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()


TOOL_GATES: Dict[str, ToolGate] = {
    "amass": ToolGate(1),
    "subfinder": ToolGate(1),
    "assetfinder": ToolGate(1),
    "findomain": ToolGate(1),
    "sublist3r": ToolGate(1),
    "crtsh": ToolGate(1),
    "github-subdomains": ToolGate(1),
    "dnsx": ToolGate(1),
    "ffuf": ToolGate(1),
    "httpx": ToolGate(1),
    "waybackurls": ToolGate(1),
    "gau": ToolGate(1),
    "gowitness": ToolGate(1),
    "nuclei": ToolGate(1),
    "nikto": ToolGate(1),
}

# State payload cache for improved performance
STATE_CACHE_LOCK = threading.Lock()
STATE_CACHE: Dict[str, Any] = {
    "etag": None,
    "payload": None,
    "last_updated": None,
}

JOB_QUEUE: deque = deque()
MAX_RUNNING_JOBS = 1
RUNNING_JOBS: Dict[str, Dict[str, Any]] = {}
COMPLETED_JOBS: Dict[str, Dict[str, Any]] = {}  # Store completed job reports
MAX_COMPLETED_JOBS_PER_DOMAIN = 10  # Keep last N completed jobs per domain
JOB_LOCK = threading.Lock()
PIPELINE_STEPS = ["amass", "subfinder", "assetfinder", "findomain", "sublist3r", "crtsh", "github-subdomains", "dnsx", "ffuf", "httpx", "waybackurls", "gau", "screenshots", "nuclei", "nikto"]

# Global rate limiter
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_LAST_CALL = 0.0
GLOBAL_RATE_LIMIT_DELAY = 0.0  # seconds between tool calls (0 = no rate limit)

# Timeout tracking for intelligent rate limit adjustment
TIMEOUT_TRACKER_LOCK = threading.Lock()
TIMEOUT_TRACKER: Dict[str, Dict[str, Any]] = {}  # domain -> {errors: int, last_error_time: float, backoff_delay: float}
TIMEOUT_ERROR_THRESHOLD = 3  # Number of errors before increasing rate limit
TIMEOUT_BACKOFF_INCREMENT = 5.0  # Seconds to add to delay after threshold (increased from 2.0 to back off more aggressively)
MAX_AUTO_BACKOFF_DELAY = 30.0  # Maximum automatic backoff delay

STEP_PROGRESS = {
    "pending": 0,
    "queued": 0,
    "running": 55,
    "completed": 100,
    "skipped": 0,
    "error": 100,
    "failed": 100,
}

# Dynamic queue management
DYNAMIC_MODE_ENABLED = False
DYNAMIC_MODE_LOCK = threading.Lock()
DYNAMIC_MODE_THREAD: Optional[threading.Thread] = None
DYNAMIC_MODE_POLL_INTERVAL = 30  # Check every 30 seconds
DYNAMIC_MODE_BASE_JOBS = 1  # Minimum jobs when dynamic mode is enabled
DYNAMIC_MODE_MAX_JOBS = 10  # Maximum jobs when dynamic mode is enabled
DYNAMIC_MODE_CPU_THRESHOLD = 75.0  # CPU % threshold
DYNAMIC_MODE_MEMORY_THRESHOLD = 80.0  # Memory % threshold

# Auto-backup system
AUTO_BACKUP_ENABLED = False
AUTO_BACKUP_LOCK = threading.Lock()
AUTO_BACKUP_THREAD: Optional[threading.Thread] = None
AUTO_BACKUP_INTERVAL = 3600  # Default: 1 hour in seconds
AUTO_BACKUP_MAX_COUNT = 10  # Keep last 10 backups
LAST_BACKUP_TIME = 0.0


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


def is_rate_limit_error(error: Exception) -> bool:
    """
    Check if an error indicates rate limiting or too many requests.
    """
    error_str = str(error).lower()
    error_type = type(error).__name__.lower()
    
    # Check for HTTP 429 (Too Many Requests) or 503 (Service Unavailable)
    if isinstance(error, HTTPError):
        if error.code in (429, 503):
            return True
    
    # Check for timeout errors
    if "timeout" in error_str or "timed out" in error_str:
        return True
    
    # Check for connection errors that might indicate rate limiting
    if "connection" in error_str and ("refused" in error_str or "reset" in error_str):
        return True
    
    # Check for rate limit keywords in error message
    rate_limit_keywords = ["rate limit", "too many requests", "throttle", "slow down"]
    if any(keyword in error_str for keyword in rate_limit_keywords):
        return True
    
    return False


def track_timeout_error(domain: str, error: Exception, job_domain: Optional[str] = None) -> None:
    """
    Track timeout/rate-limit errors for a domain and automatically adjust rate limiting.
    """
    global GLOBAL_RATE_LIMIT_DELAY
    
    if not is_rate_limit_error(error):
        return
    
    with TIMEOUT_TRACKER_LOCK:
        if domain not in TIMEOUT_TRACKER:
            TIMEOUT_TRACKER[domain] = {
                "errors": 0,
                "last_error_time": 0.0,
                "backoff_delay": 0.0,
            }
        
        tracker = TIMEOUT_TRACKER[domain]
        current_time = time.time()
        
        # Reset counter if last error was more than 5 minutes ago
        if current_time - tracker["last_error_time"] > 300:
            tracker["errors"] = 0
            tracker["backoff_delay"] = 0.0
        
        tracker["errors"] += 1
        tracker["last_error_time"] = current_time
        
        # If we've hit the threshold, increase rate limiting
        if tracker["errors"] >= TIMEOUT_ERROR_THRESHOLD:
            old_delay = GLOBAL_RATE_LIMIT_DELAY
            new_delay = min(old_delay + TIMEOUT_BACKOFF_INCREMENT, MAX_AUTO_BACKOFF_DELAY)
            
            if new_delay > old_delay:
                GLOBAL_RATE_LIMIT_DELAY = new_delay
                tracker["backoff_delay"] = new_delay
                
                log_msg = (
                    f"⚠️  Rate limiting detected for {domain} ({tracker['errors']} errors). "
                    f"Automatically increasing global rate limit from {old_delay:.1f}s to {new_delay:.1f}s. "
                    f"Error: {str(error)[:100]}"
                )
                log(log_msg)
                
                if job_domain:
                    job_log_append(
                        job_domain,
                        f"Rate limiting detected. Slowing down requests (delay now {new_delay:.1f}s)",
                        source="rate-limiter"
                    )
                
                # Reset error counter after adjustment
                tracker["errors"] = 0
            else:
                log_msg = (
                    f"⚠️  Rate limiting detected for {domain} but already at max backoff "
                    f"({GLOBAL_RATE_LIMIT_DELAY:.1f}s). Error: {str(error)[:100]}"
                )
                log(log_msg)
                
                if job_domain:
                    job_log_append(
                        job_domain,
                        f"Rate limiting detected (already at max delay {GLOBAL_RATE_LIMIT_DELAY:.1f}s)",
                        source="rate-limiter"
                    )


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

# System Resource Monitoring
SYSTEM_RESOURCE_LOCK = threading.Lock()
SYSTEM_RESOURCE_STATE: Dict[str, Any] = {}
SYSTEM_RESOURCE_THREAD: Optional[threading.Thread] = None
SYSTEM_RESOURCE_POLL_INTERVAL = 5  # Poll every 5 seconds
SYSTEM_RESOURCE_HISTORY_SIZE = 720  # Keep 1 hour of history at 5-second intervals
SYSTEM_RESOURCE_HISTORY: List[Dict[str, Any]] = []
SYSTEM_RESOURCE_FILE = DATA_DIR / "system_resources.json"


# ================== UTILITIES =======================

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts} UTC] {msg}")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)


# ================== SQLite DATABASE ====================

def get_db() -> sqlite3.Connection:
    """
    Get a thread-safe database connection with performance optimizations.
    
    Optimizations:
    - WAL mode for better concurrency
    - Increased cache size for large datasets
    - Optimized synchronous mode for speed
    """
    global DB_CONN
    with DB_LOCK:
        if DB_CONN is None:
            ensure_dirs()
            # Set isolation_level to None for autocommit mode to prevent
            # "cannot start a transaction within a transaction" errors
            DB_CONN = sqlite3.connect(str(DB_FILE), check_same_thread=False, isolation_level=None)
            DB_CONN.row_factory = sqlite3.Row
            
            # Enable WAL mode for better concurrency
            DB_CONN.execute("PRAGMA journal_mode=WAL")
            DB_CONN.execute("PRAGMA foreign_keys=ON")
            
            # OPTIMIZATION: Performance tuning for large datasets (10,000+ rows)
            # Increase cache size to 64MB (default is ~2MB)
            # This significantly improves query performance with large data
            DB_CONN.execute("PRAGMA cache_size=-64000")  # Negative = KB
            
            # Set synchronous to NORMAL for better performance (WAL makes this safe)
            # FULL is safest but slower, NORMAL is good balance with WAL
            DB_CONN.execute("PRAGMA synchronous=NORMAL")
            
            # Enable memory-mapped I/O for faster reads (256MB mmap)
            DB_CONN.execute("PRAGMA mmap_size=268435456")
            
            # Set temp store to memory for faster operations
            DB_CONN.execute("PRAGMA temp_store=MEMORY")
        return DB_CONN


def init_database() -> None:
    """Initialize the SQLite database schema."""
    db = get_db()
    cursor = db.cursor()
    
    # Config table - stores key-value configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Targets table - stores domain targets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            domain TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            flags TEXT,
            options TEXT,
            comments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Subdomains table - stores subdomain data for each target
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            data TEXT NOT NULL,
            interesting INTEGER,
            comments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(domain, subdomain),
            FOREIGN KEY (domain) REFERENCES targets(domain) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_subdomains_domain 
        ON subdomains(domain)
    """)
    
    # Completed jobs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS completed_jobs (
            job_key TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            data TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_completed_jobs_domain 
        ON completed_jobs(domain)
    """)
    
    # Monitors table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # System resources table - stores resource snapshots
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_system_resources_timestamp 
        ON system_resources(timestamp DESC)
    """)
    
    # History table - stores per-domain event history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_history_domain 
        ON history(domain, timestamp DESC)
    """)
    
    # Migration tracking table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_name TEXT UNIQUE NOT NULL,
            completed_at TEXT NOT NULL
        )
    """)
    
    db.commit()
    log("Database schema initialized successfully.")


def check_migration_done(migration_name: str) -> bool:
    """Check if a migration has already been completed."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT 1 FROM migrations WHERE migration_name = ?",
        (migration_name,)
    )
    return cursor.fetchone() is not None


def mark_migration_done(migration_name: str) -> None:
    """Mark a migration as completed."""
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT OR IGNORE INTO migrations (migration_name, completed_at) VALUES (?, ?)",
        (migration_name, now)
    )
    db.commit()


def migrate_json_to_sqlite() -> None:
    """Migrate all JSON data to SQLite database."""
    log("Starting migration from JSON files to SQLite...")
    
    # Migrate config
    if CONFIG_FILE.exists() and not check_migration_done("config_json"):
        log("Migrating config.json...")
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for key, value in config_data.items():
                cursor.execute(
                    "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), now)
                )
            
            db.commit()
            mark_migration_done("config_json")
            log("✓ Config migration completed.")
        except Exception as e:
            log(f"Error migrating config.json: {e}")
    
    # Migrate state (targets and subdomains)
    if STATE_FILE.exists() and not check_migration_done("state_json"):
        log("Migrating state.json...")
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state_data = json.load(f)
            
            targets = state_data.get("targets", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for domain, target_data in targets.items():
                subdomains = target_data.get("subdomains", {})
                flags = target_data.get("flags", {})
                options = target_data.get("options", {})
                
                # Insert target
                cursor.execute(
                    """INSERT OR REPLACE INTO targets 
                       (domain, data, flags, options, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (domain, "{}", json.dumps(flags), json.dumps(options), now, now)
                )
                
                # Insert subdomains
                for subdomain, sub_data in subdomains.items():
                    cursor.execute(
                        """INSERT OR REPLACE INTO subdomains 
                           (domain, subdomain, data, created_at, updated_at) 
                           VALUES (?, ?, ?, ?, ?)""",
                        (domain, subdomain, json.dumps(sub_data), now, now)
                    )
            
            db.commit()
            mark_migration_done("state_json")
            log(f"✓ State migration completed ({len(targets)} targets).")
        except Exception as e:
            log(f"Error migrating state.json: {e}")
    
    # Migrate completed jobs
    if COMPLETED_JOBS_FILE.exists() and not check_migration_done("completed_jobs_json"):
        log("Migrating completed_jobs.json...")
        try:
            with open(COMPLETED_JOBS_FILE, "r", encoding="utf-8") as f:
                jobs_data = json.load(f)
            
            jobs = jobs_data.get("jobs", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for job_key, job_data in jobs.items():
                domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
                completed_at = job_data.get("completed_at", now)
                
                cursor.execute(
                    """INSERT OR REPLACE INTO completed_jobs 
                       (job_key, domain, data, completed_at, created_at) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (job_key, domain, json.dumps(job_data), completed_at, now)
                )
            
            db.commit()
            mark_migration_done("completed_jobs_json")
            log(f"✓ Completed jobs migration completed ({len(jobs)} jobs).")
        except Exception as e:
            log(f"Error migrating completed_jobs.json: {e}")
    
    # Migrate monitors
    if MONITORS_FILE.exists() and not check_migration_done("monitors_json"):
        log("Migrating monitors.json...")
        try:
            with open(MONITORS_FILE, "r", encoding="utf-8") as f:
                monitors_data = json.load(f)
            
            monitors = monitors_data.get("monitors", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for monitor_id, monitor_data in monitors.items():
                name = monitor_data.get("name", "")
                url = monitor_data.get("url", "")
                created_at = monitor_data.get("created_at", now)
                
                cursor.execute(
                    """INSERT OR REPLACE INTO monitors 
                       (id, name, url, data, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (monitor_id, name, url, json.dumps(monitor_data), created_at, now)
                )
            
            db.commit()
            mark_migration_done("monitors_json")
            log(f"✓ Monitors migration completed ({len(monitors)} monitors).")
        except Exception as e:
            log(f"Error migrating monitors.json: {e}")
    
    # Migrate history files
    if HISTORY_DIR.exists() and not check_migration_done("history_jsonl"):
        log("Migrating history/*.jsonl files...")
        try:
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            total_entries = 0
            
            for history_file in HISTORY_DIR.glob("*.jsonl"):
                domain = history_file.stem
                
                with history_file.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            timestamp = entry.get("ts", now)
                            source = entry.get("source", "system")
                            text = entry.get("text", "")
                            
                            cursor.execute(
                                """INSERT INTO history 
                                   (domain, timestamp, source, text, created_at) 
                                   VALUES (?, ?, ?, ?, ?)""",
                                (domain, timestamp, source, text, now)
                            )
                            total_entries += 1
                        except json.JSONDecodeError:
                            continue
            
            db.commit()
            mark_migration_done("history_jsonl")
            log(f"✓ History migration completed ({total_entries} entries).")
        except Exception as e:
            log(f"Error migrating history files: {e}")
    
    log("Migration from JSON to SQLite completed successfully!")


def run_schema_migrations() -> None:
    """Run schema migrations to add new columns to existing tables."""
    db = get_db()
    cursor = db.cursor()
    
    # Migration: Add interesting and comments columns to subdomains table
    if not check_migration_done("add_subdomain_interesting_comments"):
        log("Running migration: add_subdomain_interesting_comments")
        try:
            # Check if columns already exist
            cursor.execute("PRAGMA table_info(subdomains)")
            columns = {row[1] for row in cursor.fetchall()}
            
            if "interesting" not in columns:
                cursor.execute("ALTER TABLE subdomains ADD COLUMN interesting INTEGER")
                log("  ✓ Added 'interesting' column to subdomains table")
            
            if "comments" not in columns:
                cursor.execute("ALTER TABLE subdomains ADD COLUMN comments TEXT")
                log("  ✓ Added 'comments' column to subdomains table")
            
            db.commit()
            mark_migration_done("add_subdomain_interesting_comments")
            log("✓ Migration add_subdomain_interesting_comments completed")
        except Exception as e:
            log(f"Error in migration add_subdomain_interesting_comments: {e}")
    
    # Migration: Add comments column to targets table
    if not check_migration_done("add_target_comments"):
        log("Running migration: add_target_comments")
        try:
            cursor.execute("PRAGMA table_info(targets)")
            columns = {row[1] for row in cursor.fetchall()}
            
            if "comments" not in columns:
                cursor.execute("ALTER TABLE targets ADD COLUMN comments TEXT")
                log("  ✓ Added 'comments' column to targets table")
            
            db.commit()
            mark_migration_done("add_target_comments")
            log("✓ Migration add_target_comments completed")
        except Exception as e:
            log(f"Error in migration add_target_comments: {e}")
    
    # Migration: Add performance indexes for summary queries
    if not check_migration_done("add_performance_indexes"):
        log("Running migration: add_performance_indexes")
        try:
            # Index for filtering subdomains by interesting flag
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_subdomains_domain_interesting 
                ON subdomains(domain, interesting) WHERE interesting IS NOT NULL
            """)
            log("  ✓ Added index on subdomains(domain, interesting)")
            
            # Index for targets updated_at for last_updated queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_targets_updated_at 
                ON targets(updated_at DESC)
            """)
            log("  ✓ Added index on targets(updated_at)")
            
            db.commit()
            mark_migration_done("add_performance_indexes")
            log("✓ Migration add_performance_indexes completed")
        except Exception as e:
            log(f"Error in migration add_performance_indexes: {e}")
    
    # Migration: Add additional indexes for JOIN optimization and large dataset handling
    if not check_migration_done("add_join_optimization_indexes"):
        log("Running migration: add_join_optimization_indexes")
        try:
            # Composite index for subdomains JOIN - covers domain lookup
            # This is critical for the optimized JOIN queries in load_state() and build_state_payload_summary()
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_subdomains_domain_subdomain 
                ON subdomains(domain, subdomain)
            """)
            log("  ✓ Added composite index on subdomains(domain, subdomain)")
            
            # Index for completed_jobs domain lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_completed_jobs_domain_completed 
                ON completed_jobs(domain, completed_at DESC)
            """)
            log("  ✓ Added index on completed_jobs(domain, completed_at)")
            
            # Index for history timestamp ordering (for paginated queries)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_domain_timestamp 
                ON history(domain, timestamp DESC)
            """)
            log("  ✓ Added index on history(domain, timestamp)")
            
            db.commit()
            mark_migration_done("add_join_optimization_indexes")
            log("✓ Migration add_join_optimization_indexes completed")
        except Exception as e:
            log(f"Error in migration add_join_optimization_indexes: {e}")



def ensure_database() -> None:
    """Ensure database is initialized and migrated."""
    init_database()
    migrate_json_to_sqlite()
    run_schema_migrations()


def atomic_write_json(filepath: Path, data: Dict[str, Any], indent: int = 2) -> None:
    """
    Atomically write JSON data to a file using a temporary file.
    This prevents corruption if the process crashes during write.
    Includes proper error handling for race conditions and filesystem issues.
    """
    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Create temp file in same directory to ensure same filesystem
    # This is important for atomic rename to work properly
    tmp_path = filepath.with_suffix(f".tmp.{os.getpid()}")
    
    try:
        # Write data to temporary file
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, sort_keys=True)
            # Sync to disk (flush OS buffers) while file is still open
            # This ensures data is written before rename
            try:
                f.flush()
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                # fsync may not be supported on all platforms/filesystems
                pass
        
        # Atomic rename - this is the critical operation
        # On most systems, this is atomic if both files are on same filesystem
        try:
            tmp_path.replace(filepath)
        except OSError as e:
            # If replace fails, try alternative methods
            log(f"Warning: atomic replace failed for {filepath}: {e}. Trying fallback...")
            
            # Try direct rename (less safe but may work)
            if filepath.exists():
                backup_path = filepath.with_suffix(".backup")
                try:
                    shutil.copy2(filepath, backup_path)
                except Exception:
                    pass
            
            shutil.move(str(tmp_path), str(filepath))
    
    except Exception as e:
        # Clean up temp file on any error
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise RuntimeError(f"Failed to write {filepath}: {e}") from e
    
    finally:
        # Ensure temp file is cleaned up even if something went wrong
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                # Don't fail if cleanup fails
                pass


def atomic_write_text(filepath: Path, content: str) -> None:
    """
    Atomically write text content to a file using a temporary file.
    Similar to atomic_write_json but for text files.
    """
    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Create temp file in same directory to ensure same filesystem
    tmp_path = filepath.with_suffix(f".tmp.{os.getpid()}")
    
    try:
        # Write content to temporary file
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            # Sync to disk while file is still open
            try:
                f.flush()
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        
        # Atomic rename
        try:
            tmp_path.replace(filepath)
        except OSError as e:
            log(f"Warning: atomic replace failed for {filepath}: {e}. Trying fallback...")
            if filepath.exists():
                backup_path = filepath.with_suffix(".backup")
                try:
                    shutil.copy2(filepath, backup_path)
                except Exception:
                    pass
            shutil.move(str(tmp_path), str(filepath))
    
    except Exception as e:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise RuntimeError(f"Failed to write {filepath}: {e}") from e
    
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


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
    global MAX_RUNNING_JOBS, GLOBAL_RATE_LIMIT_DELAY, DYNAMIC_MODE_ENABLED
    global DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS, DYNAMIC_MODE_CPU_THRESHOLD, DYNAMIC_MODE_MEMORY_THRESHOLD
    global AUTO_BACKUP_ENABLED, AUTO_BACKUP_INTERVAL, AUTO_BACKUP_MAX_COUNT
    global AUTO_CLEANUP_ENABLED, CLEANUP_SCAN_RESULTS_DAYS, CLEANUP_TEMP_FILES_HOURS, CLEANUP_INTERVAL
    
    # Apply dynamic mode settings
    try:
        DYNAMIC_MODE_ENABLED = bool(cfg.get("dynamic_mode_enabled", False))
        DYNAMIC_MODE_BASE_JOBS = max(1, int(cfg.get("dynamic_mode_base_jobs", 1)))
        DYNAMIC_MODE_MAX_JOBS = max(DYNAMIC_MODE_BASE_JOBS, int(cfg.get("dynamic_mode_max_jobs", 10)))
        DYNAMIC_MODE_CPU_THRESHOLD = max(0.0, min(100.0, float(cfg.get("dynamic_mode_cpu_threshold", 75.0))))
        DYNAMIC_MODE_MEMORY_THRESHOLD = max(0.0, min(100.0, float(cfg.get("dynamic_mode_memory_threshold", 80.0))))
    except (TypeError, ValueError):
        DYNAMIC_MODE_ENABLED = False
        DYNAMIC_MODE_BASE_JOBS = 1
        DYNAMIC_MODE_MAX_JOBS = 10
        DYNAMIC_MODE_CPU_THRESHOLD = 75.0
        DYNAMIC_MODE_MEMORY_THRESHOLD = 80.0
    
    # Apply auto-backup settings
    try:
        AUTO_BACKUP_ENABLED = bool(cfg.get("auto_backup_enabled", False))
        AUTO_BACKUP_INTERVAL = max(300, int(cfg.get("auto_backup_interval", 3600)))  # Min 5 minutes
        AUTO_BACKUP_MAX_COUNT = max(1, int(cfg.get("auto_backup_max_count", 10)))
    except (TypeError, ValueError):
        AUTO_BACKUP_ENABLED = False
        AUTO_BACKUP_INTERVAL = 3600
        AUTO_BACKUP_MAX_COUNT = 10
    
    # Apply auto-cleanup settings
    try:
        AUTO_CLEANUP_ENABLED = bool(cfg.get("auto_cleanup_enabled", True))
        CLEANUP_SCAN_RESULTS_DAYS = max(1, int(cfg.get("cleanup_scan_results_days", 30)))
        CLEANUP_TEMP_FILES_HOURS = max(1, int(cfg.get("cleanup_temp_files_hours", 24)))
        CLEANUP_INTERVAL = max(300, int(cfg.get("cleanup_interval", 3600)))  # Min 5 minutes
    except (TypeError, ValueError):
        AUTO_CLEANUP_ENABLED = True
        CLEANUP_SCAN_RESULTS_DAYS = 30
        CLEANUP_TEMP_FILES_HOURS = 24
        CLEANUP_INTERVAL = 3600
    
    # Start or stop dynamic mode worker based on config
    if DYNAMIC_MODE_ENABLED and PSUTIL_AVAILABLE:
        start_dynamic_mode_worker()
    else:
        stop_dynamic_mode_worker()
    
    # Start or stop auto-backup worker based on config
    if AUTO_BACKUP_ENABLED:
        start_auto_backup_worker()
    else:
        stop_auto_backup_worker()
    
    # Start or stop auto-cleanup worker based on config
    if AUTO_CLEANUP_ENABLED:
        start_cleanup_worker()
    else:
        stop_cleanup_worker()
    
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
        "amass": "max_parallel_amass",
        "subfinder": "max_parallel_subfinder",
        "assetfinder": "max_parallel_assetfinder",
        "findomain": "max_parallel_findomain",
        "sublist3r": "max_parallel_sublist3r",
        "crtsh": "max_parallel_crtsh",
        "github-subdomains": "max_parallel_github_subdomains",
        "dnsx": "max_parallel_dnsx",
        "ffuf": "max_parallel_ffuf",
        "httpx": "max_parallel_httpx",
        "waybackurls": "max_parallel_waybackurls",
        "gau": "max_parallel_gau",
        "gowitness": "max_parallel_gowitness",
        "nuclei": "max_parallel_nuclei",
        "nikto": "max_parallel_nikto",
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
        "max_parallel_amass": 1,
        "max_parallel_subfinder": 1,
        "max_parallel_assetfinder": 1,
        "max_parallel_findomain": 1,
        "max_parallel_sublist3r": 1,
        "max_parallel_crtsh": 1,
        "max_parallel_github_subdomains": 1,
        "max_parallel_dnsx": 1,
        "max_parallel_ffuf": 1,
        "max_parallel_httpx": 1,
        "max_parallel_waybackurls": 1,
        "max_parallel_gau": 1,
        "max_parallel_gowitness": 1,
        "max_parallel_nuclei": 1,
        "max_parallel_nikto": 1,
        "max_running_jobs": 1,
        "global_rate_limit": 0.0,
        "tool_flag_templates": {name: "" for name in TEMPLATE_AWARE_TOOLS},
        "tool_binary_paths": {},  # Custom binary paths for tools
        "dynamic_mode_enabled": False,
        "dynamic_mode_base_jobs": 1,
        "dynamic_mode_max_jobs": 10,
        "dynamic_mode_cpu_threshold": 75.0,
        "dynamic_mode_memory_threshold": 80.0,
        "auto_backup_enabled": False,
        "auto_backup_interval": 3600,
        "auto_backup_max_count": 10,
        "auto_cleanup_enabled": True,
        "cleanup_scan_results_days": 30,
        "cleanup_temp_files_hours": 24,
        "cleanup_interval": 3600,
        "screenshots_per_page": 20,
        "setup_completed": False,
    }


# ================== MONITOR MANAGEMENT ==================


def load_monitors_state() -> Dict[str, Any]:
    """Load monitors from SQLite database."""
    ensure_dirs()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, data FROM monitors")
    rows = cursor.fetchall()
    
    monitors = {}
    for row in rows:
        monitor_id = row[0]
        try:
            monitor_data = json.loads(row[1])
            monitors[monitor_id] = monitor_data
        except json.JSONDecodeError:
            pass
    
    with MONITOR_LOCK:
        MONITOR_STATE.clear()
        MONITOR_STATE.update(monitors)
    return get_monitors_snapshot()


def _save_monitors_locked() -> None:
    """Save monitors to SQLite database (must be called with MONITOR_LOCK held)."""
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    for monitor_id, monitor_data in MONITOR_STATE.items():
        name = monitor_data.get("name", "")
        url = monitor_data.get("url", "")
        created_at = monitor_data.get("created_at", now)
        
        cursor.execute(
            """INSERT OR REPLACE INTO monitors 
               (id, name, url, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (monitor_id, name, url, json.dumps(monitor_data), created_at, now)
        )
    
    db.commit()


def save_monitors_state() -> None:
    """Save monitors to SQLite database."""
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
        # Track timeout/rate-limit errors for monitors
        track_timeout_error(url, exc, None)
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


# ================== SYSTEM RESOURCE MONITORING ==================


def collect_system_resources() -> Dict[str, Any]:
    """
    Collect current system resource metrics.
    Returns comprehensive data about CPU, memory, disk, network, and process usage.
    """
    if not PSUTIL_AVAILABLE:
        return {
            "available": False,
            "error": "psutil not installed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    try:
        # Basic system info
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_count_physical = psutil.cpu_count(logical=False)
        
        # CPU metrics (use interval=None for non-blocking measurement based on previous call)
        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_freq = psutil.cpu_freq()
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
        
        # Memory metrics
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network metrics
        net_io = psutil.net_io_counters()
        
        # Process metrics - get current process and its children
        current_process = psutil.Process()
        try:
            children = current_process.children(recursive=True)
            process_count = 1 + len(children)
            
            # Sum up resources for main process and children (use interval=None)
            total_process_cpu = current_process.cpu_percent(interval=None)
            total_process_mem = current_process.memory_info().rss
            total_process_threads = current_process.num_threads()
            
            for child in children:
                try:
                    total_process_cpu += child.cpu_percent(interval=None)
                    total_process_mem += child.memory_info().rss
                    total_process_threads += child.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_count = 1
            total_process_cpu = current_process.cpu_percent(interval=None)
            total_process_mem = current_process.memory_info().rss
            total_process_threads = current_process.num_threads()
        
        return {
            "available": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu": {
                "percent": round(cpu_percent, 2),
                "per_core": [round(p, 2) for p in cpu_per_core],
                "count_logical": cpu_count_logical,
                "count_physical": cpu_count_physical,
                "frequency_mhz": round(cpu_freq.current, 2) if cpu_freq else None,
                "load_avg_1m": round(load_avg[0], 2),
                "load_avg_5m": round(load_avg[1], 2),
                "load_avg_15m": round(load_avg[2], 2),
            },
            "memory": {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "used_bytes": mem.used,
                "percent": round(mem.percent, 2),
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
            },
            "swap": {
                "total_bytes": swap.total,
                "used_bytes": swap.used,
                "free_bytes": swap.free,
                "percent": round(swap.percent, 2),
                "total_gb": round(swap.total / (1024**3), 2),
                "used_gb": round(swap.used / (1024**3), 2),
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "percent": round(disk.percent, 2),
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0,
                "read_count": disk_io.read_count if disk_io else 0,
                "write_count": disk_io.write_count if disk_io else 0,
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errin": net_io.errin,
                "errout": net_io.errout,
                "dropin": net_io.dropin,
                "dropout": net_io.dropout,
            },
            "process": {
                "count": process_count,
                "cpu_percent": round(total_process_cpu, 2),
                "memory_bytes": total_process_mem,
                "memory_mb": round(total_process_mem / (1024**2), 2),
                "threads": total_process_threads,
                "pid": current_process.pid,
            }
        }
    except Exception as exc:
        log(f"Error collecting system resources: {exc}")
        return {
            "available": False,
            "error": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def check_resource_thresholds(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check if resource usage exceeds safe thresholds and return warnings.
    """
    warnings = []
    
    if not metrics.get("available"):
        return warnings
    
    # CPU thresholds
    cpu_percent = metrics.get("cpu", {}).get("percent", 0)
    if cpu_percent > 90:
        warnings.append({
            "severity": "critical",
            "resource": "cpu",
            "message": f"CPU usage critically high at {cpu_percent}%",
            "value": cpu_percent,
            "threshold": 90
        })
    elif cpu_percent > 75:
        warnings.append({
            "severity": "warning",
            "resource": "cpu",
            "message": f"CPU usage high at {cpu_percent}%",
            "value": cpu_percent,
            "threshold": 75
        })
    
    # Memory thresholds
    mem_percent = metrics.get("memory", {}).get("percent", 0)
    if mem_percent > 90:
        warnings.append({
            "severity": "critical",
            "resource": "memory",
            "message": f"Memory usage critically high at {mem_percent}%",
            "value": mem_percent,
            "threshold": 90
        })
    elif mem_percent > 80:
        warnings.append({
            "severity": "warning",
            "resource": "memory",
            "message": f"Memory usage high at {mem_percent}%",
            "value": mem_percent,
            "threshold": 80
        })
    
    # Disk thresholds
    disk_percent = metrics.get("disk", {}).get("percent", 0)
    if disk_percent > 95:
        warnings.append({
            "severity": "critical",
            "resource": "disk",
            "message": f"Disk usage critically high at {disk_percent}%",
            "value": disk_percent,
            "threshold": 95
        })
    elif disk_percent > 85:
        warnings.append({
            "severity": "warning",
            "resource": "disk",
            "message": f"Disk usage high at {disk_percent}%",
            "value": disk_percent,
            "threshold": 85
        })
    
    # Swap usage warning
    swap_percent = metrics.get("swap", {}).get("percent", 0)
    if swap_percent > 50:
        warnings.append({
            "severity": "warning",
            "resource": "swap",
            "message": f"Swap usage at {swap_percent}%, system may be under memory pressure",
            "value": swap_percent,
            "threshold": 50
        })
    
    return warnings


def save_system_resource_state() -> None:
    """Save current system resource state and history to SQLite database."""
    ensure_dirs()
    with SYSTEM_RESOURCE_LOCK:
        # Save only recent history entries to database
        history_to_save = SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]
        
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # Insert new history entries
        for entry in history_to_save:
            timestamp = entry.get("timestamp", now)
            cursor.execute(
                """INSERT INTO system_resources (timestamp, data, created_at) 
                   VALUES (?, ?, ?)""",
                (timestamp, json.dumps(entry), now)
            )
        
        # Clean up old entries (keep only the most recent SYSTEM_RESOURCE_HISTORY_SIZE * 2 entries)
        cursor.execute(
            """DELETE FROM system_resources 
               WHERE id NOT IN (
                   SELECT id FROM system_resources 
                   ORDER BY timestamp DESC 
                   LIMIT ?
               )""",
            (SYSTEM_RESOURCE_HISTORY_SIZE * 2,)
        )
        
        db.commit()


def load_system_resource_state() -> Dict[str, Any]:
    """Load system resource state from SQLite database."""
    global SYSTEM_RESOURCE_HISTORY
    ensure_dirs()
    
    db = get_db()
    cursor = db.cursor()
    
    # Load recent history
    cursor.execute(
        """SELECT data FROM system_resources 
           ORDER BY timestamp DESC 
           LIMIT ?""",
        (SYSTEM_RESOURCE_HISTORY_SIZE,)
    )
    rows = cursor.fetchall()
    
    history = []
    for row in rows:
        try:
            entry = json.loads(row[0])
            history.append(entry)
        except json.JSONDecodeError:
            pass
    
    # Reverse to get chronological order
    history.reverse()
    
    with SYSTEM_RESOURCE_LOCK:
        SYSTEM_RESOURCE_STATE.clear()
        # Current state is the most recent entry if available
        if history:
            SYSTEM_RESOURCE_STATE.update(history[-1])
        SYSTEM_RESOURCE_HISTORY.clear()
        SYSTEM_RESOURCE_HISTORY.extend(history)
    
    return get_system_resource_snapshot()


def get_system_resource_snapshot() -> Dict[str, Any]:
    """Get a snapshot of current system resources and history."""
    with SYSTEM_RESOURCE_LOCK:
        return {
            "current": copy.deepcopy(SYSTEM_RESOURCE_STATE),
            "history": copy.deepcopy(SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]),
        }


def system_resource_worker_loop() -> None:
    """Background worker that continuously monitors system resources."""
    log("System resource monitoring worker started.")
    
    last_save_time = time.time()
    save_interval = 60  # Save every 60 seconds
    
    while True:
        try:
            # Collect current metrics
            metrics = collect_system_resources()
            
            # Check for threshold warnings
            warnings = check_resource_thresholds(metrics)
            metrics["warnings"] = warnings
            
            # Log critical warnings
            for warning in warnings:
                if warning["severity"] == "critical":
                    log(f"⚠️  RESOURCE WARNING: {warning['message']}")
            
            # Update state
            with SYSTEM_RESOURCE_LOCK:
                SYSTEM_RESOURCE_STATE.clear()
                SYSTEM_RESOURCE_STATE.update(metrics)
                
                # Add to history
                history_entry = {
                    "timestamp": metrics["timestamp"],
                    "cpu_percent": metrics.get("cpu", {}).get("percent", 0),
                    "memory_percent": metrics.get("memory", {}).get("percent", 0),
                    "disk_percent": metrics.get("disk", {}).get("percent", 0),
                    "process_cpu_percent": metrics.get("process", {}).get("cpu_percent", 0),
                    "process_memory_mb": metrics.get("process", {}).get("memory_mb", 0),
                    "warnings_count": len(warnings),
                }
                SYSTEM_RESOURCE_HISTORY.append(history_entry)
                
                # Trim history to max size
                if len(SYSTEM_RESOURCE_HISTORY) > SYSTEM_RESOURCE_HISTORY_SIZE:
                    SYSTEM_RESOURCE_HISTORY[:] = SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]
            
            # Save state periodically using timestamp-based approach
            current_time = time.time()
            if current_time - last_save_time >= save_interval:
                try:
                    save_system_resource_state()
                    last_save_time = current_time
                except Exception as exc:
                    log(f"Error saving system resource state: {exc}")
            
        except Exception as exc:
            log(f"Error in system resource monitoring: {exc}")
        
        time.sleep(SYSTEM_RESOURCE_POLL_INTERVAL)


def start_system_resource_worker() -> None:
    """Start the system resource monitoring worker thread."""
    global SYSTEM_RESOURCE_THREAD
    
    if not PSUTIL_AVAILABLE:
        log("System resource monitoring disabled: psutil not available")
        return
    
    with SYSTEM_RESOURCE_LOCK:
        already_running = SYSTEM_RESOURCE_THREAD and SYSTEM_RESOURCE_THREAD.is_alive()
    
    if already_running:
        return
    
    load_system_resource_state()
    thread = threading.Thread(target=system_resource_worker_loop, name="resource-monitor", daemon=True)
    thread.start()
    
    with SYSTEM_RESOURCE_LOCK:
        SYSTEM_RESOURCE_THREAD = thread
    
    log("System resource monitoring worker initialized.")


# ================== DYNAMIC MODE MANAGEMENT ==================


def calculate_optimal_jobs() -> int:
    """
    Calculate the optimal number of concurrent jobs based on system resources.
    Returns the recommended number of jobs to run.
    """
    if not PSUTIL_AVAILABLE:
        return DYNAMIC_MODE_BASE_JOBS
    
    try:
        metrics = collect_system_resources()
        if not metrics.get("available"):
            return DYNAMIC_MODE_BASE_JOBS
        
        cpu_percent = metrics.get("cpu", {}).get("percent", 0)
        memory_percent = metrics.get("memory", {}).get("percent", 0)
        load_avg_1m = metrics.get("cpu", {}).get("load_avg_1m", 0)
        cpu_count = metrics.get("cpu", {}).get("count_logical", 1)
        
        # Start with max jobs
        recommended_jobs = DYNAMIC_MODE_MAX_JOBS
        
        # Reduce if CPU is high
        if cpu_percent > DYNAMIC_MODE_CPU_THRESHOLD:
            # Scale down based on how much we're over threshold
            # Avoid division by zero when threshold is 100%
            denominator = max(1.0, 100 - DYNAMIC_MODE_CPU_THRESHOLD)
            overage = (cpu_percent - DYNAMIC_MODE_CPU_THRESHOLD) / denominator
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * overage)
            recommended_jobs = max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction)
        
        # Reduce if memory is high
        if memory_percent > DYNAMIC_MODE_MEMORY_THRESHOLD:
            # Avoid division by zero when threshold is 100%
            denominator = max(1.0, 100 - DYNAMIC_MODE_MEMORY_THRESHOLD)
            overage = (memory_percent - DYNAMIC_MODE_MEMORY_THRESHOLD) / denominator
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * overage)
            recommended_jobs = min(recommended_jobs, max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction))
        
        # Reduce if load average is high (more than 1.5x CPU count)
        if load_avg_1m > cpu_count * 1.5:
            overage = (load_avg_1m - cpu_count * 1.5) / (cpu_count * 1.5)
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * min(overage, 1.0))
            recommended_jobs = min(recommended_jobs, max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction))
        
        return max(DYNAMIC_MODE_BASE_JOBS, min(DYNAMIC_MODE_MAX_JOBS, recommended_jobs))
    except Exception as exc:
        log(f"Error calculating optimal jobs: {exc}")
        return DYNAMIC_MODE_BASE_JOBS


def dynamic_mode_worker_loop() -> None:
    """Background worker that continuously adjusts MAX_RUNNING_JOBS based on system resources."""
    global MAX_RUNNING_JOBS
    
    log("Dynamic mode worker started.")
    last_jobs = MAX_RUNNING_JOBS
    
    while True:
        try:
            if not DYNAMIC_MODE_ENABLED:
                time.sleep(DYNAMIC_MODE_POLL_INTERVAL)
                continue
            
            # Calculate optimal job count
            optimal_jobs = calculate_optimal_jobs()
            
            # Only update if changed
            if optimal_jobs != last_jobs:
                with DYNAMIC_MODE_LOCK:
                    old_value = MAX_RUNNING_JOBS
                    MAX_RUNNING_JOBS = optimal_jobs
                    last_jobs = optimal_jobs
                
                log(f"🔄 Dynamic mode adjusted: {old_value} → {optimal_jobs} concurrent jobs")
                
                # Trigger job scheduling to take advantage of new capacity
                schedule_jobs()
        except Exception as exc:
            log(f"Error in dynamic mode worker: {exc}")
        
        time.sleep(DYNAMIC_MODE_POLL_INTERVAL)


def start_dynamic_mode_worker() -> None:
    """Start the dynamic mode worker thread."""
    global DYNAMIC_MODE_THREAD
    
    if not PSUTIL_AVAILABLE:
        log("Dynamic mode disabled: psutil not available")
        return
    
    with DYNAMIC_MODE_LOCK:
        already_running = DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive()
    
    if already_running:
        return
    
    thread = threading.Thread(target=dynamic_mode_worker_loop, name="dynamic-mode", daemon=True)
    thread.start()
    
    with DYNAMIC_MODE_LOCK:
        DYNAMIC_MODE_THREAD = thread
    
    log("Dynamic mode worker initialized.")


def stop_dynamic_mode_worker() -> None:
    """Stop the dynamic mode worker thread."""
    global DYNAMIC_MODE_THREAD
    
    with DYNAMIC_MODE_LOCK:
        if DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive():
            # Thread will stop on next iteration when it checks DYNAMIC_MODE_ENABLED
            DYNAMIC_MODE_THREAD = None
            log("Dynamic mode worker stopped.")


def get_dynamic_mode_status() -> Dict[str, Any]:
    """Get current dynamic mode status."""
    with DYNAMIC_MODE_LOCK:
        return {
            "enabled": DYNAMIC_MODE_ENABLED,
            "base_jobs": DYNAMIC_MODE_BASE_JOBS,
            "max_jobs": DYNAMIC_MODE_MAX_JOBS,
            "current_jobs": MAX_RUNNING_JOBS,
            "cpu_threshold": DYNAMIC_MODE_CPU_THRESHOLD,
            "memory_threshold": DYNAMIC_MODE_MEMORY_THRESHOLD,
            "worker_active": DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive() if DYNAMIC_MODE_THREAD else False,
        }


# ================== BACKUP & RESTORE SYSTEM ==================


def create_backup(name: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Create a full backup of all recon data.
    Returns (success, message, backup_filename)
    """
    try:
        ensure_dirs()
        
        # Generate backup filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if name:
            backup_name = f"backup_{name}_{timestamp}.tar.gz"
        else:
            backup_name = f"backup_{timestamp}.tar.gz"
        
        backup_path = BACKUPS_DIR / backup_name
        
        # Create tarball
        with tarfile.open(backup_path, "w:gz") as tar:
            # Add state file
            if STATE_FILE.exists():
                tar.add(STATE_FILE, arcname="state.json")
            
            # Add config file
            if CONFIG_FILE.exists():
                tar.add(CONFIG_FILE, arcname="config.json")
            
            # Add monitors file
            if MONITORS_FILE.exists():
                tar.add(MONITORS_FILE, arcname="monitors.json")
            
            # Add system resources file
            if SYSTEM_RESOURCE_FILE.exists():
                tar.add(SYSTEM_RESOURCE_FILE, arcname="system_resources.json")
            
            # Add completed jobs file
            if COMPLETED_JOBS_FILE.exists():
                tar.add(COMPLETED_JOBS_FILE, arcname="completed_jobs.json")
            
            # Add history directory
            if HISTORY_DIR.exists():
                tar.add(HISTORY_DIR, arcname="history")
            
            # Add screenshots directory (if not too large)
            if SCREENSHOTS_DIR.exists():
                tar.add(SCREENSHOTS_DIR, arcname="screenshots")
        
        backup_size = backup_path.stat().st_size
        size_mb = backup_size / (1024 * 1024)
        
        log(f"✅ Backup created: {backup_name} ({size_mb:.2f} MB)")
        return True, f"Backup created successfully: {backup_name} ({size_mb:.2f} MB)", backup_name
    except Exception as exc:
        log(f"❌ Backup creation failed: {exc}")
        return False, f"Backup failed: {str(exc)}", None


def restore_backup(backup_filename: str) -> Tuple[bool, str]:
    """
    Restore data from a backup file.
    Returns (success, message)
    """
    try:
        backup_path = BACKUPS_DIR / backup_filename
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_filename}"
        
        # Create temporary restore directory
        temp_restore = DATA_DIR / ".restore_temp"
        temp_restore.mkdir(exist_ok=True)
        
        # Extract backup
        with tarfile.open(backup_path, "r:gz") as tar:
            tar.extractall(temp_restore)
        
        # Acquire lock before restoring
        acquire_lock()
        try:
            # Restore files
            restored_files = []
            
            if (temp_restore / "state.json").exists():
                shutil.copy2(temp_restore / "state.json", STATE_FILE)
                restored_files.append("state.json")
            
            if (temp_restore / "config.json").exists():
                shutil.copy2(temp_restore / "config.json", CONFIG_FILE)
                restored_files.append("config.json")
            
            if (temp_restore / "monitors.json").exists():
                shutil.copy2(temp_restore / "monitors.json", MONITORS_FILE)
                restored_files.append("monitors.json")
            
            if (temp_restore / "system_resources.json").exists():
                shutil.copy2(temp_restore / "system_resources.json", SYSTEM_RESOURCE_FILE)
                restored_files.append("system_resources.json")
            
            if (temp_restore / "completed_jobs.json").exists():
                shutil.copy2(temp_restore / "completed_jobs.json", COMPLETED_JOBS_FILE)
                restored_files.append("completed_jobs.json")
            
            if (temp_restore / "history").exists():
                if HISTORY_DIR.exists():
                    shutil.rmtree(HISTORY_DIR)
                shutil.copytree(temp_restore / "history", HISTORY_DIR)
                restored_files.append("history/")
            
            if (temp_restore / "screenshots").exists():
                if SCREENSHOTS_DIR.exists():
                    shutil.rmtree(SCREENSHOTS_DIR)
                shutil.copytree(temp_restore / "screenshots", SCREENSHOTS_DIR)
                restored_files.append("screenshots/")
        finally:
            release_lock()
        
        # Clean up temp directory
        shutil.rmtree(temp_restore, ignore_errors=True)
        
        # Reload configuration
        load_config()
        load_monitors_state()
        load_system_resource_state()
        
        # Reload completed jobs
        global COMPLETED_JOBS
        loaded_jobs = load_completed_jobs()
        with JOB_LOCK:
            COMPLETED_JOBS.clear()
            COMPLETED_JOBS.update(loaded_jobs)
        
        log(f"✅ Backup restored: {backup_filename} ({len(restored_files)} items)")
        return True, f"Backup restored successfully: {', '.join(restored_files)}"
    except Exception as exc:
        log(f"❌ Backup restoration failed: {exc}")
        return False, f"Restore failed: {str(exc)}"


def list_backups() -> List[Dict[str, Any]]:
    """List all available backups."""
    try:
        ensure_dirs()
        backups = []
        
        for backup_file in sorted(BACKUPS_DIR.glob("backup_*.tar.gz"), reverse=True):
            try:
                stat = backup_file.stat()
                backups.append({
                    "filename": backup_file.name,
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "created_timestamp": stat.st_mtime,
                })
            except Exception:
                continue
        
        return backups
    except Exception as exc:
        log(f"Error listing backups: {exc}")
        return []


def delete_backup(backup_filename: str) -> Tuple[bool, str]:
    """Delete a specific backup file."""
    try:
        backup_path = BACKUPS_DIR / backup_filename
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_filename}"
        
        backup_path.unlink()
        log(f"🗑️  Backup deleted: {backup_filename}")
        return True, f"Backup deleted: {backup_filename}"
    except Exception as exc:
        log(f"❌ Backup deletion failed: {exc}")
        return False, f"Delete failed: {str(exc)}"


def cleanup_old_backups() -> int:
    """Delete old backups keeping only the most recent N backups. Returns number deleted."""
    try:
        backups = list_backups()
        if len(backups) <= AUTO_BACKUP_MAX_COUNT:
            return 0
        
        # Delete oldest backups
        to_delete = backups[AUTO_BACKUP_MAX_COUNT:]
        deleted_count = 0
        
        for backup in to_delete:
            success, _ = delete_backup(backup["filename"])
            if success:
                deleted_count += 1
        
        if deleted_count > 0:
            log(f"🗑️  Cleaned up {deleted_count} old backup(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up backups: {exc}")
        return 0


def auto_backup_worker_loop() -> None:
    """Background worker that creates automatic backups on a schedule."""
    global LAST_BACKUP_TIME
    
    log("Auto-backup worker started.")
    
    # Set initial backup time to now to avoid immediate backup on start
    LAST_BACKUP_TIME = time.time()
    
    while True:
        try:
            if not AUTO_BACKUP_ENABLED:
                time.sleep(60)  # Check every minute if disabled
                continue
            
            current_time = time.time()
            time_since_backup = current_time - LAST_BACKUP_TIME
            
            if time_since_backup >= AUTO_BACKUP_INTERVAL:
                log("⏰ Auto-backup triggered")
                success, message, filename = create_backup("auto")
                
                if success:
                    LAST_BACKUP_TIME = current_time
                    # Clean up old backups
                    cleanup_old_backups()
                else:
                    log(f"Auto-backup failed: {message}")
            
            # Sleep for a short interval to check again
            time.sleep(60)
        except Exception as exc:
            log(f"Error in auto-backup worker: {exc}")
            time.sleep(60)


def start_auto_backup_worker() -> None:
    """Start the auto-backup worker thread."""
    global AUTO_BACKUP_THREAD
    
    with AUTO_BACKUP_LOCK:
        already_running = AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive()
    
    if already_running:
        return
    
    thread = threading.Thread(target=auto_backup_worker_loop, name="auto-backup", daemon=True)
    thread.start()
    
    with AUTO_BACKUP_LOCK:
        AUTO_BACKUP_THREAD = thread
    
    log("Auto-backup worker initialized.")


def stop_auto_backup_worker() -> None:
    """Stop the auto-backup worker thread."""
    global AUTO_BACKUP_THREAD
    
    with AUTO_BACKUP_LOCK:
        if AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive():
            AUTO_BACKUP_THREAD = None
            log("Auto-backup worker stopped.")


def get_auto_backup_status() -> Dict[str, Any]:
    """Get current auto-backup status."""
    with AUTO_BACKUP_LOCK:
        next_backup_time = LAST_BACKUP_TIME + AUTO_BACKUP_INTERVAL if AUTO_BACKUP_ENABLED else None
        return {
            "enabled": AUTO_BACKUP_ENABLED,
            "interval_seconds": AUTO_BACKUP_INTERVAL,
            "max_count": AUTO_BACKUP_MAX_COUNT,
            "last_backup_timestamp": LAST_BACKUP_TIME,
            "next_backup_timestamp": next_backup_time,
            "next_backup": datetime.fromtimestamp(next_backup_time, tz=timezone.utc).isoformat() if next_backup_time else None,
            "worker_active": AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive() if AUTO_BACKUP_THREAD else False,
        }


# ================== FILE CLEANUP SYSTEM ==================

# Cleanup system configuration
AUTO_CLEANUP_ENABLED = False
CLEANUP_SCAN_RESULTS_DAYS = 30
CLEANUP_TEMP_FILES_HOURS = 24
CLEANUP_INTERVAL = 3600
LAST_CLEANUP_TIME = 0.0
CLEANUP_LOCK = threading.Lock()
CLEANUP_THREAD: Optional[threading.Thread] = None
CLEANUP_STOP_EVENT = threading.Event()


def cleanup_temporary_files() -> int:
    """
    Clean up temporary files (.tmp.*, .backup) older than configured hours.
    Returns number of files deleted.
    """
    try:
        ensure_dirs()
        deleted_count = 0
        cutoff_time = time.time() - (CLEANUP_TEMP_FILES_HOURS * 3600)
        
        # Patterns for temporary files
        temp_patterns = [
            "*.tmp.*",
            "*.backup",
            ".restore_temp"
        ]
        
        for pattern in temp_patterns:
            for temp_file in DATA_DIR.glob(pattern):
                try:
                    # Skip if it's a directory (handle .restore_temp separately)
                    if temp_file.is_dir():
                        # Only remove .restore_temp if it's old
                        if temp_file.name == ".restore_temp":
                            file_mtime = temp_file.stat().st_mtime
                            if file_mtime < cutoff_time:
                                shutil.rmtree(temp_file, ignore_errors=True)
                                deleted_count += 1
                                log(f"🗑️  Removed old temp directory: {temp_file.name}")
                        continue
                    
                    # Check file age
                    file_mtime = temp_file.stat().st_mtime
                    if file_mtime < cutoff_time:
                        temp_file.unlink()
                        deleted_count += 1
                        log(f"🗑️  Removed old temp file: {temp_file.name}")
                except Exception as e:
                    log(f"Warning: Could not remove temp file {temp_file}: {e}")
        
        if deleted_count > 0:
            log(f"✓ Cleaned up {deleted_count} temporary file(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up temporary files: {exc}")
        return 0


def cleanup_old_scan_results() -> int:
    """
    Clean up old scan result files (nuclei_*.json, nikto_*.json, httpx_*.json, ffuf_*.json)
    older than configured days. Returns number of files deleted.
    """
    try:
        ensure_dirs()
        deleted_count = 0
        cutoff_time = time.time() - (CLEANUP_SCAN_RESULTS_DAYS * 86400)
        
        # Patterns for scan result files
        scan_patterns = [
            "nuclei_*.json",
            "nikto_*.json",
            "httpx_*.json",
            "ffuf_*.json"
        ]
        
        for pattern in scan_patterns:
            for scan_file in DATA_DIR.glob(pattern):
                try:
                    # Skip if it's not a file
                    if not scan_file.is_file():
                        continue
                    
                    # Check file age
                    file_mtime = scan_file.stat().st_mtime
                    if file_mtime < cutoff_time:
                        scan_file.unlink()
                        deleted_count += 1
                        log(f"🗑️  Removed old scan result: {scan_file.name}")
                except Exception as e:
                    log(f"Warning: Could not remove scan file {scan_file}: {e}")
        
        if deleted_count > 0:
            log(f"✓ Cleaned up {deleted_count} old scan result file(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up scan results: {exc}")
        return 0


def run_cleanup() -> Dict[str, int]:
    """Run all cleanup tasks and return statistics."""
    stats = {
        "temp_files": 0,
        "scan_results": 0,
        "backups": 0
    }
    
    try:
        # Clean up temporary files
        stats["temp_files"] = cleanup_temporary_files()
        
        # Clean up old scan results
        stats["scan_results"] = cleanup_old_scan_results()
        
        # Clean up old backups
        stats["backups"] = cleanup_old_backups()
        
        total = sum(stats.values())
        if total > 0:
            log(f"✓ Cleanup completed: {stats['temp_files']} temp files, "
                f"{stats['scan_results']} scan results, {stats['backups']} backups removed")
        
        return stats
    except Exception as exc:
        log(f"Error during cleanup: {exc}")
        return stats


def auto_cleanup_worker_loop() -> None:
    """Background worker that performs automatic cleanup on a schedule."""
    global LAST_CLEANUP_TIME
    
    log("Auto-cleanup worker started.")
    
    # Set initial cleanup time to now to avoid immediate cleanup on start
    LAST_CLEANUP_TIME = time.time()
    
    while not CLEANUP_STOP_EVENT.is_set():
        try:
            if not AUTO_CLEANUP_ENABLED:
                # Wait with timeout so we can respond to stop event
                CLEANUP_STOP_EVENT.wait(timeout=60)
                continue
            
            current_time = time.time()
            time_since_cleanup = current_time - LAST_CLEANUP_TIME
            
            if time_since_cleanup >= CLEANUP_INTERVAL:
                log("⏰ Auto-cleanup triggered")
                stats = run_cleanup()
                LAST_CLEANUP_TIME = current_time
            
            # Sleep with timeout so we can respond to stop event
            CLEANUP_STOP_EVENT.wait(timeout=60)
        except Exception as exc:
            log(f"Error in auto-cleanup worker: {exc}")
            CLEANUP_STOP_EVENT.wait(timeout=60)
    
    log("Auto-cleanup worker stopped.")


def start_cleanup_worker() -> None:
    """Start the auto-cleanup worker thread."""
    global CLEANUP_THREAD
    
    with CLEANUP_LOCK:
        already_running = CLEANUP_THREAD and CLEANUP_THREAD.is_alive()
    
    if already_running:
        return
    
    # Clear stop event before starting
    CLEANUP_STOP_EVENT.clear()
    
    thread = threading.Thread(target=auto_cleanup_worker_loop, name="auto-cleanup", daemon=True)
    thread.start()
    
    with CLEANUP_LOCK:
        CLEANUP_THREAD = thread
    
    log("Auto-cleanup worker initialized.")


def stop_cleanup_worker() -> None:
    """Stop the auto-cleanup worker thread."""
    global CLEANUP_THREAD
    
    with CLEANUP_LOCK:
        if CLEANUP_THREAD and CLEANUP_THREAD.is_alive():
            # Signal thread to stop
            CLEANUP_STOP_EVENT.set()
            CLEANUP_THREAD = None
            log("Auto-cleanup worker stop signal sent.")


def get_cleanup_status() -> Dict[str, Any]:
    """Get current auto-cleanup status."""
    with CLEANUP_LOCK:
        next_cleanup_time = LAST_CLEANUP_TIME + CLEANUP_INTERVAL if AUTO_CLEANUP_ENABLED else None
        return {
            "enabled": AUTO_CLEANUP_ENABLED,
            "interval_seconds": CLEANUP_INTERVAL,
            "scan_results_retention_days": CLEANUP_SCAN_RESULTS_DAYS,
            "temp_files_retention_hours": CLEANUP_TEMP_FILES_HOURS,
            "last_cleanup_timestamp": LAST_CLEANUP_TIME,
            "next_cleanup_timestamp": next_cleanup_time,
            "next_cleanup": datetime.fromtimestamp(next_cleanup_time, tz=timezone.utc).isoformat() if next_cleanup_time else None,
            "worker_active": CLEANUP_THREAD and CLEANUP_THREAD.is_alive() if CLEANUP_THREAD else False,
        }


def save_config(cfg: Dict[str, Any]) -> None:
    """Save configuration to SQLite database with proper error handling."""
    ensure_dirs()
    
    try:
        db = get_db()  # get_db() uses DB_LOCK internally
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # Temporarily set isolation_level to enable proper transaction handling
        # Note: Connection is normally in autocommit mode (isolation_level=None)
        # We need to switch to manual transaction mode for atomic save
        old_isolation = db.isolation_level
        try:
            # Switch to manual transaction mode (empty string enables manual control)
            db.isolation_level = ''
            
            # Now start an explicit transaction with IMMEDIATE lock
            # This provides exclusive write access and prevents concurrent modifications
            cursor.execute("BEGIN IMMEDIATE")
            try:
                for key, value in cfg.items():
                    cursor.execute(
                        "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
                        (key, json.dumps(value), now)
                    )
                
                # Commit the transaction using connection-level method
                db.commit()
            except Exception as e:
                # Rollback on any error using connection-level method
                db.rollback()
                log(f"Error saving config, transaction rolled back: {e}")
                raise
        finally:
            # Restore original isolation level
            db.isolation_level = old_isolation
        
        # Update in-memory config after successful save
        with CONFIG_LOCK:
            CONFIG.clear()
            CONFIG.update(cfg)
        
        # Apply concurrency limits
        # Wrap in try-except to prevent config save from failing if applying limits fails
        try:
            apply_concurrency_limits(cfg)
        except Exception as apply_err:
            log(f"Warning: Config saved successfully but failed to apply concurrency limits: {apply_err}")
            # Don't re-raise - config was saved successfully, we just couldn't apply the runtime changes
    except Exception as e:
        log(f"Failed to save configuration: {e}")
        raise


def load_config() -> Dict[str, Any]:
    """Load configuration from SQLite database."""
    ensure_dirs()
    cfg = default_config()
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT key, value FROM config")
    rows = cursor.fetchall()
    
    if rows:
        for row in rows:
            key = row[0]
            try:
                value = json.loads(row[1])
                if key in cfg:
                    cfg[key] = value
            except json.JSONDecodeError:
                pass
    else:
        # No config in database, save defaults
        save_config(cfg)
    cfg["tool_flag_templates"] = _normalize_tool_flag_templates(cfg.get("tool_flag_templates"))
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)
    
    # Apply concurrency limits
    # Wrap in try-except to prevent config load from failing if applying limits fails
    try:
        apply_concurrency_limits(cfg)
    except Exception as apply_err:
        log(f"Warning: Config loaded successfully but failed to apply concurrency limits: {apply_err}")
        # Don't re-raise - config was loaded successfully, we just couldn't apply the runtime changes
    
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


def _parse_multiple_domains(value: str) -> List[str]:
    """
    Parse multiple domain inputs separated by commas or newlines.
    Returns a deduplicated list of lowercase domain strings.
    
    Examples:
      "example.com, test.com"
      "*.example.com\n*.test.com"
      "*-*-*-*.tangos.nl, *.adsl.xs4all.be"
    """
    if not value:
        return []
    
    # Split by both newlines and commas
    raw_domains = []
    for line in value.split('\n'):
        # For each line, split by commas
        for domain in line.split(','):
            stripped = domain.strip()
            if stripped:
                raw_domains.append(stripped)
    
    # Deduplicate while preserving order (normalize to lowercase)
    seen = set()
    result = []
    for domain in raw_domains:
        domain_lower = domain.lower()
        if domain_lower and domain_lower not in seen:
            seen.add(domain_lower)
            result.append(domain_lower)  # Append normalized version
    
    return result


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
    """
    Expand wildcard targets from input string. Supports multiple domains
    separated by commas or newlines.
    
    Examples:
      Single domain: "example.com"
      Wildcard: "*.example.com"
      TLD wildcard: "example.*"
      Multiple domains: "example.com, test.com" or "example.com\ntest.com"
      Multiple wildcards: "*.example.com\n*.test.com"
    """
    # Parse multiple domains from input
    domain_inputs = _parse_multiple_domains(raw)
    if not domain_inputs:
        return []
    
    all_candidates: List[str] = []
    
    # Process each domain input
    for domain_input in domain_inputs:
        normalized = _sanitize_domain_input(domain_input)
        if not normalized:
            continue
        
        while normalized.startswith("*."):
            normalized = normalized[2:]
        trailing_any_tld = normalized.endswith(".*")
        if trailing_any_tld:
            normalized = normalized[:-2]
        normalized = normalized.strip(".")
        if not normalized:
            continue
        
        # Expand TLD wildcards if present
        if trailing_any_tld:
            cfg = config or get_config()
            tlds = _normalize_tld_list(cfg.get("wildcard_tlds"))
            for suffix in tlds:
                if not suffix:
                    continue
                all_candidates.append(f"{normalized}.{suffix}")
        else:
            all_candidates.append(normalized)
    
    # Deduplicate results
    deduped: List[str] = []
    seen: set = set()
    for candidate in all_candidates:
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
        "max_parallel_amass": "Amass parallel slots",
        "max_parallel_subfinder": "Subfinder parallel slots",
        "max_parallel_assetfinder": "Assetfinder parallel slots",
        "max_parallel_findomain": "Findomain parallel slots",
        "max_parallel_sublist3r": "Sublist3r parallel slots",
        "max_parallel_crtsh": "Crt.sh parallel slots",
        "max_parallel_github_subdomains": "GitHub-Subdomains parallel slots",
        "max_parallel_dnsx": "DNSx parallel slots",
        "max_parallel_httpx": "HTTPx parallel slots",
        "max_parallel_ffuf": "FFUF parallel slots",
        "max_parallel_waybackurls": "Waybackurls parallel slots",
        "max_parallel_gau": "GAU parallel slots",
        "max_parallel_nuclei": "Nuclei parallel slots",
        "max_parallel_nikto": "Nikto parallel slots",
        "max_parallel_gowitness": "Screenshot parallel slots",
        "subfinder_threads": "Subfinder threads",
        "assetfinder_threads": "Assetfinder threads",
        "findomain_threads": "Findomain threads",
        "amass_timeout": "Amass timeout (seconds)",
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
    
    # Handle dynamic mode settings
    if "dynamic_mode_enabled" in values:
        new_dynamic = bool_from_value(values.get("dynamic_mode_enabled"), cfg.get("dynamic_mode_enabled", False))
        if cfg.get("dynamic_mode_enabled", False) != new_dynamic:
            cfg["dynamic_mode_enabled"] = new_dynamic
            changed = True
    
    dynamic_mode_fields = {
        "dynamic_mode_base_jobs": "Dynamic mode base jobs",
        "dynamic_mode_max_jobs": "Dynamic mode max jobs",
    }
    for field, label in dynamic_mode_fields.items():
        if field in values:
            try:
                new_limit = max(1, int(values.get(field)))
            except (TypeError, ValueError):
                return False, f"{label} must be an integer >= 1.", cfg
            if cfg.get(field, 1) != new_limit:
                cfg[field] = new_limit
                changed = True
    
    # Handle dynamic mode threshold settings
    if "dynamic_mode_cpu_threshold" in values:
        try:
            new_threshold = max(0.0, min(100.0, float(values.get("dynamic_mode_cpu_threshold"))))
        except (TypeError, ValueError):
            return False, "CPU threshold must be a number between 0 and 100.", cfg
        if cfg.get("dynamic_mode_cpu_threshold", 75.0) != new_threshold:
            cfg["dynamic_mode_cpu_threshold"] = new_threshold
            changed = True
    
    if "dynamic_mode_memory_threshold" in values:
        try:
            new_threshold = max(0.0, min(100.0, float(values.get("dynamic_mode_memory_threshold"))))
        except (TypeError, ValueError):
            return False, "Memory threshold must be a number between 0 and 100.", cfg
        if cfg.get("dynamic_mode_memory_threshold", 80.0) != new_threshold:
            cfg["dynamic_mode_memory_threshold"] = new_threshold
            changed = True
    
    # Handle auto-backup settings
    if "auto_backup_enabled" in values:
        new_auto_backup = bool_from_value(values.get("auto_backup_enabled"), cfg.get("auto_backup_enabled", False))
        if cfg.get("auto_backup_enabled", False) != new_auto_backup:
            cfg["auto_backup_enabled"] = new_auto_backup
            changed = True
    
    if "auto_backup_interval" in values:
        try:
            new_interval = max(300, int(values.get("auto_backup_interval")))  # Min 5 minutes
        except (TypeError, ValueError):
            return False, "Auto-backup interval must be an integer >= 300 seconds (5 minutes).", cfg
        if cfg.get("auto_backup_interval", 3600) != new_interval:
            cfg["auto_backup_interval"] = new_interval
            changed = True
    
    if "auto_backup_max_count" in values:
        try:
            new_count = max(1, int(values.get("auto_backup_max_count")))
        except (TypeError, ValueError):
            return False, "Auto-backup max count must be an integer >= 1.", cfg
        if cfg.get("auto_backup_max_count", 10) != new_count:
            cfg["auto_backup_max_count"] = new_count
            changed = True
    
    # Handle custom tool binary paths
    if "tool_binary_paths" in values:
        new_paths = values.get("tool_binary_paths", {})
        if isinstance(new_paths, dict):
            # Validate that paths exist
            validated_paths = {}
            for tool, path in new_paths.items():
                if tool in TOOLS and path:
                    path_obj = Path(path)
                    if path_obj.exists():
                        validated_paths[tool] = str(path_obj.resolve())
                    else:
                        log(f"Warning: Custom path for {tool} does not exist: {path}")
            
            if cfg.get("tool_binary_paths", {}) != validated_paths:
                cfg["tool_binary_paths"] = validated_paths
                changed = True

    if changed:
        save_config(cfg)
        return True, "Settings updated.", cfg
    return True, "No changes applied.", cfg


def acquire_lock(timeout: int = 30) -> None:
    """
    Very simple file lock with exponential backoff; best-effort to avoid concurrent writes.
    Increased timeout from 10s to 30s and added exponential backoff to reduce contention.
    """
    start = time.time()
    retry_delay = 0.1  # Start with 100ms
    max_retry_delay = 2.0  # Cap at 2 seconds
    
    while True:
        try:
            # use exclusive create
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return
        except FileExistsError:
            elapsed = time.time() - start
            if elapsed > timeout:
                log("Lock timeout reached, proceeding anyway (best effort).")
                return
            time.sleep(retry_delay)
            # Exponential backoff: increase delay for next retry
            retry_delay = min(retry_delay * 1.5, max_retry_delay)


def release_lock() -> None:
    try:
        LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def load_state() -> Dict[str, Any]:
    """
    Load state (targets and subdomains) from SQLite database.
    
    Optimizations:
    - Uses single JOIN query instead of N+1 queries for better performance
    - Processes results in a single pass
    """
    db = get_db()
    cursor = db.cursor()
    
    # OPTIMIZATION: Single query with JOIN instead of N+1 queries
    cursor.execute("""
        SELECT 
            t.domain, t.flags, t.options, t.comments,
            s.subdomain, s.data, s.interesting, s.comments as sub_comments
        FROM targets t
        LEFT JOIN subdomains s ON t.domain = s.domain
        ORDER BY t.domain, s.subdomain
    """)
    
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    
    # Process results in a single pass
    for row in cursor:
        domain = row[0]
        
        # Check if we've moved to a new domain
        if domain != current_domain:
            # Save previous domain's data if exists
            if current_domain is not None:
                current_target["subdomains"] = subdomains
                targets[current_domain] = current_target
            
            # Start new domain
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            
            current_target = {
                "flags": flags,
                "options": options,
                "comments": target_comments,
            }
            subdomains = {}
        
        # Process subdomain if present (LEFT JOIN may have NULL subdomain)
        subdomain = row[4]
        if subdomain is not None:
            try:
                sub_data = json.loads(row[5])
                # Add interesting and comments to subdomain data
                if row[6] is not None:
                    sub_data["interesting"] = bool(row[6])
                if row[7]:
                    sub_data["comments"] = json.loads(row[7])
                subdomains[subdomain] = sub_data
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain's data
    if current_domain is not None:
        current_target["subdomains"] = subdomains
        targets[current_domain] = current_target
    
    # Get last updated time from the most recent target update
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    return {
        "version": 1,
        "targets": targets,
        "last_updated": last_updated
    }


def save_state(state: Dict[str, Any]) -> None:
    """Save state (targets and subdomains) to SQLite database."""
    now = datetime.now(timezone.utc).isoformat()
    state["last_updated"] = now
    
    acquire_lock()
    try:
        db = get_db()
        cursor = db.cursor()
        
        targets = state.get("targets", {})
        
        for domain, target_data in targets.items():
            subdomains = target_data.get("subdomains", {})
            flags = target_data.get("flags", {})
            options = target_data.get("options", {})
            target_comments = target_data.get("comments", [])
            
            # Insert or update target
            cursor.execute(
                """INSERT INTO targets (domain, data, flags, options, comments, created_at, updated_at) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(domain) DO UPDATE SET 
                   data = excluded.data,
                   flags = excluded.flags,
                   options = excluded.options,
                   comments = excluded.comments,
                   updated_at = excluded.updated_at""",
                (domain, "{}", json.dumps(flags), json.dumps(options), json.dumps(target_comments), now, now)
            )
            
            # Delete old subdomains not in current state
            current_subdomains = set(subdomains.keys())
            cursor.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ?",
                (domain,)
            )
            existing_subdomains = {row[0] for row in cursor.fetchall()}
            
            for old_subdomain in existing_subdomains - current_subdomains:
                cursor.execute(
                    "DELETE FROM subdomains WHERE domain = ? AND subdomain = ?",
                    (domain, old_subdomain)
                )
            
            # Insert or update subdomains
            for subdomain, sub_data in subdomains.items():
                # Extract interesting and comments from sub_data
                interesting = sub_data.get("interesting")
                interesting_val = None if interesting is None else (1 if interesting else 0)
                comments_data = sub_data.get("comments", [])
                
                # Create clean sub_data without interesting/comments for data field
                clean_sub_data = {k: v for k, v in sub_data.items() if k not in ("interesting", "comments")}
                
                cursor.execute(
                    """INSERT INTO subdomains (domain, subdomain, data, interesting, comments, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(domain, subdomain) DO UPDATE SET 
                       data = excluded.data,
                       interesting = excluded.interesting,
                       comments = excluded.comments,
                       updated_at = excluded.updated_at""",
                    (domain, subdomain, json.dumps(clean_sub_data), interesting_val, json.dumps(comments_data), now, now)
                )
        
        db.commit()
        
        # Invalidate state cache after successful save
        invalidate_state_cache()
    finally:
        release_lock()
    
    try:
        generate_html_dashboard(state)
    except Exception as e:
        log(f"Error refreshing dashboard HTML: {e}")



def load_completed_jobs() -> Dict[str, Dict[str, Any]]:
    """Load completed jobs from SQLite database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT job_key, data FROM completed_jobs")
    rows = cursor.fetchall()
    
    jobs = {}
    for row in rows:
        job_key = row[0]
        try:
            job_data = json.loads(row[1])
            jobs[job_key] = job_data
        except json.JSONDecodeError:
            pass
    
    return jobs


def save_completed_jobs() -> None:
    """Save completed jobs to SQLite database."""
    with JOB_LOCK:
        jobs_to_save = copy.deepcopy(COMPLETED_JOBS)
    
    try:
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        for job_key, job_data in jobs_to_save.items():
            domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
            completed_at = job_data.get("completed_at", now)
            
            cursor.execute(
                """INSERT OR REPLACE INTO completed_jobs 
                   (job_key, domain, data, completed_at, created_at) 
                   VALUES (?, ?, ?, ?, ?)""",
                (job_key, domain, json.dumps(job_data), completed_at, now)
            )
        
        db.commit()
    except Exception as e:
        log(f"Error saving completed jobs: {e}")


def add_completed_job(domain: str, job_data: Dict[str, Any]) -> None:
    """
    Add a completed job to the completed jobs storage.
    Keeps only the last MAX_COMPLETED_JOBS_PER_DOMAIN jobs per domain.
    """
    with JOB_LOCK:
        # Remove thread reference before deepcopy as it's not serializable
        # Thread objects contain locks that cannot be pickled
        job_data_copy = {k: v for k, v in job_data.items() if k != 'thread'}
        job_copy = copy.deepcopy(job_data_copy)
        
        # Add completion timestamp
        completion_time = datetime.now(timezone.utc)
        job_copy["completed_at"] = completion_time.isoformat()
        
        # Store with a unique key that includes high-precision timestamp to allow multiple runs
        # Using timestamp() gives microsecond precision to avoid collisions
        job_key = f"{domain}_{completion_time.timestamp()}"
        COMPLETED_JOBS[job_key] = job_copy
        
        # Cleanup old completed jobs for this domain
        domain_jobs = [(k, v) for k, v in COMPLETED_JOBS.items() if k.startswith(f"{domain}_")]
        if len(domain_jobs) > MAX_COMPLETED_JOBS_PER_DOMAIN:
            # Sort by completion time and keep only the most recent
            domain_jobs.sort(key=lambda x: x[1].get("completed_at", ""), reverse=True)
            for old_key, _ in domain_jobs[MAX_COMPLETED_JOBS_PER_DOMAIN:]:
                COMPLETED_JOBS.pop(old_key, None)
    
    # Save to disk
    save_completed_jobs()


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
    """
    Resolve the path to a tool binary, checking custom paths first,
    then standard locations.
    """
    # Check custom binary paths from config first
    config = get_config()
    custom_paths = config.get("tool_binary_paths", {})
    if tool in custom_paths:
        custom_path = custom_paths[tool]
        if custom_path and Path(custom_path).exists():
            if _validate_tool_binary(tool, custom_path):
                log(f"Using custom binary path for {tool}: {custom_path}")
                return custom_path
            else:
                log(f"Custom path for {tool} at {custom_path} failed validation. Trying standard locations.")
    
    # Fall back to standard tool resolution
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


def get_tool_installation_instructions(tool: str) -> str:
    """
    Get detailed installation instructions for a specific tool.
    Returns a formatted string with OS-specific installation commands.
    """
    instructions = {
        "amass": """
AMASS - OWASP Amass Subdomain Enumeration
==========================================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y amass

macOS (Homebrew):
  brew install amass

From Source (requires Go 1.19+):
  go install -v github.com/owasp-amass/amass/v3/...@latest
  # Binary will be in: ~/go/bin/amass or $GOPATH/bin/amass

Official Releases:
  https://github.com/OWASP/Amass/releases
  Download the binary for your platform and add to PATH
""",
        "subfinder": """
SUBFINDER - ProjectDiscovery Subdomain Discovery
=================================================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y subfinder

macOS (Homebrew):
  brew install subfinder

From Source (requires Go 1.19+):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  # Binary will be in: ~/go/bin/subfinder or $GOPATH/bin/subfinder

Official Releases:
  https://github.com/projectdiscovery/subfinder/releases
  Download the binary for your platform and add to PATH
""",
        "assetfinder": """
ASSETFINDER - Find domains and subdomains
==========================================

From Source (requires Go 1.19+):
  go install github.com/tomnomnom/assetfinder@latest
  # Binary will be in: ~/go/bin/assetfinder or $GOPATH/bin/assetfinder

Official Repository:
  https://github.com/tomnomnom/assetfinder
""",
        "findomain": """
FINDOMAIN - Fast subdomain enumeration
=======================================

Ubuntu/Debian:
  # Download latest release
  wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
  chmod +x findomain-linux
  sudo mv findomain-linux /usr/local/bin/findomain

macOS (Homebrew):
  brew install findomain

Windows:
  # Download from: https://github.com/Findomain/Findomain/releases
  # Add to PATH

Official Repository:
  https://github.com/Findomain/Findomain
""",
        "sublist3r": """
SUBLIST3R - Python subdomain enumeration
=========================================

Using pip:
  pip install sublist3r
  # OR
  pip3 install sublist3r

From Source:
  git clone https://github.com/aboul3la/Sublist3r.git
  cd Sublist3r
  pip install -r requirements.txt
  python sublist3r.py --help

Ubuntu/Debian:
  sudo apt-get install -y sublist3r

Official Repository:
  https://github.com/aboul3la/Sublist3r
""",
        "dnsx": """
DNSX - Fast and multi-purpose DNS toolkit
==========================================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y dnsx

macOS (Homebrew):
  brew install dnsx

From Source (requires Go 1.19+):
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  # Binary will be in: ~/go/bin/dnsx or $GOPATH/bin/dnsx

Official Releases:
  https://github.com/projectdiscovery/dnsx/releases
  Download the binary for your platform and add to PATH
""",
        "ffuf": """
FFUF - Fast web fuzzer
======================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y ffuf

macOS (Homebrew):
  brew install ffuf

From Source (requires Go 1.19+):
  go install github.com/ffuf/ffuf@latest
  # Binary will be in: ~/go/bin/ffuf or $GOPATH/bin/ffuf

Official Releases:
  https://github.com/ffuf/ffuf/releases
  Download the binary for your platform and add to PATH
""",
        "httpx": """
HTTPX - Fast HTTP toolkit from ProjectDiscovery
================================================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y httpx-toolkit

macOS (Homebrew):
  brew install httpx

From Source (requires Go 1.19+):
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  # Binary will be in: ~/go/bin/httpx or $GOPATH/bin/httpx

Official Releases:
  https://github.com/projectdiscovery/httpx/releases
  Download the binary for your platform and add to PATH

Note: Make sure you have ProjectDiscovery's httpx, not the Python httpx client!
""",
        "waybackurls": """
WAYBACKURLS - Fetch URLs from the Wayback Machine
==================================================

From Source (requires Go 1.19+):
  go install github.com/tomnomnom/waybackurls@latest
  # Binary will be in: ~/go/bin/waybackurls or $GOPATH/bin/waybackurls

Official Repository:
  https://github.com/tomnomnom/waybackurls
""",
        "gau": """
GAU - Get All URLs from various sources
========================================

From Source (requires Go 1.19+):
  go install github.com/lc/gau/v2/cmd/gau@latest
  # Binary will be in: ~/go/bin/gau or $GOPATH/bin/gau

Official Releases:
  https://github.com/lc/gau/releases
  Download the binary for your platform and add to PATH
""",
        "nuclei": """
NUCLEI - Fast vulnerability scanner from ProjectDiscovery
==========================================================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y nuclei

macOS (Homebrew):
  brew install nuclei

From Source (requires Go 1.19+):
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  # Binary will be in: ~/go/bin/nuclei or $GOPATH/bin/nuclei

Official Releases:
  https://github.com/projectdiscovery/nuclei/releases
  Download the binary for your platform and add to PATH
""",
        "nikto": """
NIKTO - Web server scanner
===========================

Ubuntu/Debian:
  sudo apt-get update && sudo apt-get install -y nikto

macOS (Homebrew):
  brew install nikto

From Source:
  git clone https://github.com/sullo/nikto
  cd nikto/program
  perl nikto.pl --help

Official Repository:
  https://github.com/sullo/nikto

Note: Nikto requires Perl to be installed
""",
        "gowitness": """
GOWITNESS - Web screenshot tool
================================

macOS (Homebrew):
  brew install gowitness

From Source (requires Go 1.19+):
  go install github.com/sensepost/gowitness@latest
  # Binary will be in: ~/go/bin/gowitness or $GOPATH/bin/gowitness

Official Releases:
  https://github.com/sensepost/gowitness/releases
  Download the binary for your platform and add to PATH

Note: gowitness requires Chrome/Chromium to be installed for screenshots
""",
        "github-subdomains": """
GITHUB-SUBDOMAINS - Find subdomains on GitHub
==============================================

From Source (requires Go 1.19+):
  go install github.com/gwen001/github-subdomains@latest
  # Binary will be in: ~/go/bin/github-subdomains or $GOPATH/bin/github-subdomains

Official Repository:
  https://github.com/gwen001/github-subdomains

Note: Requires GitHub API token for best results
""",
        "crtsh": """
CRT.SH - Certificate Transparency Log Search (API-based)
=========================================================

This is a virtual tool that uses the crt.sh API.
No installation required - it works via HTTP requests.

API Endpoint: https://crt.sh/?q=%25.example.com&output=json
""",
    }
    
    return instructions.get(tool, f"No detailed installation instructions available for {tool}")


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

    # Print detailed installation instructions
    log(f"Could not auto-install {tool}. Please install it manually.")
    log(f"Installation instructions for {tool}:")
    print("\n" + get_tool_installation_instructions(tool))
    return False


def ensure_required_tools() -> None:
    log("Verifying required tooling...")
    for name in TOOLS.keys():
        ensure_tool_installed(name)


# ================== FIRST-RUN SETUP WIZARD ==================

def run_setup_wizard() -> None:
    """
    Interactive first-run setup wizard to configure all settings and API keys.
    This prevents the program from freezing during execution by collecting all
    required information upfront.
    """
    print("\n" + "="*70)
    print("    🚀 WELCOME TO SUBSCRAPER - FIRST RUN SETUP WIZARD")
    print("="*70)
    print("\nThis wizard will help you configure subScraper for optimal performance.")
    print("You can skip any setting by pressing Enter (defaults will be used).")
    print("You can always change these settings later in the web UI.\n")
    
    config = get_config()
    
    # Basic Settings
    print("\n" + "-"*70)
    print("📋 BASIC SETTINGS")
    print("-"*70)
    
    # Wordlist configuration
    print("\n1. Default Wordlist for Subdomain Brute-Force (ffuf)")
    print("   Recommended: Download a wordlist like SecLists subdomains-top1million-5000.txt")
    current_wordlist = config.get("default_wordlist", "")
    if current_wordlist:
        print(f"   Current: {current_wordlist}")
    try:
        wordlist = input("   Enter wordlist path (or press Enter to skip): ").strip()
        if wordlist and Path(wordlist).exists():
            config["default_wordlist"] = wordlist
            print(f"   ✓ Wordlist set to: {wordlist}")
        elif wordlist:
            print(f"   ⚠ Warning: File not found: {wordlist}. You can set this later.")
            config["default_wordlist"] = wordlist
        else:
            print("   ⏭ Skipped (you can add this later in Settings)")
    except (EOFError, KeyboardInterrupt):
        print("\n   ⏭ Skipped")
    
    # Concurrency settings
    print("\n2. Concurrent Jobs")
    print(f"   Current: {config.get('max_running_jobs', 1)}")
    print("   How many scans should run simultaneously? (1-10 recommended)")
    try:
        jobs = input("   Enter number (or press Enter for default): ").strip()
        if jobs:
            config["max_running_jobs"] = max(1, min(20, int(jobs)))
            print(f"   ✓ Set to: {config['max_running_jobs']} concurrent jobs")
        else:
            print("   ⏭ Using default: 1")
    except (ValueError, EOFError, KeyboardInterrupt):
        print("   ⏭ Using default: 1")
    
    # Nikto settings
    print("\n3. Skip Nikto by Default?")
    print("   Nikto scans can be slow. Skip them unless explicitly needed?")
    try:
        skip = input("   Skip Nikto? (y/N): ").strip().lower()
        config["skip_nikto_by_default"] = (skip == 'y')
        print(f"   ✓ {'Will skip' if config['skip_nikto_by_default'] else 'Will run'} Nikto by default")
    except (EOFError, KeyboardInterrupt):
        print("   ⏭ Using default: Run Nikto")
    
    # API Keys Configuration
    print("\n" + "-"*70)
    print("🔑 API KEYS SETUP")
    print("-"*70)
    print("\nMany tools work better with API keys for better results and rate limits.")
    print("You can skip these and add them later, but adding them now is recommended.\n")
    
    # Amass API keys
    print("4. Amass Configuration")
    print("   Amass supports multiple data sources with API keys:")
    print("   - Shodan, VirusTotal, SecurityTrails, Censys, PassiveTotal, etc.")
    
    amass_config_dir = Path.home() / ".config" / "amass"
    amass_config_file = amass_config_dir / "config.ini"
    
    if amass_config_file.exists():
        print(f"   ✓ Amass config already exists at: {amass_config_file}")
        try:
            update = input("   Update Amass API keys? (y/N): ").strip().lower()
            if update != 'y':
                print("   ⏭ Keeping existing Amass config")
            else:
                setup_amass_config(amass_config_dir, amass_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Keeping existing Amass config")
    else:
        try:
            setup = input("   Configure Amass API keys now? (Y/n): ").strip().lower()
            if setup == 'n':
                print("   ⏭ Skipped Amass setup")
            else:
                setup_amass_config(amass_config_dir, amass_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Skipped Amass setup")
    
    # Subfinder API keys
    print("\n5. Subfinder Configuration")
    print("   Subfinder also supports various API sources.")
    subfinder_config_dir = Path.home() / ".config" / "subfinder"
    subfinder_config_file = subfinder_config_dir / "provider-config.yaml"
    
    if subfinder_config_file.exists():
        print(f"   ✓ Subfinder config already exists at: {subfinder_config_file}")
        try:
            update = input("   Update Subfinder API keys? (y/N): ").strip().lower()
            if update == 'y':
                setup_subfinder_config(subfinder_config_dir, subfinder_config_file)
            else:
                print("   ⏭ Keeping existing Subfinder config")
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Keeping existing Subfinder config")
    else:
        try:
            setup = input("   Configure Subfinder API keys now? (Y/n): ").strip().lower()
            if setup == 'n':
                print("   ⏭ Skipped Subfinder setup")
            else:
                setup_subfinder_config(subfinder_config_dir, subfinder_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Skipped Subfinder setup")
    
    # Save configuration
    print("\n" + "-"*70)
    print("💾 SAVING CONFIGURATION")
    print("-"*70)
    
    config["setup_completed"] = True
    save_config(config)
    print("✓ Configuration saved successfully!")
    
    # Display summary and next steps
    print("\n" + "="*70)
    print("✅ SETUP COMPLETE!")
    print("="*70)
    print("\n📊 Configuration Summary:")
    print(f"   • Wordlist: {config.get('default_wordlist') or 'Not configured (optional)'}")
    print(f"   • Concurrent Jobs: {config.get('max_running_jobs', 1)}")
    print(f"   • Skip Nikto: {'Yes' if config.get('skip_nikto_by_default') else 'No'}")
    print(f"   • Amass Config: {'✓ Configured' if amass_config_file.exists() else '⏭ Skipped'}")
    print(f"   • Subfinder Config: {'✓ Configured' if subfinder_config_file.exists() else '⏭ Skipped'}")
    
    print("\n" + "-"*70)
    print("🚀 NEXT STEPS TO GET THE FULL PROGRAM WORKING")
    print("-"*70)
    print("\n1. VERIFY TOOLS INSTALLATION")
    print("   All required tools should be installed automatically.")
    print("   If any tool is missing, install it manually:")
    print("   - amass, subfinder, assetfinder, findomain, sublist3r")
    print("   - ffuf, httpx, nuclei, nikto, gowitness")
    print("   - waybackurls, gau, dnsx")
    
    print("\n2. INSTALL PYTHON DEPENDENCIES (if not already done)")
    print("   $ pip3 install -r requirements.txt")
    
    print("\n3. START THE WEB SERVER")
    print("   $ python3 main.py")
    print("   Then open: http://127.0.0.1:8342")
    
    print("\n4. OR RUN A DIRECT SCAN")
    print("   $ python3 main.py example.com --wordlist /path/to/wordlist.txt")
    
    print("\n5. CONFIGURE MORE SETTINGS (optional)")
    print("   • Open the web UI → Settings tab")
    print("   • Configure tool-specific flags and templates")
    print("   • Set up monitoring feeds")
    print("   • Enable dynamic queue management")
    print("   • Configure auto-backup")
    
    print("\n6. DOWNLOAD A WORDLIST (if you haven't)")
    print("   Popular options:")
    print("   • SecLists: https://github.com/danielmiessler/SecLists")
    print("   • DNS wordlists: subdomains-top1million-5000.txt")
    
    print("\n" + "="*70)
    print("📚 For more information:")
    print("   • README.md - Full documentation")
    print("   • QUICKSTART.md - Quick start guide")
    print("   • Web UI Settings - Configure everything through the interface")
    print("="*70 + "\n")


def setup_amass_config(config_dir: Path, config_file: Path) -> None:
    """Setup Amass configuration with API keys."""
    config_dir.mkdir(parents=True, exist_ok=True)
    
    providers = {
        "shodan": "Shodan API (https://account.shodan.io/)",
        "virustotal": "VirusTotal API (https://www.virustotal.com/gui/my-apikey)",
        "securitytrails": "SecurityTrails API (https://securitytrails.com/app/account/credentials)",
        "censys": "Censys API (https://search.censys.io/account/api)",
        "passivetotal": "PassiveTotal/RiskIQ API (https://community.riskiq.com/settings)",
        "binaryedge": "BinaryEdge API (https://app.binaryedge.io/account/api)",
        "bevigil": "BeVigil API (https://bevigil.com/osint-api)",
    }
    
    api_keys = {}
    print("\n   Press Enter to skip any provider.")
    for name, description in providers.items():
        print(f"\n   {description}")
        try:
            key = input(f"   Enter API key for {name} (or press Enter to skip): ").strip()
            if key:
                api_keys[name] = key
                print(f"   ✓ {name} API key saved")
        except (EOFError, KeyboardInterrupt):
            break
    
    # Write config.ini
    lines = [
        "# Generated by subScraper setup wizard",
        "# You can edit this file later to add more API keys",
        "[resolvers]",
        "resolver = 1.1.1.1",
        "resolver = 8.8.8.8",
        "",
        "[scope]",
        "# Add scope settings here if needed",
        "",
        "[datasources]",
    ]
    
    for name, key in api_keys.items():
        lines.append(f"[datasources.{name}]")
        lines.append(f"[datasources.{name}.Credentials]")
        lines.append(f"apikey = {key}")
        lines.append("")
    
    # Add commented templates for providers not configured
    for name in providers.keys():
        if name not in api_keys:
            lines.append(f"# [{name}]")
            lines.append(f"# [datasources.{name}.Credentials]")
            lines.append("# apikey = YOUR_KEY_HERE")
            lines.append("")
    
    atomic_write_text(config_file, "\n".join(lines))
    print(f"\n   ✓ Amass config created at: {config_file}")
    if api_keys:
        print(f"   ✓ Configured {len(api_keys)} API key(s)")
    else:
        print("   ⏭ No API keys configured (you can add them later)")


def setup_subfinder_config(config_dir: Path, config_file: Path) -> None:
    """Setup Subfinder configuration with API keys."""
    config_dir.mkdir(parents=True, exist_ok=True)
    
    providers = {
        "shodan": "Shodan API",
        "censys": "Censys API",
        "virustotal": "VirusTotal API",
        "binaryedge": "BinaryEdge API",
        "securitytrails": "SecurityTrails API",
        "passivetotal": "PassiveTotal API",
        "github": "GitHub Personal Access Token",
    }
    
    api_keys = {}
    print("\n   Press Enter to skip any provider.")
    for name, description in providers.items():
        try:
            key = input(f"   Enter {description} (or press Enter to skip): ").strip()
            if key:
                api_keys[name] = key
                print(f"   ✓ {name} saved")
        except (EOFError, KeyboardInterrupt):
            break
    
    # Create YAML config
    lines = ["# Generated by subScraper setup wizard"]
    for name, key in api_keys.items():
        lines.append(f"{name}: [{key}]")
    
    if not api_keys:
        lines.append("# Add your API keys here")
        lines.append("# Format: provider: [api_key]")
        lines.append("# Example:")
        lines.append("# shodan: [your_api_key_here]")
    
    atomic_write_text(config_file, "\n".join(lines))
    print(f"\n   ✓ Subfinder config created at: {config_file}")
    if api_keys:
        print(f"   ✓ Configured {len(api_keys)} API key(s)")
    else:
        print("   ⏭ No API keys configured (you can add them later)")


# ================== API KEY MANAGEMENT ==================

def read_amass_api_keys() -> Dict[str, str]:
    """Read API keys from Amass config file."""
    config_file = Path.home() / ".config" / "amass" / "config.ini"
    api_keys = {}
    
    if not config_file.exists():
        return api_keys
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse simple INI format for datasources
        # Look for patterns like [datasources.provider] followed by apikey = value
        pattern = r'\[datasources\.(\w+)\.Credentials\]\s*\napikey\s*=\s*(.+?)(?:\n|$)'
        matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
        
        for provider, key in matches:
            api_keys[provider.lower()] = key.strip()
    
    except Exception as exc:
        log(f"Error reading Amass config: {exc}")
    
    return api_keys


def write_amass_api_keys(api_keys: Dict[str, str]) -> Tuple[bool, str]:
    """Write API keys to Amass config file."""
    config_dir = Path.home() / ".config" / "amass"
    config_file = config_dir / "config.ini"
    
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Build config content
        lines = [
            "# Generated by subScraper",
            "# You can edit this file to add or update API keys",
            "[resolvers]",
            "resolver = 1.1.1.1",
            "resolver = 8.8.8.8",
            "",
            "[scope]",
            "# Add scope settings here if needed",
            "",
            "[datasources]",
        ]
        
        # Add API keys for providers that have them
        for provider in AMASS_PROVIDERS:
            if provider in api_keys and api_keys[provider].strip():
                lines.append(f"[datasources.{provider}]")
                lines.append(f"[datasources.{provider}.Credentials]")
                lines.append(f"apikey = {api_keys[provider].strip()}")
                lines.append("")
        
        # Add commented templates for providers without keys
        for provider in AMASS_PROVIDERS:
            if provider not in api_keys or not api_keys[provider].strip():
                lines.append(f"# [datasources.{provider}]")
                lines.append(f"# [datasources.{provider}.Credentials]")
                lines.append("# apikey = YOUR_KEY_HERE")
                lines.append("")
        
        atomic_write_text(config_file, "\n".join(lines))
        return True, f"Amass API keys saved to {config_file}"
    
    except Exception as exc:
        return False, f"Error saving Amass config: {exc}"


def read_subfinder_api_keys() -> Dict[str, str]:
    """Read API keys from Subfinder config file."""
    config_file = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
    api_keys = {}
    
    if not config_file.exists():
        return api_keys
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse simple YAML format: provider: [key]
        pattern = r'^(\w+):\s*\[([^\]]+)\]'
        matches = re.findall(pattern, content, re.MULTILINE)
        
        for provider, key in matches:
            api_keys[provider.lower()] = key.strip()
    
    except Exception as exc:
        log(f"Error reading Subfinder config: {exc}")
    
    return api_keys


def write_subfinder_api_keys(api_keys: Dict[str, str]) -> Tuple[bool, str]:
    """Write API keys to Subfinder config file."""
    config_dir = Path.home() / ".config" / "subfinder"
    config_file = config_dir / "provider-config.yaml"
    
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Build YAML content
        lines = ["# Generated by subScraper"]
        
        # Add API keys for providers that have them
        for provider in SUBFINDER_PROVIDERS:
            if provider in api_keys and api_keys[provider].strip():
                lines.append(f"{provider}: [{api_keys[provider].strip()}]")
        
        # Add commented examples for providers without keys
        if not any(provider in api_keys and api_keys[provider].strip() for provider in SUBFINDER_PROVIDERS):
            lines.append("# Add your API keys here")
            lines.append("# Format: provider: [api_key]")
            lines.append("# Example:")
            lines.append("# shodan: [your_api_key_here]")
        
        atomic_write_text(config_file, "\n".join(lines))
        return True, f"Subfinder API keys saved to {config_file}"
    
    except Exception as exc:
        return False, f"Error saving Subfinder config: {exc}"


def get_all_api_keys() -> Dict[str, Any]:
    """Get all API keys from both Amass and Subfinder configs."""
    return {
        "amass": read_amass_api_keys(),
        "subfinder": read_subfinder_api_keys(),
    }


def save_all_api_keys(amass_keys: Dict[str, str], subfinder_keys: Dict[str, str]) -> Tuple[bool, str]:
    """Save API keys to both Amass and Subfinder configs."""
    amass_success, amass_msg = write_amass_api_keys(amass_keys)
    subfinder_success, subfinder_msg = write_subfinder_api_keys(subfinder_keys)
    
    if amass_success and subfinder_success:
        return True, "API keys saved successfully"
    elif amass_success:
        return False, f"Amass keys saved, but Subfinder failed: {subfinder_msg}"
    elif subfinder_success:
        return False, f"Subfinder keys saved, but Amass failed: {amass_msg}"
    else:
        return False, f"Failed to save keys. Amass: {amass_msg}, Subfinder: {subfinder_msg}"


# ================== AMASS CONFIG ==================

def ensure_amass_config_interactive() -> None:
    """
    If no amass config is found, optionally ask user if they want a basic template
    and (optionally) enter some keys.
    NOTE: This is only called during pipeline execution if setup was not completed.
    The main setup wizard handles this during first run.
    """
    # Check if setup was completed - if so, don't block with interactive prompts
    cfg = get_config()
    if cfg.get("setup_completed", False):
        # Setup was completed, don't prompt during execution
        config_dir = Path.home() / ".config" / "amass"
        config_file = config_dir / "config.ini"
        if not config_file.exists():
            log("Amass config not found, but setup was completed. Skipping interactive prompt.")
            log("You can configure Amass API keys later through the web UI or by editing ~/.config/amass/config.ini")
        return
    
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

    atomic_write_text(config_file, "\n".join(lines))
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
        
        # Set environment variables to prevent interactive prompts from various tools
        # These ensure tools run in non-interactive mode and don't freeze waiting for input
        non_interactive_env = {
            # General non-interactive settings
            "DEBIAN_FRONTEND": "noninteractive",
            "TERM": "dumb",
            "CI": "true",  # Many tools detect CI environments and disable interactive features
            
            # Subfinder - prevent interactive config creation
            "SUBFINDER_CONFIG_PATH": str(Path.home() / ".config" / "subfinder" / "provider-config.yaml"),
            
            # Nuclei - prevent interactive prompts and template updates
            "NUCLEI_NONINTERACTIVE": "1",
            "NUCLEI_NO_COLOR": "1",
            
            # Amass - already handled via config file but ensure non-interactive
            "AMASS_CONFIG": str(Path.home() / ".config" / "amass" / "config.ini"),
            
            # GitHub CLI / github-subdomains - prevent auth prompts
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_PAGER": "",
            
            # General tool settings to prevent prompts
            "PAGER": "",
            "MANPAGER": "",
            "NO_COLOR": "1",
        }
        
        # Apply non-interactive environment
        merged_env.update(non_interactive_env)
        
        # Apply any custom environment variables passed in
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
            stdin=subprocess.DEVNULL,  # Prevent reading from stdin - critical for non-interactive mode
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
            
            # Check if stderr contains rate limit indicators and track them
            combined_output = stdout + stderr
            if any(keyword in combined_output.lower() for keyword in 
                   ["rate limit", "too many requests", "429", "throttle", "slow down"]):
                if job_domain:
                    track_timeout_error(job_domain, Exception(stderr_preview), job_domain)
            
            return False

    except subprocess.TimeoutExpired as e:
        log(f"Command timeout: {display_cmd}")
        if job_domain:
            job_log_append(job_domain, f"Command timeout after {timeout}s", source=step or "system")
            # Track timeout errors
            track_timeout_error(job_domain, e, job_domain)
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
            # Track potential rate limit errors
            track_timeout_error(job_domain, e, job_domain)
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


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences (color codes, formatting) from text.
    This handles common terminal color codes that tools like sublist3r add to output.
    """
    # Pattern matches ANSI escape sequences including CSI sequences
    # \x1b is ESC (hex), \033 is ESC (octal)
    # Matches standard ANSI control sequences ending in A-Za-z
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\033\[[0-9;]*[A-Za-z]')
    return ansi_escape.sub('', text)


def is_valid_subdomain(text: str) -> bool:
    """
    Validate that a string looks like a valid domain or subdomain.
    Returns False for ANSI codes, error messages, status messages, etc.
    """
    if not text:
        return False
    
    # Strip ANSI codes first
    cleaned = strip_ansi_codes(text).strip()
    if not cleaned:
        return False
    
    # Reject lines that are clearly not domains
    # Check for common patterns in tool output that shouldn't be domains
    invalid_patterns = [
        r'^\[',  # Starts with bracket (ANSI remnants, arrays, etc.)
        r'^\]',  # Starts with closing bracket
        r'^[-\+#]',  # Starts with status symbols (but not * for wildcards)
        r'error|Error|ERROR',  # Contains error keywords
        r'warning|Warning|WARNING',  # Contains warning keywords
        r'searching|enumerat|finish|coded by',  # Tool status messages
        r'^\s*$',  # Empty or whitespace only
        r'\s{2,}',  # Multiple consecutive spaces (likely formatted output)
        r'^[0-9]+\s',  # Starts with number and space (table rows)
        r'^\||^-+$|^\++$',  # Table borders
        r'^http://|^https://',  # URLs (not raw domains)
        r'[ \t\r\n\f\v]',  # Contains ASCII whitespace (domains don't have spaces)
    ]
    
    for pattern in invalid_patterns:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return False
    
    # Basic domain validation: should contain at least one dot and valid chars
    # Valid domain characters: alphanumeric, dots, hyphens, underscores
    # Must contain at least one dot (subdomain.domain or domain.tld)
    if '.' not in cleaned:
        return False
    
    # Check if it looks like a domain (alphanumeric with dots, hyphens, underscores)
    # Allow wildcards at the start (*.example.com)
    domain_pattern = r'^(\*\.)?[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+$'
    if not re.match(domain_pattern, cleaned, re.IGNORECASE):
        return False
    
    return True


def read_lines_file(path: Path) -> List[str]:
    if not path or not path.exists():
        return []
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    # Strip ANSI codes and validate
                    cleaned = strip_ansi_codes(line).strip()
                    if cleaned and is_valid_subdomain(cleaned):
                        lines.append(cleaned.lower())
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
    
    # Newer versions of findomain use different output handling
    # Instead of --output, we use output redirection
    cmd = [
        TOOLS["findomain"],
        "--target", domain,
        "--threads", str(threads),
        "--quiet",
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
        "THREADS": threads,
    }
    cmd = apply_template_flags("findomain", cmd, context, config)
    
    # Use output redirection instead of --output flag
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
        import ssl
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconTool/1.0"})
        if job_domain:
            job_log_append(job_domain, f"Querying crt.sh for {domain}", source="crtsh")
        
        # Create SSL context that doesn't verify certificates
        # SECURITY NOTE: This is needed because crt.sh may be behind proxies with self-signed certs.
        # The data from crt.sh is public certificate transparency logs, so the risk is limited to
        # potential MITM attacks affecting subdomain enumeration accuracy, not credential exposure.
        # For production use, consider implementing certificate pinning for crt.sh's actual cert.
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
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
        # Track timeout/rate-limit errors for intelligent backoff
        track_timeout_error(domain, exc, job_domain)
    return sorted(subs)


def github_subdomains_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use github-subdomains tool to find subdomains via GitHub.
    Requires GitHub token - will try to use token from subfinder config if available.
    """
    if not ensure_tool_installed("github-subdomains"):
        return []
    
    # Try to get GitHub token from subfinder config
    github_token = None
    try:
        subfinder_keys = read_subfinder_api_keys()
        github_token = subfinder_keys.get("github", "").strip()
    except Exception:
        pass
    
    # If no token available, skip with warning
    if not github_token:
        if job_domain:
            job_log_append(job_domain, 
                "github-subdomains: No GitHub token configured. Add token in API Keys settings.", 
                source="github-subdomains")
        log(f"github-subdomains: Skipping {domain} - no GitHub token configured")
        return []
    
    out_path = DATA_DIR / f"github_subdomains_{domain}.txt"
    
    # Use environment variable to pass token securely (avoid exposing in process list)
    env = os.environ.copy()
    
    # Create temporary token file to avoid exposing token in command line
    import tempfile
    token_file = None
    try:
        # Create temporary file for token
        fd, token_file = tempfile.mkstemp(prefix="github_token_", suffix=".txt", dir=DATA_DIR)
        with os.fdopen(fd, 'w') as f:
            f.write(github_token)
        
        cmd = [
            TOOLS["github-subdomains"],
            "-d", domain,
            "-t", token_file,  # Use token file instead of raw token
            "-o", str(out_path),
        ]
        context = {
            "DOMAIN": domain,
            "OUTPUT": str(out_path),
        }
        cmd = apply_template_flags("github-subdomains", cmd, context)
        success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="github-subdomains")
        return read_lines_file(out_path) if success else []
    finally:
        # Clean up token file
        if token_file and os.path.exists(token_file):
            try:
                os.unlink(token_file)
            except Exception:
                pass


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
        if job_domain:
            job_log_append(job_domain, "Waiting for httpx slot...", "scheduler")
        with TOOL_GATES["httpx"]:
            if job_domain:
                job_log_append(job_domain, "httpx slot acquired.", "scheduler")
            httpx_json = httpx_scan(batch_file, domain, config=config, job_domain=job_domain)
        try:
            batch_file.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if not httpx_json:
            job_log_append(job_domain, "httpx batch failed. Continuing with pipeline.", "httpx")
            update_step("httpx", status="error", message="httpx batch failed (timeouts or connection issues). Continuing with pipeline.", progress=100)
            # Don't break - httpx failures (especially timeouts) are common and shouldn't stop the pipeline
            # Mark as done so we don't retry indefinitely
            flags["httpx_done"] = True
            save_state(state)
        else:
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
        # Store endpoints in state
        tgt = ensure_target_state(state, domain)
        existing_endpoints = set(tgt.get("endpoints", []))
        for url in urls:
            if url and url not in existing_endpoints:
                tgt["endpoints"].append(url)
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
        # Store endpoints in state
        tgt = ensure_target_state(state, domain)
        existing_endpoints = set(tgt.get("endpoints", []))
        for url in urls:
            if url and url not in existing_endpoints:
                tgt["endpoints"].append(url)
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
    if skip_nikto:
        update_step("nikto", status="skipped", message="Nikto skipped per run options.", progress=0)
    else:
        nikto_processed: set = set()
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
    
    Only returns subdomains that are properly formatted as valid subdomains.
    ffuf is configured via -mc to only return specific status codes (200, 301, 302, 403, 401).
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
        invalid_count = 0
        for r in data.get("results", []):
            raw_host = r.get("host") or r.get("url")
            if raw_host:
                # ffuf may show host as FUZZ.domain.tld - clean and normalize it
                host = raw_host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                
                # Validate subdomain format before adding
                # This filters out invalid entries from wordlist (comments, malformed names, etc.)
                if is_valid_subdomain(host):
                    subs.add(host)
                else:
                    invalid_count += 1
        
        if invalid_count > 0:
            msg = f"Filtered out {invalid_count} invalid subdomain entries from results"
            log(f"ffuf: {msg}")
            if job_domain:
                job_log_append(job_domain, msg, "ffuf")
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
    """
    Run httpx HTTP probing with enhanced error handling.
    
    Httpx may timeout on some hosts, which is normal - this shouldn't crash the pipeline.
    Returns the output JSON file path if successful, None otherwise.
    """
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
    
    # Run httpx - it may fail on individual hosts (timeouts) but should still produce output
    success = run_subprocess(cmd, job_domain=job_domain, step="httpx")
    
    # Even if httpx returns non-zero exit code (some hosts timed out),
    # it may have successfully probed other hosts and written partial results
    # So check if output file exists with content, not just success flag
    if out_json.exists() and out_json.stat().st_size > 0:
        return out_json
    elif success:
        # Success but no output - probably no hosts responded
        if job_domain:
            job_log_append(job_domain, "httpx completed but found no responsive hosts", "httpx")
        return None
    else:
        # Failed and no output
        return None


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
        # Only include subdomains with valid response codes (optimization)
        status_code = httpx_info.get("status_code")
        if status_code is None:
            continue
        # Filter out invalid responses (0 or no response typically means failed connection)
        if status_code == 0:
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
        "scan",
        "file",
        "-f", str(target_file),
        "-P", str(dest_dir),
        "--db", str(db_path),
        "--write-db",
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
        # Log the results summary
        log(f"Nikto scan complete: {len(results)} findings written to {out_json.name}")
        if job_domain:
            job_log_append(job_domain, f"Nikto found {len(results)} total findings across {len(subs)} host(s), saved to {out_json.name}", source="nikto")
    except Exception as e:
        log(f"Error writing Nikto JSON: {e}")
        return None

    return out_json if out_json.exists() else None


# ================== STATE ENRICHMENT ==================


def make_subdomain_entry() -> Dict[str, Any]:
    return {
        "sources": [],
        "httpx": None,
        "nuclei": [],
        "nikto": [],
        "screenshot": None,
        "scans": {},
    }


def ensure_target_state(state: Dict[str, Any], domain: str) -> Dict[str, Any]:
    targets = state.setdefault("targets", {})
    tgt = targets.setdefault(domain, {
        "subdomains": {},
        "endpoints": [],  # Store discovered URLs from waybackurls and gau
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
    tgt.setdefault("endpoints", [])
    tgt.setdefault("flags", {})
    tgt.setdefault("options", {})
    for k in ["amass_done", "subfinder_done", "assetfinder_done", "findomain_done", "sublist3r_done",
              "ffuf_done", "httpx_done", "screenshots_done", "nuclei_done", "nikto_done"]:
        tgt["flags"].setdefault(k, False)
    for sub, entry in list(tgt["subdomains"].items()):
        if not isinstance(entry, dict):
            tgt["subdomains"][sub] = make_subdomain_entry()
            continue
        entry.setdefault("sources", [])
        entry.setdefault("httpx", None)
        entry.setdefault("nuclei", [])
        entry.setdefault("nikto", [])
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
        atomic_write_text(HTML_DASHBOARD_FILE, "\n".join(html_parts))
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
                    # Wait for tool slot if gate exists
                    if name in TOOL_GATES:
                        job_log_append(job_domain, f"Waiting for {name} slot...", "scheduler")
                        with TOOL_GATES[name]:
                            job_log_append(job_domain, f"{name} slot acquired.", "scheduler")
                            subs = func() or []
                    else:
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
            # Save the completed job before removing it from running jobs
            # Get job data while holding lock, then save outside lock to avoid deadlock
            job_to_save = None
            with JOB_LOCK:
                job_record = RUNNING_JOBS.get(domain)
                if job_record:
                    # Remove thread reference before deepcopy to avoid pickle errors
                    # Thread objects contain locks that cannot be pickled
                    # Create a copy excluding the thread key to preserve original state
                    job_to_save = copy.deepcopy({k: v for k, v in job_record.items() if k != 'thread'})
                RUNNING_JOBS.pop(domain, None)
            
            # Save outside the lock to avoid deadlock (add_completed_job acquires lock)
            if job_to_save:
                add_completed_job(domain, job_to_save)
            
            # Schedule next jobs after cleanup
            schedule_jobs()
            cleanup_job_control(domain)

    thread = threading.Thread(target=runner, name=f"pipeline-{domain}", daemon=True)
    with JOB_LOCK:
        job["thread"] = thread
        job["started"] = datetime.now(timezone.utc).isoformat()
        # Start thread while holding lock to prevent race condition
        # This ensures count_active_jobs_locked() sees the thread immediately
        thread.start()
    job_log_append(domain, "Job dispatched to worker.", "scheduler")


def schedule_jobs() -> None:
    """
    Schedule queued jobs to run, respecting MAX_RUNNING_JOBS limit.
    Starts jobs one at a time while holding the lock to prevent race conditions.
    """
    while True:
        job_to_start = None
        with JOB_LOCK:
            # Check if we can start another job
            if not JOB_QUEUE or count_active_jobs_locked() >= MAX_RUNNING_JOBS:
                break
            
            # Get next job from queue
            domain = JOB_QUEUE.popleft()
            job = RUNNING_JOBS.get(domain)
            
            # Skip if job doesn't exist or already has a thread
            if not job or job.get("thread"):
                continue
            
            job["status"] = "dispatching"
            job["message"] = "Preparing to start."
            job_to_start = job
        
        # Start the job (this acquires JOB_LOCK internally)
        if job_to_start:
            _start_job_thread(job_to_start)


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
    """Append an entry to domain history in SQLite database."""
    if not domain or not entry:
        return
    try:
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        timestamp = entry.get("ts", now)
        source = entry.get("source", "system")
        text = entry.get("text", "")
        
        cursor.execute(
            """INSERT INTO history (domain, timestamp, source, text, created_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (domain, timestamp, source, text, now)
        )
        db.commit()
    except Exception as exc:
        log(f"Failed to write history for {domain}: {exc}")


def load_domain_history(domain: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Load domain history from SQLite database.
    
    Args:
        domain: The domain to load history for
        limit: Maximum number of recent entries to return (None = all entries)
               When limit is specified, returns the most recent entries.
    
    Returns:
        List of history events in chronological order (oldest first)
    
    Note:
        Uses ORDER BY timestamp DESC, id DESC to ensure consistent ordering
        when multiple entries have the same timestamp. The id DESC ensures
        that within the same timestamp, newer entries (higher id) come first
        in the DESC sort, maintaining insertion order.
    """
    db = get_db()
    cursor = db.cursor()
    
    if limit is not None and limit > 0:
        # Efficiently get the last N entries using a subquery
        # Inner query: get last N entries ordered DESC (including id for proper ordering)
        # Outer query: re-order them ASC for chronological display
        cursor.execute(
            """SELECT timestamp, source, text FROM (
                   SELECT id, timestamp, source, text FROM history 
                   WHERE domain = ? 
                   ORDER BY timestamp DESC, id DESC
                   LIMIT ?
               ) ORDER BY timestamp ASC, id ASC""",
            (domain, limit)
        )
        rows = cursor.fetchall()
    else:
        # Load all entries (for backward compatibility, though not recommended for large datasets)
        cursor.execute(
            """SELECT timestamp, source, text FROM history 
               WHERE domain = ? 
               ORDER BY timestamp ASC""",
            (domain,)
        )
        rows = cursor.fetchall()
    
    events = []
    for row in rows:
        events.append({
            "ts": row[0],
            "source": row[1],
            "text": row[2]
        })
    
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
input[type="text"], input[type="number"], textarea { width:100%; padding:10px; border-radius:8px; border:1px solid #1f2937; background:#0b152c; color:var(--text); font-family: inherit; }
textarea { resize: vertical; min-height: 80px; }
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
.log-file-link { color:#60a5fa; text-decoration:underline; cursor:pointer; }
.log-file-link:hover { color:#93c5fd; }
.job-actions { margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; }
.queue-card { display:flex; flex-direction:column; gap:8px; }
.queue-row { display:flex; justify-content:space-between; align-items:center; }
.queue-meta { display:flex; flex-wrap:wrap; gap:12px; font-size:13px; color:var(--muted); }
.worker-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; }
.worker-card { background:var(--panel-alt); border-radius:14px; padding:16px; border:1px solid #1f2937; box-shadow:0 10px 20px rgba(0,0,0,0.2); }
.worker-card h3 { margin:0 0 8px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.worker-card .metric { font-size:32px; font-weight:600; }
.worker-card .muted { margin-top:4px; }
.worker-card .warning { margin-top:4px; color:#f59e0b; font-size:12px; }
.worker-card.rate-limit-active { border-color:#f59e0b; box-shadow:0 10px 20px rgba(245,158,11,0.15); }
.worker-card .metric.warning { color:#f59e0b; }
.worker-progress { margin-top:10px; }

.resource-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; margin-bottom:24px; }
.resource-card { background:var(--panel-alt); border-radius:14px; padding:20px; border:1px solid #1f2937; box-shadow:0 10px 20px rgba(0,0,0,0.2); transition:all 0.3s ease; }
.resource-card h3 { margin:0 0 8px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.resource-metric { font-size:36px; font-weight:700; margin:8px 0; }
.resource-card.warning { border-color:#f59e0b; box-shadow:0 10px 20px rgba(245,158,11,0.2); }
.resource-card.warning .resource-metric { color:#f59e0b; }
.resource-card.critical { border-color:#dc2626; box-shadow:0 10px 20px rgba(220,38,38,0.2); }
.resource-card.critical .resource-metric { color:#dc2626; }
.resource-details { margin-top:12px; padding-top:12px; border-top:1px solid #1f2937; }
.resource-detail-item { display:flex; justify-content:space-between; padding:4px 0; font-size:13px; }
.resource-label { color:var(--muted); }
.resource-value { color:var(--text); font-weight:500; }

.resource-warnings-section { background:var(--panel-alt); border-radius:14px; padding:20px; margin-bottom:24px; border-left:4px solid #f59e0b; }
.resource-warnings-section h3 { margin:0 0 16px 0; color:#f59e0b; }
.resource-warning { padding:12px 16px; margin-bottom:8px; border-radius:8px; font-size:14px; }
.resource-warning.warning { background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); color:#fbbf24; }
.resource-warning.critical { background:rgba(220,38,38,0.1); border:1px solid rgba(220,38,38,0.3); color:#ef4444; }

.resource-history { background:var(--panel-alt); border-radius:14px; padding:20px; margin-bottom:24px; border:1px solid #1f2937; }
.resource-history h3 { margin:0 0 16px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.resource-history-grid { display:grid; gap:16px; }
.resource-history-item { display:grid; grid-template-columns:80px 1fr 60px; align-items:center; gap:12px; padding:12px; background:var(--panel); border-radius:8px; }
.resource-history-label { font-size:13px; font-weight:600; color:var(--muted); }
.resource-history-sparkline { display:flex; align-items:flex-end; gap:2px; height:50px; }
.sparkline-bar { flex:1; min-width:2px; border-radius:2px 2px 0 0; transition:all 0.3s ease; }
.resource-history-current { font-size:16px; font-weight:700; text-align:right; }

.resource-network { background:var(--panel-alt); border-radius:14px; padding:20px; border:1px solid #1f2937; }
.resource-network h3 { margin:0 0 16px 0; font-size:15px; text-transform:uppercase; letter-spacing:0.08em; color:#93c5fd; }
.resource-network-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }
.resource-network-item { padding:12px; background:var(--panel); border-radius:8px; display:flex; justify-content:space-between; }

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
.gallery-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:20px; margin-top:20px; }
.gallery-card { background:var(--panel-alt); border-radius:12px; overflow:hidden; border:1px solid #1f2937; transition:transform .2s ease; }
.gallery-card:hover { transform:translateY(-4px); }
.gallery-image { width:100%; height:180px; object-fit:cover; cursor:pointer; background:#0f172a; }
.gallery-info { padding:14px; }
.gallery-subdomain { font-weight:600; color:#f1f5f9; margin-bottom:6px; word-break:break-all; font-size:13px; }
.gallery-url { color:#60a5fa; text-decoration:none; font-size:12px; word-break:break-all; display:block; margin-bottom:8px; }
.gallery-url:hover { text-decoration:underline; }
.gallery-meta { font-size:11px; color:var(--muted); }
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
      <a class="nav-link" data-view="resources" href="#resources">System Resources</a>
      <a class="nav-link" data-view="queue" href="#queue">Queue</a>
      <a class="nav-link" data-view="reports" href="#reports">Reports</a>
      <a class="nav-link" data-view="gallery" href="#gallery">Gallery</a>
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
        <div class="card" style="margin: 24px 0;">
          <h3>Recent Targets</h3>
          <p class="muted">Quick overview of all tracked domains</p>
          <div id="overview-targets-list"></div>
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
              <label for="launch-domain">Domain(s) / TLD(s)
                <textarea id="launch-domain" name="domain" rows="4" placeholder="example.com&#10;*.test.com, *.corp.com&#10;*.subdomain.example.*" required aria-required="true" aria-describedby="domain-help"></textarea>
                <small id="domain-help" style="color: #94a3b8; font-size: 0.85rem; display: block; margin-top: 4px;">
                  Enter one or more domains/wildcards. Separate with commas or newlines.
                </small>
              </label>
              <label for="launch-wordlist">Wordlist path (optional)
                <input id="launch-wordlist" type="text" name="wordlist" placeholder="./w.txt" />
              </label>
              <label for="launch-interval">Dashboard interval seconds
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
      <div class="module-body">
        <div id="jobs-list">
          <div class="section-placeholder">No active jobs.</div>
        </div>
        <div class="table-pagination" id="jobs-pagination"></div>
      </div>
    </section>

    <section class="module" data-view="workers">
      <div class="module-header"><h2>Workers</h2></div>
      <div class="module-body" id="workers-body">
        <div class="section-placeholder">Loading worker data…</div>
      </div>
    </section>

    <section class="module" data-view="resources">
      <div class="module-header">
        <h2>System Resources</h2>
        <p class="muted">Real-time monitoring of system resource usage</p>
      </div>
      <div class="module-body" id="resources-body">
        <div class="section-placeholder">Loading system resource data…</div>
      </div>
    </section>

    <section class="module" data-view="queue">
      <div class="module-header"><h2>Job Queue</h2></div>
      <div class="module-body">
        <p class="muted">Jobs wait here when all worker slots are busy. They start automatically.</p>
        <div id="queue-list" class="queue-list section-placeholder">Queue empty.</div>
        <div class="table-pagination" id="queue-pagination"></div>
      </div>
    </section>

    <section class="module" data-view="reports">
      <div class="module-header"><h2>Reports & Export</h2></div>
      <div class="module-body" id="reports-body">
        <div class="section-placeholder">No data yet.</div>
      </div>
    </section>

    <section class="module" data-view="gallery">
      <div class="module-header"><h2>Screenshot Gallery</h2></div>
      <div class="module-body" id="gallery-body">
        <div class="section-placeholder">Select a target from the dropdown to view screenshots.</div>
        <div style="margin: 20px 0;">
          <label>Select Target
            <select id="gallery-target-select" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
              <option value="">-- Select a target --</option>
            </select>
          </label>
        </div>
        <div id="gallery-grid" class="gallery-grid"></div>
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
          <button class="settings-tab" data-tab="api-keys">API Keys</button>
          <button class="settings-tab" data-tab="concurrency">Concurrency</button>
          <button class="settings-tab" data-tab="backup">Backup & Restore</button>
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

          <div class="settings-subtab-content" data-tab-content="api-keys">
            <div class="card">
              <h3>🔑 API Keys Configuration</h3>
              <p class="muted">Configure API keys for enhanced subdomain enumeration. Most tools work without API keys, but adding them significantly improves results and rate limits.</p>
              
              <div style="background: #0b152c; border: 1px solid #1f2937; border-radius: 12px; padding: 16px; margin: 20px 0;">
                <h4 style="margin-top: 0; color: #60a5fa;">ℹ️ Important Information</h4>
                <ul class="tips" style="margin-bottom: 0;">
                  <li><strong>API keys are stored in tool-specific config files</strong></li>
                  <li>Amass keys: <code>~/.config/amass/config.ini</code></li>
                  <li>Subfinder keys: <code>~/.config/subfinder/provider-config.yaml</code></li>
                  <li>After saving keys, restart any active scans to apply changes</li>
                </ul>
              </div>

              <form id="api-keys-form">
                <h4 style="margin-top: 24px;">Amass API Keys</h4>
                <p class="muted">Amass supports multiple data sources for passive subdomain enumeration.</p>
                
                <div style="display: grid; gap: 16px; margin-top: 16px;">
                  <!-- Shodan -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">Shodan</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Search engine for Internet-connected devices. Free tier: 100 queries/month.
                      <a href="https://account.shodan.io/" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-shodan" name="amass-shodan" placeholder="Enter Shodan API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- VirusTotal -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">VirusTotal</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Analyzes files and URLs for malware, includes passive DNS. Free tier: 4 requests/minute.
                      <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-virustotal" name="amass-virustotal" placeholder="Enter VirusTotal API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- SecurityTrails -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">SecurityTrails</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      DNS and domain intelligence platform. Free tier: 50 API calls/month.
                      <a href="https://securitytrails.com/app/account/credentials" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-securitytrails" name="amass-securitytrails" placeholder="Enter SecurityTrails API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- Censys -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">Censys</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Internet-wide scanning and certificate data. Free tier: 250 queries/month.
                      <a href="https://search.censys.io/account/api" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-censys" name="amass-censys" placeholder="Enter Censys API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- PassiveTotal -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">PassiveTotal (RiskIQ)</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Threat intelligence platform with passive DNS. Free community edition available.
                      <a href="https://community.riskiq.com/settings" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-passivetotal" name="amass-passivetotal" placeholder="Enter PassiveTotal API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- BinaryEdge -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">BinaryEdge</strong>
                        <span class="badge" style="background: #f59e0b; color: white; margin-left: 8px; font-size: 11px;">PAID ONLY</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Cybersecurity data platform. Starting at $10/month for 10,000 queries.
                      <a href="https://app.binaryedge.io/account/api" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-binaryedge" name="amass-binaryedge" placeholder="Enter BinaryEdge API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>

                  <!-- BeVigil -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">BeVigil</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE TIER</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Mobile app security platform with OSINT API. Free tier available with rate limits.
                      <a href="https://bevigil.com/osint-api" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Get key</a>
                    </p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Key:</span>
                      <input type="text" id="amass-bevigil" name="amass-bevigil" placeholder="Enter BeVigil API key (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>
                </div>

                <h4 style="margin-top: 32px;">Subfinder API Keys</h4>
                <p class="muted">Subfinder aggregates data from multiple passive sources. Note: Shodan, VirusTotal, Censys, SecurityTrails, PassiveTotal, and BinaryEdge use the same keys as configured above.</p>
                
                <div style="display: grid; gap: 16px; margin-top: 16px;">
                  <!-- GitHub Token -->
                  <div style="background: #050b18; border: 1px solid #1f2937; border-radius: 10px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                      <div>
                        <strong style="font-size: 15px; color: #e2e8f0;">GitHub Personal Access Token</strong>
                        <span class="badge" style="background: #16a34a; color: white; margin-left: 8px; font-size: 11px;">FREE</span>
                      </div>
                    </div>
                    <p style="font-size: 13px; color: var(--muted); margin: 8px 0;">
                      Search GitHub code for subdomain mentions. Rate limits: 5,000 requests/hour.
                      <a href="https://github.com/settings/tokens" target="_blank" style="color: #60a5fa; font-size: 13px;">→ Create token</a>
                    </p>
                    <p style="font-size: 12px; color: #fbbf24; margin-top: 4px;"><strong>Permissions needed:</strong> public_repo (or repo for private repos)</p>
                    <label style="display: block; margin-top: 12px;">
                      <span style="font-size: 13px; color: var(--muted);">API Token:</span>
                      <input type="text" id="subfinder-github" name="subfinder-github" placeholder="Enter GitHub Personal Access Token (optional)" style="width: 100%; margin-top: 4px;" />
                    </label>
                  </div>
                </div>

                <div style="background: rgba(22, 163, 74, 0.1); border: 1px solid #16a34a; border-radius: 12px; padding: 16px; margin-top: 24px;">
                  <h5 style="margin: 0 0 8px 0; color: #86efac;">💡 Pro Tips</h5>
                  <ul style="margin: 0; padding-left: 20px; color: var(--muted); font-size: 13px;">
                    <li style="margin-bottom: 8px;">Start with free tiers - you can discover many subdomains without paying</li>
                    <li style="margin-bottom: 8px;">Shodan, VirusTotal, and SecurityTrails offer the best value for free tiers</li>
                    <li style="margin-bottom: 8px;">GitHub token is completely free and very useful for finding subdomains in code</li>
                    <li style="margin-bottom: 8px;">Combine multiple free sources for comprehensive coverage</li>
                    <li>Consider paid plans only if you're doing high-volume scanning regularly</li>
                  </ul>
                </div>

                <button type="submit" style="margin-top: 20px;">Save API Keys</button>
                <div class="status" id="api-keys-status"></div>
              </form>
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
              <h5 style="color: var(--muted); font-size: 14px; margin-top: 16px;">Subdomain Enumeration Tools</h5>
              <label>Amass parallel slots
                <input id="settings-amass" type="number" name="max_parallel_amass" min="1" />
              </label>
              <label>Subfinder parallel slots
                <input id="settings-subfinder" type="number" name="max_parallel_subfinder" min="1" />
              </label>
              <label>Assetfinder parallel slots
                <input id="settings-assetfinder" type="number" name="max_parallel_assetfinder" min="1" />
              </label>
              <label>Findomain parallel slots
                <input id="settings-findomain" type="number" name="max_parallel_findomain" min="1" />
              </label>
              <label>Sublist3r parallel slots
                <input id="settings-sublist3r" type="number" name="max_parallel_sublist3r" min="1" />
              </label>
              <label>Crt.sh parallel slots
                <input id="settings-crtsh" type="number" name="max_parallel_crtsh" min="1" />
              </label>
              <label>GitHub-Subdomains parallel slots
                <input id="settings-github-subdomains" type="number" name="max_parallel_github_subdomains" min="1" />
              </label>
              
              <h5 style="color: var(--muted); font-size: 14px; margin-top: 16px;">DNS & HTTP Tools</h5>
              <label>DNSx parallel slots
                <input id="settings-dnsx" type="number" name="max_parallel_dnsx" min="1" />
              </label>
              <label>HTTPx parallel slots
                <input id="settings-httpx" type="number" name="max_parallel_httpx" min="1" />
              </label>
              <label>FFUF parallel slots
                <input id="settings-ffuf" type="number" name="max_parallel_ffuf" min="1" />
              </label>
              
              <h5 style="color: var(--muted); font-size: 14px; margin-top: 16px;">URL Discovery Tools</h5>
              <label>Waybackurls parallel slots
                <input id="settings-waybackurls" type="number" name="max_parallel_waybackurls" min="1" />
              </label>
              <label>GAU parallel slots
                <input id="settings-gau" type="number" name="max_parallel_gau" min="1" />
              </label>
              
              <h5 style="color: var(--muted); font-size: 14px; margin-top: 16px;">Scanning & Analysis Tools</h5>
              <label>Nuclei parallel slots
                <input id="settings-nuclei" type="number" name="max_parallel_nuclei" min="1" />
              </label>
              <label>Nikto parallel slots
                <input id="settings-nikto" type="number" name="max_parallel_nikto" min="1" />
              </label>
              <label>Screenshot parallel slots
                <input id="settings-gowitness" type="number" name="max_parallel_gowitness" min="1" />
              </label>
            </div>
            
            <div class="card">
              <h3>Dynamic Queue Management</h3>
              <p class="muted">Automatically adjust concurrent jobs based on system resources (CPU, memory, load). Requires psutil to be installed.</p>
              <label class="checkbox">
                <input id="settings-dynamic-mode" type="checkbox" name="dynamic_mode_enabled" />
                Enable Dynamic Mode
              </label>
              <label>Minimum concurrent jobs
                <input id="settings-dynamic-base-jobs" type="number" name="dynamic_mode_base_jobs" min="1" />
              </label>
              <label>Maximum concurrent jobs
                <input id="settings-dynamic-max-jobs" type="number" name="dynamic_mode_max_jobs" min="1" />
              </label>
              <label>CPU threshold (%)
                <input id="settings-dynamic-cpu-threshold" type="number" name="dynamic_mode_cpu_threshold" min="0" max="100" step="0.1" />
              </label>
              <label>Memory threshold (%)
                <input id="settings-dynamic-memory-threshold" type="number" name="dynamic_mode_memory_threshold" min="0" max="100" step="0.1" />
              </label>
              <p class="muted">Dynamic mode will reduce concurrent jobs when CPU or memory usage exceeds the thresholds.</p>
            </div>
          </div>
          
          <div class="settings-subtab-content" data-tab-content="backup">
            <div class="card">
              <h3>Backup & Restore</h3>
              <p class="muted">Create backups of all reconnaissance data including state, configuration, monitors, history, and screenshots.</p>
              
              <h4>Manual Backup</h4>
              <div style="display: flex; gap: 12px; align-items: flex-end; margin-bottom: 20px;">
                <label style="flex: 1;">Backup name (optional)
                  <input id="backup-name-input" type="text" placeholder="e.g., before-upgrade" />
                </label>
                <button id="create-backup-btn" class="btn">Create Backup</button>
              </div>
              
              <h4>Available Backups</h4>
              <div id="backup-list" style="margin-bottom: 20px;">
                <p class="muted">Loading backups...</p>
              </div>
              
              <h4>Auto-Backup Settings</h4>
              <label class="checkbox">
                <input id="settings-auto-backup-enabled" type="checkbox" name="auto_backup_enabled" />
                Enable automatic backups
              </label>
              <label>Backup interval (seconds, minimum 300 = 5 minutes)
                <input id="settings-auto-backup-interval" type="number" name="auto_backup_interval" min="300" step="60" />
              </label>
              <label>Maximum backup count (older backups are auto-deleted)
                <input id="settings-auto-backup-max-count" type="number" name="auto_backup_max_count" min="1" />
              </label>
              <p class="muted">Auto-backups are created with the "auto" prefix and old backups are automatically removed.</p>
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

          <button type="submit" onclick="if(window.saveSettingsNow){console.log('[DEBUG] Button onclick fired'); window.saveSettingsNow(); return false;} else {console.error('[DEBUG] saveSettingsNow not defined yet');}">Save Settings</button>
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
console.log('[DEBUG] Script loading started');
const navLinks = document.querySelectorAll('.nav-link');
const viewSections = document.querySelectorAll('.module');
const SEVERITY_SCALE = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE'];
const SEVERITY_RANK = SEVERITY_SCALE.reduce((acc, label, idx) => {
  acc[label] = idx;
  return acc;
}, {});

// API Key provider constants
const AMASS_PROVIDERS = ['shodan', 'virustotal', 'securitytrails', 'censys', 'passivetotal', 'binaryedge', 'bevigil'];
const SUBFINDER_SHARED_PROVIDERS = ['shodan', 'censys', 'virustotal', 'binaryedge', 'securitytrails', 'passivetotal'];

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
const settingsAmass = document.getElementById('settings-amass');
const settingsSubfinder = document.getElementById('settings-subfinder');
const settingsAssetfinder = document.getElementById('settings-assetfinder');
const settingsFindomain = document.getElementById('settings-findomain');
const settingsSublist3r = document.getElementById('settings-sublist3r');
const settingsCrtsh = document.getElementById('settings-crtsh');
const settingsGithubSubdomains = document.getElementById('settings-github-subdomains');
const settingsDnsx = document.getElementById('settings-dnsx');
const settingsHttpx = document.getElementById('settings-httpx');
const settingsFFUF = document.getElementById('settings-ffuf');
const settingsWaybackurls = document.getElementById('settings-waybackurls');
const settingsGau = document.getElementById('settings-gau');
const settingsNuclei = document.getElementById('settings-nuclei');
const settingsNikto = document.getElementById('settings-nikto');
const settingsGowitness = document.getElementById('settings-gowitness');
const settingsDynamicMode = document.getElementById('settings-dynamic-mode');
const settingsDynamicBaseJobs = document.getElementById('settings-dynamic-base-jobs');
const settingsDynamicMaxJobs = document.getElementById('settings-dynamic-max-jobs');
const settingsDynamicCpuThreshold = document.getElementById('settings-dynamic-cpu-threshold');
const settingsDynamicMemoryThreshold = document.getElementById('settings-dynamic-memory-threshold');
const settingsAutoBackupEnabled = document.getElementById('settings-auto-backup-enabled');
const settingsAutoBackupInterval = document.getElementById('settings-auto-backup-interval');
const settingsAutoBackupMaxCount = document.getElementById('settings-auto-backup-max-count');
const backupNameInput = document.getElementById('backup-name-input');
const createBackupBtn = document.getElementById('create-backup-btn');
const backupList = document.getElementById('backup-list');
const settingsStatus = document.getElementById('settings-status');
const settingsSummary = document.getElementById('settings-summary');
const settingsSaveBtn = document.querySelector('#settings-form button[type="submit"]');
console.log('[DEBUG] All DOM elements retrieved, settingsForm:', settingsForm ? 'found' : 'NULL', 'saveBtn:', settingsSaveBtn ? 'found' : 'NULL');
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
const overviewTargetsList = document.getElementById('overview-targets-list');
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

function linkifyLogText(text) {
  // Escape the text first
  const escaped = escapeHtml(text || '');
  
  // Pattern to match result file names (nikto_*.json, nuclei_*.json, httpx_*.json, etc.)
  const filePattern = /(nikto_[a-zA-Z0-9._-]+\.json|nuclei_[a-zA-Z0-9._-]+\.json|httpx_[a-zA-Z0-9._-]+\.json|ffuf_[a-zA-Z0-9._-]+\.json)/g;
  
  // Replace file references with download links
  return escaped.replace(filePattern, (match) => {
    // Create a download link for the JSON file using the /results/ endpoint
    return `<a href="/results/${match}" download="${match}" class="log-file-link" title="Download ${match}">${match}</a>`;
  });
}

function renderLogEntries(logs) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  if (!safeLogs.length) {
    return '<p class="muted">No output yet.</p>';
  }
  return safeLogs.slice(-200).map(entry => {
    const linkedText = linkifyLogText(entry.text || '');
    return `
      <div class="log-entry">
        <div class="log-meta">${fmtTime(entry.ts)} — ${escapeHtml(entry.source || 'app')}</div>
        <pre class="log-text">${linkedText}</pre>
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

// Pagination state for jobs view
let jobsPaginationState = {
  currentPage: 1,
  pageSize: 10,  // Show 10 jobs per page for performance
  totalPages: 1
};

function renderJobs(jobs) {
  const all = Array.isArray(jobs) ? jobs : [];
  const running = all.filter(job => job.status !== 'queued');
  const activeJobs = running.filter(job => !job.completed_at);
  const completedJobs = running.filter(job => job.completed_at);
  
  // Update the stat to show active + completed
  statActive.textContent = `${activeJobs.length}${completedJobs.length > 0 ? ` (+ ${completedJobs.length} completed)` : ''}`;
  
  if (!running.length) {
    jobsList.innerHTML = '<div class="section-placeholder">No active jobs.</div>';
    const pagerEl = document.getElementById('jobs-pagination');
    if (pagerEl) pagerEl.innerHTML = '';
    return;
  }
  
  // Render active jobs first, then completed jobs
  const sortedJobs = [...activeJobs, ...completedJobs];
  
  // Calculate pagination
  const totalJobs = sortedJobs.length;
  jobsPaginationState.totalPages = Math.max(1, Math.ceil(totalJobs / jobsPaginationState.pageSize));
  
  // Ensure current page is within bounds - handle edge case of 0 pages
  if (totalJobs === 0) {
    jobsPaginationState.currentPage = 1;
  } else if (jobsPaginationState.currentPage > jobsPaginationState.totalPages) {
    jobsPaginationState.currentPage = jobsPaginationState.totalPages;
  }
  
  // Get jobs for current page
  const startIdx = (jobsPaginationState.currentPage - 1) * jobsPaginationState.pageSize;
  const endIdx = startIdx + jobsPaginationState.pageSize;
  const pageJobs = sortedJobs.slice(startIdx, endIdx);
  
  // Render only jobs on current page
  const cards = pageJobs.map(job => {
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
            ${job.completed_at ? `<div class="muted">Completed ${fmtTime(job.completed_at)}</div>` : ''}
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
  
  // Render pagination controls
  renderJobsPagination(totalJobs);
}

function renderJobsPagination(totalJobs) {
  const pagerEl = document.getElementById('jobs-pagination');
  if (!pagerEl) return;
  
  // Don't show pagination if only one page
  if (jobsPaginationState.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  
  const state = jobsPaginationState;
  pagerEl.innerHTML = `
    <span class="page-info">Showing ${(state.currentPage - 1) * state.pageSize + 1}-${Math.min(state.currentPage * state.pageSize, totalJobs)} of ${totalJobs} jobs</span>
    <button data-jobs-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-jobs-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-jobs-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-jobs-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

// Handle jobs pagination clicks
// Note: Using document-level event delegation because pagination buttons are dynamically rendered
document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-jobs-page-action]');
  if (!btn) return;
  
  const action = btn.getAttribute('data-jobs-page-action');
  if (action === 'prev') {
    jobsPaginationState.currentPage = Math.max(1, jobsPaginationState.currentPage - 1);
  } else if (action === 'next') {
    jobsPaginationState.currentPage = Math.min(jobsPaginationState.totalPages, jobsPaginationState.currentPage + 1);
  } else if (action === 'first') {
    jobsPaginationState.currentPage = 1;
  } else if (action === 'last') {
    jobsPaginationState.currentPage = jobsPaginationState.totalPages;
  }
  
  // Re-render jobs with new page - latestRunningJobs is already filtered/sorted from API
  renderJobs(latestRunningJobs);
});

// Pagination state for queue view
let queuePaginationState = {
  currentPage: 1,
  pageSize: 10,  // Show 10 queued jobs per page
  totalPages: 1
};

function renderQueue(queue) {
  const items = Array.isArray(queue) ? queue : [];
  statQueued.textContent = items.length;
  if (!items.length) {
    queueList.innerHTML = '<div class="section-placeholder">Queue empty.</div>';
    const pagerEl = document.getElementById('queue-pagination');
    if (pagerEl) pagerEl.innerHTML = '';
    return;
  }
  
  // Calculate pagination
  const totalItems = items.length;
  queuePaginationState.totalPages = Math.max(1, Math.ceil(totalItems / queuePaginationState.pageSize));
  
  // Ensure current page is within bounds - handle edge case of 0 pages
  if (totalItems === 0) {
    queuePaginationState.currentPage = 1;
  } else if (queuePaginationState.currentPage > queuePaginationState.totalPages) {
    queuePaginationState.currentPage = queuePaginationState.totalPages;
  }
  
  // Get items for current page
  const startIdx = (queuePaginationState.currentPage - 1) * queuePaginationState.pageSize;
  const endIdx = startIdx + queuePaginationState.pageSize;
  const pageItems = items.slice(startIdx, endIdx);
  
  // Render only items on current page
  const cards = pageItems.map((job) => {
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
  
  // Render pagination controls
  renderQueuePagination(totalItems);
}

function renderQueuePagination(totalItems) {
  const pagerEl = document.getElementById('queue-pagination');
  if (!pagerEl) return;
  
  // Don't show pagination if only one page
  if (queuePaginationState.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  
  const state = queuePaginationState;
  pagerEl.innerHTML = `
    <span class="page-info">Showing ${(state.currentPage - 1) * state.pageSize + 1}-${Math.min(state.currentPage * state.pageSize, totalItems)} of ${totalItems} queued jobs</span>
    <button data-queue-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-queue-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-queue-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-queue-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

// Handle queue pagination clicks
// Note: Using document-level event delegation because pagination buttons are dynamically rendered
document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-queue-page-action]');
  if (!btn) return;
  
  const action = btn.getAttribute('data-queue-page-action');
  if (action === 'prev') {
    queuePaginationState.currentPage = Math.max(1, queuePaginationState.currentPage - 1);
  } else if (action === 'next') {
    queuePaginationState.currentPage = Math.min(queuePaginationState.totalPages, queuePaginationState.currentPage + 1);
  } else if (action === 'first') {
    queuePaginationState.currentPage = 1;
  } else if (action === 'last') {
    queuePaginationState.currentPage = queuePaginationState.totalPages;
  }
  
  // Re-render queue with new page - latestQueuedJobs is already from API
  renderQueue(latestQueuedJobs);
});

function renderOverviewTargets(targets) {
  const entries = Object.entries(targets || {});
  if (!entries.length || !overviewTargetsList) {
    if (overviewTargetsList) {
      overviewTargetsList.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    }
    return;
  }
  
  // Get filter values from localStorage or defaults
  const overviewFilters = getOverviewFilters();
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (overviewFilters.domainSearch && !domain.toLowerCase().includes(overviewFilters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (overviewFilters.status !== 'all') {
      const isPending = info && info.pending;
      if (overviewFilters.status === 'pending' && !isPending) return false;
      if (overviewFilters.status === 'complete' && isPending) return false;
    }
    
    return true;
  });
  
  filteredEntries.sort((a, b) => a[0].localeCompare(b[0]));
  
  // Add filter controls
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 12px; background: var(--panel); border-radius: 8px; border: 1px solid #1f2937;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="overview-domain-search" placeholder="example.com" value="${escapeHtml(overviewFilters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="overview-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${overviewFilters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${overviewFilters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${overviewFilters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} targets
      </div>
    </div>
  `;
  
  const tableRows = filteredEntries.map(([domain, info], idx) => {
    const subs = (info && info.subdomains) || {};
    const subCount = Object.keys(subs).length;
    const isPending = info && info.pending;
    const statusBadge = isPending 
      ? '<span class="badge pending">Pending</span>'
      : '<span class="badge complete">Complete</span>';
    
    // Count findings
    let nucleiCount = 0;
    let niktoCount = 0;
    Object.values(subs).forEach(entry => {
      nucleiCount += Array.isArray(entry.nuclei) ? entry.nuclei.length : 0;
      niktoCount += Array.isArray(entry.nikto) ? entry.nikto.length : 0;
    });
    const findingsCount = nucleiCount + niktoCount;
    
    return `
      <tr>
        <td>${idx + 1}</td>
        <td><a href="/domain/${encodeURIComponent(domain)}" class="link-btn">${escapeHtml(domain)}</a></td>
        <td>${subCount}</td>
        <td>${findingsCount}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
  
  const table = `
    <div class="table-wrapper">
      <table class="targets-table" id="overview-targets-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Domain</th>
            <th>Subdomains</th>
            <th>Findings</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${tableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="overview-targets-pagination"></div>
  `;
  
  overviewTargetsList.innerHTML = filterControls + table;
  
  // Attach filter event listeners
  attachOverviewFilterListeners();
  
  // Initialize pagination
  const tableEl = document.getElementById('overview-targets-table');
  const pagerEl = document.getElementById('overview-targets-pagination');
  if (tableEl && pagerEl) {
    initPagination(tableEl, pagerEl, DEFAULT_PAGE_SIZE);
  }
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
  
  // Get filter values from localStorage or defaults
  const targetFilters = getTargetFilters();
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (targetFilters.domainSearch && !domain.toLowerCase().includes(targetFilters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (targetFilters.status !== 'all') {
      const isPending = info && info.pending;
      if (targetFilters.status === 'pending' && !isPending) return false;
      if (targetFilters.status === 'complete' && isPending) return false;
    }
    
    // Has subdomains filter
    if (targetFilters.hasSubdomains) {
      const subs = (info && info.subdomains) || {};
      if (Object.keys(subs).length === 0) return false;
    }
    
    return true;
  });
  
  filteredEntries.sort((a, b) => a[0].localeCompare(b[0]));
  let subCount = 0;
  
  // Add filter controls and export buttons at the top
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 16px; background: var(--panel-alt); border-radius: 12px; border: 1px solid #1f2937;">
      <h3 style="margin: 0 0 12px 0; font-size: 14px; color: #93c5fd;">Filter Targets</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="target-domain-search" placeholder="example.com" value="${escapeHtml(targetFilters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="target-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${targetFilters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${targetFilters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${targetFilters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
        <div style="display: flex; align-items: flex-end;">
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer; padding: 8px 0;">
            <input type="checkbox" id="target-has-subdomains" ${targetFilters.hasSubdomains ? 'checked' : ''}>
            Has Subdomains
          </label>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} targets
      </div>
    </div>
  `;
  
  const exportButtons = `
    <div class="export-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
      <a class="btn secondary small" href="/api/export/state" target="_blank">Export JSON</a>
      <a class="btn secondary small" href="/api/export/csv" target="_blank">Export CSV</a>
    </div>
  `;
  
  const cards = filteredEntries.map(([domain, info]) => {
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
    
    // Generate node map visualization
    const nodeMapId = `node-map-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const nodeMap = keys.length > 0 ? `
      <div style="margin: 16px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h4 style="margin: 0; font-size: 14px; color: #93c5fd;">Subdomain Network Map</h4>
          <button class="btn small" onclick="toggleNodeMap('${nodeMapId}')">Toggle Map</button>
        </div>
        <div id="${nodeMapId}" style="display: none;">
          <canvas id="${nodeMapId}-canvas" width="800" height="400" style="width: 100%; height: 400px; background: #050b18; border-radius: 12px; border: 1px solid #1f2937; cursor: pointer;"></canvas>
        </div>
      </div>
    ` : '';
    
    return `
      <div class="target-card" data-domain="${escapeHtml(domain)}">
        <div class="job-summary">
          <div><a href="/domain/${encodeURIComponent(domain)}" class="link-btn" style="font-size: 1.1rem; font-weight: 600;">${escapeHtml(domain)}</a></div>
          <div>${badges}</div>
        </div>
        ${nodeMap}
        ${table}
      </div>
    `;
  });
  statSubs.textContent = subCount;
  targetsList.innerHTML = exportButtons + filterControls + cards.join('');
  
  // Attach filter event listeners
  attachTargetFilterListeners();
  
  // Initialize pagination for each target's table
  filteredEntries.forEach(([domain]) => {
    const tableId = `targets-table-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const paginationId = `targets-pagination-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const table = document.getElementById(tableId);
    const pagerEl = document.getElementById(paginationId);
    if (table && pagerEl) {
      initPagination(table, pagerEl, DEFAULT_PAGE_SIZE);
    }
  });
  
  // Initialize node maps
  entries.forEach(([domain, info]) => {
    const nodeMapId = `node-map-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    initNodeMap(domain, info, nodeMapId);
  });
}

// Node map visualization functions
function toggleNodeMap(mapId) {
  const mapEl = document.getElementById(mapId);
  if (mapEl) {
    const isVisible = mapEl.style.display !== 'none';
    mapEl.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
      // Redraw when shown
      const canvasId = `${mapId}-canvas`;
      const canvas = document.getElementById(canvasId);
      if (canvas && canvas.dataset.domain) {
        drawNodeMap(canvas);
      }
    }
  }
}

function initNodeMap(domain, info, mapId) {
  const canvasId = `${mapId}-canvas`;
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  
  const subs = (info && info.subdomains) || {};
  const subdomains = Object.keys(subs).sort();
  
  // Store data in canvas dataset
  canvas.dataset.domain = domain;
  canvas.dataset.subdomains = JSON.stringify(subdomains);
  
  // Set actual canvas resolution
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = rect.height * window.devicePixelRatio;
  
  // Draw the node map
  drawNodeMap(canvas);
  
  // Add click handler
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) * (canvas.width / rect.width);
    const y = (e.clientY - rect.top) * (canvas.height / rect.height);
    handleNodeMapClick(canvas, x, y);
  });
}

function drawNodeMap(canvas) {
  const ctx = canvas.getContext('2d');
  const domain = canvas.dataset.domain;
  const subdomains = JSON.parse(canvas.dataset.subdomains || '[]');
  
  const width = canvas.width;
  const height = canvas.height;
  
  // Clear canvas
  ctx.clearRect(0, 0, width, height);
  
  // Draw background
  ctx.fillStyle = '#050b18';
  ctx.fillRect(0, 0, width, height);
  
  if (subdomains.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = `${16 * window.devicePixelRatio}px system-ui`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No subdomains to display', width / 2, height / 2);
    return;
  }
  
  // Calculate layout
  const centerX = width / 2;
  const centerY = height / 2;
  const domainRadius = 30 * window.devicePixelRatio;
  const subRadius = 15 * window.devicePixelRatio;
  const orbitRadius = Math.min(width, height) * 0.35;
  
  // Store node positions for click detection
  const nodes = [];
  
  // Draw connections from domain to subdomains
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2 * window.devicePixelRatio;
  subdomains.forEach((sub, i) => {
    const angle = (i / subdomains.length) * Math.PI * 2 - Math.PI / 2;
    const x = centerX + Math.cos(angle) * orbitRadius;
    const y = centerY + Math.sin(angle) * orbitRadius;
    
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(x, y);
    ctx.stroke();
  });
  
  // Draw subdomain nodes
  subdomains.forEach((sub, i) => {
    const angle = (i / subdomains.length) * Math.PI * 2 - Math.PI / 2;
    const x = centerX + Math.cos(angle) * orbitRadius;
    const y = centerY + Math.sin(angle) * orbitRadius;
    
    // Node circle
    ctx.fillStyle = '#2563eb';
    ctx.beginPath();
    ctx.arc(x, y, subRadius, 0, Math.PI * 2);
    ctx.fill();
    
    // Node border
    ctx.strokeStyle = '#60a5fa';
    ctx.lineWidth = 2 * window.devicePixelRatio;
    ctx.stroke();
    
    // Store for click detection
    nodes.push({ x, y, radius: subRadius, subdomain: sub, type: 'subdomain' });
    
    // Label (only show if space allows)
    if (subdomains.length < 20) {
      ctx.fillStyle = '#e2e8f0';
      ctx.font = `${11 * window.devicePixelRatio}px system-ui`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const labelY = y + subRadius + 15 * window.devicePixelRatio;
      const shortLabel = sub.length > 15 ? sub.substring(0, 12) + '...' : sub;
      ctx.fillText(shortLabel, x, labelY);
    }
  });
  
  // Draw domain node (center)
  ctx.fillStyle = '#1d4ed8';
  ctx.beginPath();
  ctx.arc(centerX, centerY, domainRadius, 0, Math.PI * 2);
  ctx.fill();
  
  ctx.strokeStyle = '#3b82f6';
  ctx.lineWidth = 3 * window.devicePixelRatio;
  ctx.stroke();
  
  // Domain label
  ctx.fillStyle = '#ffffff';
  ctx.font = `bold ${14 * window.devicePixelRatio}px system-ui`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const domainLabel = domain.length > 12 ? domain.substring(0, 10) + '...' : domain;
  ctx.fillText(domainLabel, centerX, centerY);
  
  // Store domain node
  nodes.push({ x: centerX, y: centerY, radius: domainRadius, domain: domain, type: 'domain' });
  
  // Store nodes in canvas dataset for click handling
  canvas.dataset.nodes = JSON.stringify(nodes);
  
  // Draw legend
  ctx.fillStyle = '#94a3b8';
  ctx.font = `${10 * window.devicePixelRatio}px system-ui`;
  ctx.textAlign = 'left';
  ctx.fillText(`${subdomains.length} subdomains`, 10 * window.devicePixelRatio, height - 10 * window.devicePixelRatio);
}

function handleNodeMapClick(canvas, x, y) {
  const nodes = JSON.parse(canvas.dataset.nodes || '[]');
  const domain = canvas.dataset.domain;
  
  // Check if click is on any node
  for (const node of nodes) {
    const dx = x - node.x;
    const dy = y - node.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    
    if (distance <= node.radius) {
      if (node.type === 'subdomain') {
        // Navigate to subdomain detail page
        window.location.href = `/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(node.subdomain)}`;
      } else if (node.type === 'domain') {
        // Could navigate to domain report or do nothing
        const reportsLink = document.querySelector(`a[href="#reports"]`);
        if (reportsLink) {
          reportsLink.click();
          setTimeout(() => {
            const domainCard = document.querySelector(`.report-nav-card[data-report-domain="${domain}"]`);
            if (domainCard) {
              domainCard.click();
            }
          }, 100);
        }
      }
      break;
    }
  }
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
      <div class="workflow-stage-title">Phase 6: Vulnerability Scanning</div>
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
  const dynamicMode = workers.dynamic_mode || {};
  const autoBackup = workers.auto_backup || {};
  
  const jobPct = job.limit ? Math.min(100, Math.round((job.active || 0) / job.limit * 100)) : 0;
  
  // Dynamic mode indicator
  let dynamicIndicator = '';
  if (dynamicMode.enabled) {
    dynamicIndicator = `<div class="badge" style="background: #3b82f6; margin-top: 4px;">🔄 Dynamic Mode Active</div>`;
  }
  
  const jobCard = `
    <div class="worker-card">
      <h3>Job Slots</h3>
      <div class="metric">${job.active || 0}/${job.limit || 1}</div>
      <div class="muted">${job.queue || 0} queued</div>
      ${dynamicIndicator}
      <div class="worker-progress">${renderProgress(jobPct, (job.active || 0) >= (job.limit || 1) ? 'running' : 'completed')}</div>
    </div>
  `;
  
  // Add dynamic mode card if enabled
  let dynamicCard = '';
  if (dynamicMode.enabled) {
    dynamicCard = `
      <div class="worker-card">
        <h3>Dynamic Mode</h3>
        <div class="metric">${dynamicMode.current_jobs || 1}</div>
        <div class="muted">Range: ${dynamicMode.base_jobs || 1}–${dynamicMode.max_jobs || 10}</div>
        <div class="muted">CPU &lt; ${dynamicMode.cpu_threshold || 75}% · Mem &lt; ${dynamicMode.memory_threshold || 80}%</div>
      </div>
    `;
  }
  
  // Add auto-backup card if enabled
  let backupCard = '';
  if (autoBackup.enabled) {
    const nextBackup = autoBackup.next_backup ? new Date(autoBackup.next_backup).toLocaleTimeString() : 'N/A';
    backupCard = `
      <div class="worker-card">
        <h3>Auto-Backup</h3>
        <div class="metric">💾 Active</div>
        <div class="muted">Next: ${nextBackup}</div>
        <div class="muted">Keep last ${autoBackup.max_count || 10}</div>
      </div>
    `;
  }
  
  // Add rate limiting card
  const rateLimiting = workers.rate_limiting || {};
  const currentDelay = rateLimiting.current_delay || 0;
  const maxBackoff = rateLimiting.max_auto_backoff || 30;
  const timeoutTracker = rateLimiting.timeout_tracker || {};
  const activeRateLimits = Object.keys(timeoutTracker).length;
  
  let rateLimitStatus = 'inactive';
  let rateLimitClass = 'muted';
  if (currentDelay > 0) {
    rateLimitStatus = 'active';
    rateLimitClass = 'warning';
  }
  
  const rateLimitCard = `
    <div class="worker-card ${currentDelay > 0 ? 'rate-limit-active' : ''}">
      <h3>Rate Limiting</h3>
      <div class="metric ${rateLimitClass}">${currentDelay.toFixed(1)}s</div>
      <div class="muted">delay between calls</div>
      ${activeRateLimits > 0 ? `<div class="warning">⚠️ ${activeRateLimits} tracked domain(s)</div>` : ''}
    </div>
  `;
  
  const tools = workers.tools || {};
  const toolCards = Object.keys(tools).sort().map(name => {
    const info = tools[name] || {};
    const limit = info.limit;
    const active = info.active || 0;
    const queued = info.queued || 0;
    
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
      // Tool with gate - show active/limit and queued items
      const pct = limit ? Math.min(100, Math.round(active / limit * 100)) : 0;
      const queueInfo = queued > 0 ? `<div class="muted" style="margin-top: 4px;">📋 ${queued} queued</div>` : '';
      return `
        <div class="worker-card">
          <h3>${escapeHtml(name)}</h3>
          <div class="metric">${active}/${limit}</div>
          <div class="muted">slots in use</div>
          ${queueInfo}
          <div class="worker-progress">${renderProgress(pct, active >= limit ? 'running' : 'completed')}</div>
        </div>
      `;
    }
  }).join('') || '<div class="section-placeholder">No tool data.</div>';
  workersBody.innerHTML = `<div class="worker-grid">${jobCard}${dynamicCard}${backupCard}${rateLimitCard}${toolCards}</div>`;
}

function renderSystemResources(data) {
  const resourcesBody = document.getElementById('resources-body');
  if (!resourcesBody) return;
  
  if (!data || !data.current || !data.current.available) {
    const errorMsg = data && data.current ? data.current.error : 'System resource monitoring unavailable';
    resourcesBody.innerHTML = `<div class="section-placeholder">⚠️ ${escapeHtml(errorMsg)}</div>`;
    return;
  }
  
  const current = data.current;
  const history = data.history || [];
  
  // Helper to get status class
  function getStatusClass(percent, criticalThreshold, warningThreshold) {
    if (percent >= criticalThreshold) return 'critical';
    if (percent >= warningThreshold) return 'warning';
    return 'normal';
  }
  
  // CPU metrics
  const cpu = current.cpu || {};
  const cpuPercent = cpu.percent || 0;
  const cpuClass = getStatusClass(cpuPercent, 90, 75);
  
  // Memory metrics
  const memory = current.memory || {};
  const memPercent = memory.percent || 0;
  const memClass = getStatusClass(memPercent, 90, 80);
  
  // Disk metrics
  const disk = current.disk || {};
  const diskPercent = disk.percent || 0;
  const diskClass = getStatusClass(diskPercent, 95, 85);
  
  // Process metrics
  const process = current.process || {};
  
  // Warnings
  const warnings = current.warnings || [];
  let warningsHtml = '';
  if (warnings.length > 0) {
    const criticalWarnings = warnings.filter(w => w.severity === 'critical');
    const normalWarnings = warnings.filter(w => w.severity !== 'critical');
    
    const warningItems = [...criticalWarnings, ...normalWarnings].map(w => {
      const icon = w.severity === 'critical' ? '🔴' : '⚠️';
      const cls = w.severity === 'critical' ? 'critical' : 'warning';
      return `<div class="resource-warning ${cls}">${icon} ${escapeHtml(w.message)}</div>`;
    }).join('');
    
    warningsHtml = `
      <div class="resource-warnings-section">
        <h3>⚠️ Resource Warnings (${warnings.length})</h3>
        ${warningItems}
      </div>
    `;
  }
  
  // Build main metrics grid
  const metricsHtml = `
    <div class="resource-grid">
      <div class="resource-card ${cpuClass}">
        <h3>CPU Usage</h3>
        <div class="resource-metric">${cpuPercent.toFixed(1)}%</div>
        <div class="muted">${cpu.count_logical || 0} logical cores</div>
        <div class="worker-progress">${renderProgress(cpuPercent, cpuClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Load Average:</span>
            <span class="resource-value">${cpu.load_avg_1m || 0} / ${cpu.load_avg_5m || 0} / ${cpu.load_avg_15m || 0}</span>
          </div>
          ${cpu.frequency_mhz ? `
          <div class="resource-detail-item">
            <span class="resource-label">Frequency:</span>
            <span class="resource-value">${cpu.frequency_mhz} MHz</span>
          </div>
          ` : ''}
        </div>
      </div>
      
      <div class="resource-card ${memClass}">
        <h3>Memory Usage</h3>
        <div class="resource-metric">${memPercent.toFixed(1)}%</div>
        <div class="muted">${memory.used_gb || 0} / ${memory.total_gb || 0} GB</div>
        <div class="worker-progress">${renderProgress(memPercent, memClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Available:</span>
            <span class="resource-value">${memory.available_gb || 0} GB</span>
          </div>
        </div>
      </div>
      
      <div class="resource-card ${diskClass}">
        <h3>Disk Usage</h3>
        <div class="resource-metric">${diskPercent.toFixed(1)}%</div>
        <div class="muted">${disk.used_gb || 0} / ${disk.total_gb || 0} GB</div>
        <div class="worker-progress">${renderProgress(diskPercent, diskClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Free:</span>
            <span class="resource-value">${disk.free_gb || 0} GB</span>
          </div>
        </div>
      </div>
      
      <div class="resource-card">
        <h3>Application</h3>
        <div class="resource-metric">${process.cpu_percent || 0}%</div>
        <div class="muted">${process.memory_mb || 0} MB used</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Processes:</span>
            <span class="resource-value">${process.count || 1}</span>
          </div>
          <div class="resource-detail-item">
            <span class="resource-label">Threads:</span>
            <span class="resource-value">${process.threads || 0}</span>
          </div>
          <div class="resource-detail-item">
            <span class="resource-label">PID:</span>
            <span class="resource-value">${process.pid || 'N/A'}</span>
          </div>
        </div>
      </div>
    </div>
  `;
  
  // Build history chart (simple ASCII-style visualization)
  let historyHtml = '';
  if (history.length > 0) {
    const recentHistory = history.slice(-60); // Last 5 minutes at 5s intervals
    const maxDataPoints = Math.min(recentHistory.length, 60);
    const step = Math.ceil(recentHistory.length / maxDataPoints);
    const chartData = [];
    
    for (let i = 0; i < recentHistory.length; i += step) {
      chartData.push(recentHistory[i]);
    }
    
    // Create simple chart representation
    const chartWidth = 100;
    const cpuPoints = chartData.map(d => d.cpu_percent || 0);
    const memPoints = chartData.map(d => d.memory_percent || 0);
    
    const cpuLine = cpuPoints.map(v => Math.round(v)).join(', ');
    const memLine = memPoints.map(v => Math.round(v)).join(', ');
    
    historyHtml = `
      <div class="resource-history">
        <h3>Usage History (Last 5 Minutes)</h3>
        <div class="resource-history-grid">
          <div class="resource-history-item">
            <span class="resource-history-label">CPU:</span>
            <div class="resource-history-sparkline">
              ${cpuPoints.map((v, i) => {
                const height = Math.min(100, Math.max(5, v));
                const color = v > 90 ? '#dc2626' : v > 75 ? '#f59e0b' : '#10b981';
                return `<div class="sparkline-bar" style="height: ${height}%; background: ${color};" title="${v.toFixed(1)}%"></div>`;
              }).join('')}
            </div>
            <span class="resource-history-current">${cpuPercent.toFixed(1)}%</span>
          </div>
          <div class="resource-history-item">
            <span class="resource-history-label">Memory:</span>
            <div class="resource-history-sparkline">
              ${memPoints.map((v, i) => {
                const height = Math.min(100, Math.max(5, v));
                const color = v > 90 ? '#dc2626' : v > 80 ? '#f59e0b' : '#3b82f6';
                return `<div class="sparkline-bar" style="height: ${height}%; background: ${color};" title="${v.toFixed(1)}%"></div>`;
              }).join('')}
            </div>
            <span class="resource-history-current">${memPercent.toFixed(1)}%</span>
          </div>
        </div>
      </div>
    `;
  }
  
  // Additional system info
  const networkHtml = `
    <div class="resource-network">
      <h3>Network I/O</h3>
      <div class="resource-network-grid">
        <div class="resource-network-item">
          <span class="resource-label">Sent:</span>
          <span class="resource-value">${formatBytes(current.network?.bytes_sent || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Received:</span>
          <span class="resource-value">${formatBytes(current.network?.bytes_recv || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Packets Sent:</span>
          <span class="resource-value">${formatNumber(current.network?.packets_sent || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Packets Received:</span>
          <span class="resource-value">${formatNumber(current.network?.packets_recv || 0)}</span>
        </div>
      </div>
    </div>
  `;
  
  resourcesBody.innerHTML = warningsHtml + metricsHtml + historyHtml + networkHtml;
}

// Helper functions for formatting
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
  return num.toString().replace(/\\B(?=(\\d{3})+(?!\\d))/g, ",");
}

async function fetchSystemResources() {
  try {
    const resp = await fetch('/api/system-resources');
    if (!resp.ok) throw new Error('Failed to fetch system resources');
    const data = await resp.json();
    renderSystemResources(data);
  } catch (err) {
    const resourcesBody = document.getElementById('resources-body');
    if (resourcesBody) {
      resourcesBody.innerHTML = `<div class="section-placeholder">Error: ${escapeHtml(err.message)}</div>`;
    }
  }
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

// Report filter management
function getReportFilters() {
  try {
    const saved = localStorage.getItem('reportFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all',
      maxSeverity: 'all',
      hasFindings: false,
      hasScreenshots: false
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all',
      maxSeverity: 'all',
      hasFindings: false,
      hasScreenshots: false
    };
  }
}

function saveReportFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('report-domain-search')?.value || '';
    const status = document.getElementById('report-status-filter')?.value || 'all';
    const maxSeverity = document.getElementById('report-severity-filter')?.value || 'all';
    const hasFindings = document.getElementById('report-has-findings')?.checked || false;
    const hasScreenshots = document.getElementById('report-has-screenshots')?.checked || false;
    
    localStorage.setItem('reportFilters', JSON.stringify({
      domainSearch,
      status,
      maxSeverity,
      hasFindings,
      hasScreenshots
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachReportFilterListeners() {
  const domainSearch = document.getElementById('report-domain-search');
  const statusFilter = document.getElementById('report-status-filter');
  const severityFilter = document.getElementById('report-severity-filter');
  const findingsFilter = document.getElementById('report-has-findings');
  const screenshotsFilter = document.getElementById('report-has-screenshots');
  
  const applyFilters = () => {
    saveReportFiltersToStorage();
    renderReports(latestTargetsData);
  };
  
  if (domainSearch) {
    domainSearch.addEventListener('input', applyFilters);
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
  if (severityFilter) {
    severityFilter.addEventListener('change', applyFilters);
  }
  if (findingsFilter) {
    findingsFilter.addEventListener('change', applyFilters);
  }
  if (screenshotsFilter) {
    screenshotsFilter.addEventListener('change', applyFilters);
  }
}

// Target filter management
function getTargetFilters() {
  try {
    const saved = localStorage.getItem('targetFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all',
      hasSubdomains: false
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all',
      hasSubdomains: false
    };
  }
}

function saveTargetFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('target-domain-search')?.value || '';
    const status = document.getElementById('target-status-filter')?.value || 'all';
    const hasSubdomains = document.getElementById('target-has-subdomains')?.checked || false;
    
    localStorage.setItem('targetFilters', JSON.stringify({
      domainSearch,
      status,
      hasSubdomains
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachTargetFilterListeners() {
  const domainSearch = document.getElementById('target-domain-search');
  const statusFilter = document.getElementById('target-status-filter');
  const subdomainsFilter = document.getElementById('target-has-subdomains');
  
  const applyFilters = () => {
    saveTargetFiltersToStorage();
    renderTargets(latestTargetsData);
  };
  
  if (domainSearch) {
    domainSearch.addEventListener('input', applyFilters);
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
  if (subdomainsFilter) {
    subdomainsFilter.addEventListener('change', applyFilters);
  }
}

// Overview filter management
function getOverviewFilters() {
  try {
    const saved = localStorage.getItem('overviewFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all'
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all'
    };
  }
}

function saveOverviewFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('overview-domain-search')?.value || '';
    const status = document.getElementById('overview-status-filter')?.value || 'all';
    
    localStorage.setItem('overviewFilters', JSON.stringify({
      domainSearch,
      status
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachOverviewFilterListeners() {
  const domainSearch = document.getElementById('overview-domain-search');
  const statusFilter = document.getElementById('overview-status-filter');
  
  const applyFilters = () => {
    saveOverviewFiltersToStorage();
    renderOverviewTargets(latestTargetsData);
  };
  
  if (domainSearch) {
    domainSearch.addEventListener('input', applyFilters);
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
}

function renderReports(targets) {
  latestTargetsData = targets || {};
  
  // Get filter values
  const filters = getReportFilters();
  
  const entries = Object.entries(latestTargetsData);
  if (!entries.length) {
    reportsBody.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    selectedReportDomain = null;
    return;
  }
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (filters.domainSearch && !domain.toLowerCase().includes(filters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (filters.status !== 'all') {
      const isPending = info && info.pending;
      if (filters.status === 'pending' && !isPending) return false;
      if (filters.status === 'complete' && isPending) return false;
    }
    
    // Severity filter
    if (filters.maxSeverity !== 'all') {
      const stats = computeReportStats(info || {});
      const severity = stats.maxSeverity || 'NONE';
      const severityLevels = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const filterIndex = severityLevels.indexOf(filters.maxSeverity);
      const domainIndex = severityLevels.indexOf(severity);
      if (domainIndex < filterIndex) return false;
    }
    
    // Has findings filter
    if (filters.hasFindings) {
      const stats = computeReportStats(info || {});
      if (stats.nuclei === 0 && stats.nikto === 0) return false;
    }
    
    // Has screenshots filter
    if (filters.hasScreenshots) {
      const stats = computeReportStats(info || {});
      if (stats.screenshots === 0) return false;
    }
    
    return true;
  });
  
  // Sort filtered entries
  filteredEntries.sort((a, b) => {
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
    selectedReportDomain = filteredEntries.length > 0 ? filteredEntries[0][0] : null;
  }
  
  const cards = filteredEntries.map(([domain, info]) => {
    const stats = computeReportStats(info || {});
    const badge = info && info.pending
      ? '<span class="report-badge pending">Pending</span>'
      : '<span class="report-badge complete">Complete</span>';
    const severity = stats.maxSeverity || 'NONE';
    const severityText = formatSeverityLabel(severity);
    const severityFlag = `<span class="severity-flag ${escapeHtml(severity)}">Max: ${escapeHtml(severityText)}</span>`;
    
    // Add completion timestamp if available
    // Only show timestamp for completed (non-pending) reports with a completion time
    let completedAtText = '';
    if (info && info.completed_at && !info.pending) {
      const completedDate = new Date(info.completed_at);
      const timeStr = completedDate.toLocaleString();
      completedAtText = `<span style="font-size: 11px; color: #94a3b8; display: block; margin-top: 4px;">Completed: ${escapeHtml(timeStr)}</span>`;
    }
    
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
        ${completedAtText}
      </div>
    `;
  }).join('');
  
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 16px; background: var(--panel-alt); border-radius: 12px; border: 1px solid #1f2937;">
      <h3 style="margin: 0 0 12px 0; font-size: 14px; color: #93c5fd;">Filter Reports</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="report-domain-search" placeholder="example.com" value="${escapeHtml(filters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="report-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${filters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${filters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${filters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Min Severity</label>
          <select id="report-severity-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${filters.maxSeverity === 'all' ? 'selected' : ''}>All</option>
            <option value="INFO" ${filters.maxSeverity === 'INFO' ? 'selected' : ''}>Info+</option>
            <option value="LOW" ${filters.maxSeverity === 'LOW' ? 'selected' : ''}>Low+</option>
            <option value="MEDIUM" ${filters.maxSeverity === 'MEDIUM' ? 'selected' : ''}>Medium+</option>
            <option value="HIGH" ${filters.maxSeverity === 'HIGH' ? 'selected' : ''}>High+</option>
            <option value="CRITICAL" ${filters.maxSeverity === 'CRITICAL' ? 'selected' : ''}>Critical</option>
          </select>
        </div>
        <div style="display: flex; flex-direction: column; gap: 8px; justify-content: center;">
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="report-has-findings" ${filters.hasFindings ? 'checked' : ''}>
            Has Findings
          </label>
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="report-has-screenshots" ${filters.hasScreenshots ? 'checked' : ''}>
            Has Screenshots
          </label>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} reports
      </div>
    </div>
  `;
  
  reportsBody.innerHTML = `
    <div class="export-actions">
      <a class="btn" href="/api/export/state" target="_blank">Download JSON</a>
      <a class="btn secondary" href="/api/export/csv" target="_blank">Download CSV</a>
    </div>
    ${filterControls}
    <div class="reports-layout">
      <div class="reports-nav" id="reports-nav">${cards}</div>
      <div class="report-detail" id="report-detail"></div>
    </div>
  `;
  
  // Attach filter event listeners
  attachReportFilterListeners();
  
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
  // Endpoints section (URLs from waybackurls and gau)
  const endpoints = info.endpoints || [];
  const endpointsTitle = `Endpoints (${endpoints.length})`;
  const endpointsBody = endpoints.length > 0 ? `
    <div class="filter-bar">
      <input type="search" class="report-search" placeholder="Search endpoints…" data-endpoint-search />
    </div>
    <div class="table-wrapper">
      <table class="targets-table" id="endpoints-table">
        <thead>
          <tr>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          ${endpoints.slice(0, 500).map(url => `
            <tr data-endpoint="${escapeHtml(url.toLowerCase())}">
              <td><a href="${escapeHtml(url)}" target="_blank" class="link-btn">${escapeHtml(url)}</a></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ${endpoints.length > 500 ? `<p class="muted">Showing first 500 of ${endpoints.length} endpoints</p>` : ''}
    <div class="table-pagination" id="endpoints-pagination"></div>
  ` : '<p class="muted">No endpoints discovered yet.</p>';
  
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
    ${endpoints.length > 0 ? renderCollapsibleSection('endpoints', endpointsTitle, endpointsBody, false) : ''}
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
  if (endpoints.length > 0) {
    initPagination(detail.querySelector('#endpoints-table'), detail.querySelector('#endpoints-pagination'), DEFAULT_PAGE_SIZE);
    attachEndpointFilter(detail);
  }
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
  
  // Generate a unique ID for this filter set based on table ID and wrapper attributes
  const tableId = table.id || '';
  const filterId = `severity_filter_${tableId}`;
  
  // Restore saved checkbox states
  checkboxes.forEach((cb, index) => {
    const cbId = `${filterId}_${cb.value}_${index}`;
    const saved = loadCheckboxState(cbId);
    if (saved !== null) {
      cb.checked = saved;
    }
  });
  
  const apply = () => {
    const allowed = new Set(Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value));
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const sev = row.dataset.severity || 'INFO';
      row.dataset.filterHidden = allowed.has(sev) ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  
  checkboxes.forEach((cb, index) => {
    const cbId = `${filterId}_${cb.value}_${index}`;
    cb.addEventListener('change', () => {
      saveCheckboxState(cbId, cb.checked);
      apply();
    });
  });
  
  apply();
}

function attachEndpointFilter(detailEl) {
  const table = detailEl.querySelector('#endpoints-table');
  if (!table) return;
  const searchInput = detailEl.querySelector('[data-endpoint-search]');
  if (!searchInput) return;
  
  const apply = () => {
    const query = (searchInput.value || '').trim().toLowerCase();
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const endpoint = row.dataset.endpoint || '';
      const matchesSearch = !query || endpoint.includes(query);
      row.dataset.filterHidden = matchesSearch ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  
  searchInput.addEventListener('input', apply);
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
  
  // Save collapsible state to localStorage
  const collapsibleId = container.getAttribute('data-collapsible');
  if (collapsibleId) {
    saveCollapsibleState(collapsibleId, container.classList.contains('open'));
  }
});

// Functions to manage collapsible state
function saveCollapsibleState(id, isOpen) {
  try {
    localStorage.setItem(`collapsible_${id}`, isOpen ? '1' : '0');
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadCollapsibleState(id) {
  try {
    const saved = localStorage.getItem(`collapsible_${id}`);
    return saved === '1';
  } catch (e) {
    return false;
  }
}

function restoreAllCollapsibleStates() {
  const collapsibles = document.querySelectorAll('.collapsible[data-collapsible]');
  collapsibles.forEach(container => {
    const id = container.getAttribute('data-collapsible');
    if (id && loadCollapsibleState(id)) {
      container.classList.add('open');
    }
  });
}
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
    settingsAmass.value = config.max_parallel_amass || 1;
    settingsSubfinder.value = config.max_parallel_subfinder || 1;
    settingsAssetfinder.value = config.max_parallel_assetfinder || 1;
    settingsFindomain.value = config.max_parallel_findomain || 1;
    settingsSublist3r.value = config.max_parallel_sublist3r || 1;
    settingsCrtsh.value = config.max_parallel_crtsh || 1;
    settingsGithubSubdomains.value = config.max_parallel_github_subdomains || 1;
    settingsDnsx.value = config.max_parallel_dnsx || 1;
    settingsHttpx.value = config.max_parallel_httpx || 1;
    settingsFFUF.value = config.max_parallel_ffuf || 1;
    settingsWaybackurls.value = config.max_parallel_waybackurls || 1;
    settingsGau.value = config.max_parallel_gau || 1;
    settingsNuclei.value = config.max_parallel_nuclei || 1;
    settingsNikto.value = config.max_parallel_nikto || 1;
    settingsGowitness.value = config.max_parallel_gowitness || 1;
    settingsDynamicMode.checked = config.dynamic_mode_enabled || false;
    settingsDynamicBaseJobs.value = config.dynamic_mode_base_jobs || 1;
    settingsDynamicMaxJobs.value = config.dynamic_mode_max_jobs || 10;
    settingsDynamicCpuThreshold.value = config.dynamic_mode_cpu_threshold || 75.0;
    settingsDynamicMemoryThreshold.value = config.dynamic_mode_memory_threshold || 80.0;
    settingsAutoBackupEnabled.checked = config.auto_backup_enabled || false;
    settingsAutoBackupInterval.value = config.auto_backup_interval || 3600;
    settingsAutoBackupMaxCount.value = config.auto_backup_max_count || 10;
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



// Store last ETag for caching
let lastStateETag = null;

async function fetchState() {
  try {
    // Build request with ETag support for caching
    const headers = {};
    if (lastStateETag) {
      headers['If-None-Match'] = lastStateETag;
    }
    
    const resp = await fetch('/api/state', { headers });
    
    // Check for 304 Not Modified - no need to update
    if (resp.status === 304) {
      // Data unchanged, just update timestamp
      const now = new Date().toISOString();
      document.getElementById('last-updated').textContent = 'Last updated: ' + now + ' (cached)';
      return;
    }
    
    if (!resp.ok) throw new Error('Failed to fetch state');
    
    // Store new ETag for next request
    const etag = resp.headers.get('ETag');
    if (etag) {
      lastStateETag = etag;
    }
    
    const data = await resp.json();
    latestConfig = data.config || {};
    latestRunningJobs = data.running_jobs || [];
    latestQueuedJobs = data.queued_jobs || [];
    latestTargetsData = data.targets || {};
    document.getElementById('last-updated').textContent = 'Last updated: ' + (data.last_updated || 'never');
    renderJobs(data.running_jobs || []);
    renderQueue(data.queued_jobs || []);
    renderOverviewTargets(data.targets || {});
    renderTargets(data.targets || {});
    renderSettings(data.config || {}, data.tools || {});
    renderWorkers(data.workers || {});
    renderReports(data.targets || {});
    renderMonitors(data.monitors || []);
    renderGallery(data.targets || {});
    
    // Fetch and render system resources
    await fetchSystemResources();
    
    // Restore collapsible states after rendering
    restoreAllCollapsibleStates();
    
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

if (settingsForm) {
  settingsForm.addEventListener('input', () => { settingsFormDirty = true; });
} else {
  console.error('Settings form not found!');
}

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

if (settingsForm) {
  // Create the save settings function that can be called from anywhere
  window.saveSettingsNow = async function() {
    try {
      console.log('[DEBUG] saveSettingsNow called');
      
      // Validate all required elements exist
      if (!settingsStatus) {
        console.error('settingsStatus element not found');
        alert('Error: Settings status element not found. Please refresh the page.');
        return;
      }
      
      settingsStatus.textContent = 'Saving...';
      settingsStatus.className = 'status';
      
      const payload = {
        default_wordlist: settingsWordlist ? settingsWordlist.value : '',
        default_interval: settingsInterval ? settingsInterval.value : '',
        wildcard_tlds: settingsWildcardTlds ? settingsWildcardTlds.value : '',
        skip_nikto_by_default: settingsSkipNikto ? settingsSkipNikto.checked : false,
        enable_screenshots: settingsEnableScreenshots ? settingsEnableScreenshots.checked : true,
        enable_amass: settingsEnableAmass ? settingsEnableAmass.checked : true,
        amass_timeout: settingsAmassTimeout ? settingsAmassTimeout.value : '',
        enable_subfinder: settingsEnableSubfinder ? settingsEnableSubfinder.checked : true,
        enable_assetfinder: settingsEnableAssetfinder ? settingsEnableAssetfinder.checked : true,
        enable_findomain: settingsEnableFindomain ? settingsEnableFindomain.checked : true,
        enable_sublist3r: settingsEnableSublist3r ? settingsEnableSublist3r.checked : true,
        enable_crtsh: settingsEnableCrtsh ? settingsEnableCrtsh.checked : true,
        enable_github_subdomains: settingsEnableGithubSubdomains ? settingsEnableGithubSubdomains.checked : true,
        enable_dnsx: settingsEnableDnsx ? settingsEnableDnsx.checked : true,
        enable_waybackurls: settingsEnableWaybackurls ? settingsEnableWaybackurls.checked : true,
        enable_gau: settingsEnableGau ? settingsEnableGau.checked : true,
        subfinder_threads: settingsSubfinderThreads ? settingsSubfinderThreads.value : '',
        assetfinder_threads: settingsAssetfinderThreads ? settingsAssetfinderThreads.value : '',
        findomain_threads: settingsFindomainThreads ? settingsFindomainThreads.value : '',
        global_rate_limit: settingsGlobalRateLimit ? settingsGlobalRateLimit.value : '',
        max_running_jobs: settingsMaxJobs ? settingsMaxJobs.value : '',
        max_parallel_amass: settingsAmass ? settingsAmass.value : '',
        max_parallel_subfinder: settingsSubfinder ? settingsSubfinder.value : '',
        max_parallel_assetfinder: settingsAssetfinder ? settingsAssetfinder.value : '',
        max_parallel_findomain: settingsFindomain ? settingsFindomain.value : '',
        max_parallel_sublist3r: settingsSublist3r ? settingsSublist3r.value : '',
        max_parallel_crtsh: settingsCrtsh ? settingsCrtsh.value : '',
        max_parallel_github_subdomains: settingsGithubSubdomains ? settingsGithubSubdomains.value : '',
        max_parallel_dnsx: settingsDnsx ? settingsDnsx.value : '',
        max_parallel_httpx: settingsHttpx ? settingsHttpx.value : '',
        max_parallel_ffuf: settingsFFUF ? settingsFFUF.value : '',
        max_parallel_waybackurls: settingsWaybackurls ? settingsWaybackurls.value : '',
        max_parallel_gau: settingsGau ? settingsGau.value : '',
        max_parallel_nuclei: settingsNuclei ? settingsNuclei.value : '',
        max_parallel_nikto: settingsNikto ? settingsNikto.value : '',
        max_parallel_gowitness: settingsGowitness ? settingsGowitness.value : '',
        dynamic_mode_enabled: settingsDynamicMode ? settingsDynamicMode.checked : false,
        dynamic_mode_base_jobs: settingsDynamicBaseJobs ? settingsDynamicBaseJobs.value : '',
        dynamic_mode_max_jobs: settingsDynamicMaxJobs ? settingsDynamicMaxJobs.value : '',
        dynamic_mode_cpu_threshold: settingsDynamicCpuThreshold ? settingsDynamicCpuThreshold.value : '',
        dynamic_mode_memory_threshold: settingsDynamicMemoryThreshold ? settingsDynamicMemoryThreshold.value : '',
        auto_backup_enabled: settingsAutoBackupEnabled ? settingsAutoBackupEnabled.checked : false,
        auto_backup_interval: settingsAutoBackupInterval ? settingsAutoBackupInterval.value : '',
        auto_backup_max_count: settingsAutoBackupMaxCount ? settingsAutoBackupMaxCount.value : '',
      };
      
      const templatePayload = {};
      Object.entries(templateInputs).forEach(([key, el]) => {
        if (!el) return;
        templatePayload[key] = el.value || '';
      });
      payload.tool_flag_templates = templatePayload;
      
      console.log('Sending settings payload:', payload);
      
      const resp = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      
      console.log('Response status:', resp.status);
      const data = await resp.json();
      console.log('Response data:', data);
      
      settingsStatus.textContent = data.message || 'Saved';
      settingsStatus.className = 'status ' + (data.success ? 'success' : 'error');
      if (data.success) {
        settingsFormDirty = false;
        fetchState();
      }
    } catch (err) {
      console.error('Settings form submission error:', err);
      if (settingsStatus) {
        settingsStatus.textContent = 'Error: ' + err.message;
        settingsStatus.className = 'status error';
      } else {
        alert('Error saving settings: ' + err.message);
      }
    }
  };
  
  // Attach to form submit event
  settingsForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    console.log('[DEBUG] Form submit event fired');
    await window.saveSettingsNow();
  }, true); // Use capture phase
  
  // Also add a direct button click handler with capture
  if (settingsSaveBtn) {
    settingsSaveBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      console.log('[DEBUG] Save button clicked directly (addEventListener), calling saveSettingsNow');
      await window.saveSettingsNow();
    }, true); // Use capture phase to intercept before any other handler
  } else {
    console.error('[DEBUG] settingsSaveBtn not found!');
  }
  
  // Add Enter key support for all settings inputs with capture
  const settingsInputs = settingsForm.querySelectorAll('input, textarea, select');
  console.log('[DEBUG] Found', settingsInputs.length, 'form inputs for Enter key binding');
  settingsInputs.forEach(input => {
    input.addEventListener('keydown', async (event) => {
      if (event.key === 'Enter' && event.target.tagName !== 'TEXTAREA') {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        console.log('[DEBUG] Enter pressed in', event.target.id || event.target.name, ', calling saveSettingsNow');
        await window.saveSettingsNow();
      }
    }, true); // Use capture phase
  });
  
  console.log('[DEBUG] Settings form handlers attached. Form ID:', settingsForm.id, 'Button:', settingsSaveBtn ? 'found' : 'NOT FOUND');
} else {
  console.error('Cannot attach submit handler: settingsForm is null');
}

// API Keys functionality
const apiKeysForm = document.getElementById('api-keys-form');
const apiKeysStatus = document.getElementById('api-keys-status');

// Load existing API keys when settings tab is viewed
async function loadApiKeys() {
  try {
    const resp = await fetch('/api/api-keys');
    if (!resp.ok) throw new Error('Failed to load API keys');
    const data = await resp.json();
    
    // Populate Amass keys
    const amassKeys = data.amass || {};
    AMASS_PROVIDERS.forEach(provider => {
      const input = document.getElementById(`amass-${provider}`);
      if (input && amassKeys[provider]) {
        input.value = amassKeys[provider];
      }
    });
    
    // Populate Subfinder keys
    const subfinderKeys = data.subfinder || {};
    const githubInput = document.getElementById('subfinder-github');
    if (githubInput && subfinderKeys.github) {
      githubInput.value = subfinderKeys.github;
    }
  } catch (err) {
    console.error('Error loading API keys:', err);
  }
}

// Save API keys form handler
if (apiKeysForm) {
  apiKeysForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const amassKeys = {};
    AMASS_PROVIDERS.forEach(provider => {
      const input = document.getElementById(`amass-${provider}`);
      if (input && input.value.trim()) {
        amassKeys[provider] = input.value.trim();
      }
    });
    
    const subfinderKeys = {};
    const githubInput = document.getElementById('subfinder-github');
    if (githubInput && githubInput.value.trim()) {
      subfinderKeys.github = githubInput.value.trim();
    }
    
    // Copy shared keys to Subfinder
    SUBFINDER_SHARED_PROVIDERS.forEach(provider => {
      if (amassKeys[provider]) {
        subfinderKeys[provider] = amassKeys[provider];
      }
    });
    
    try {
      const resp = await fetch('/api/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amass: amassKeys, subfinder: subfinderKeys })
      });
      
      if (!resp.ok) throw new Error('Failed to save API keys');
      const result = await resp.json();
      
      if (result.success) {
        apiKeysStatus.textContent = result.message || 'API keys saved successfully';
        apiKeysStatus.className = 'status success';
        setTimeout(() => {
          apiKeysStatus.textContent = '';
          apiKeysStatus.className = 'status';
        }, 3000);
      } else {
        apiKeysStatus.textContent = result.message || 'Failed to save API keys';
        apiKeysStatus.className = 'status error';
      }
    } catch (err) {
      apiKeysStatus.textContent = err.message;
      apiKeysStatus.className = 'status error';
    }
  });
}

// Load API keys when switching to API Keys tab
settingsTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    if (tab.dataset.tab === 'api-keys') {
      loadApiKeys();
    }
  });
});

// Backup functionality
async function loadBackups() {
  try {
    const resp = await fetch('/api/backups');
    if (!resp.ok) throw new Error('Failed to load backups');
    const data = await resp.json();
    renderBackupsList(data.backups || []);
  } catch (err) {
    if (backupList) {
      backupList.innerHTML = `<p class="muted">Error loading backups: ${escapeHtml(err.message)}</p>`;
    }
  }
}

function renderBackupsList(backups) {
  if (!backupList) return;
  
  if (backups.length === 0) {
    backupList.innerHTML = '<p class="muted">No backups available</p>';
    return;
  }
  
  const html = backups.map(backup => {
    const date = new Date(backup.created);
    const dateStr = date.toLocaleString();
    return `
      <div class="backup-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #0f172a; border-radius: 6px; margin-bottom: 8px;">
        <div>
          <strong>${escapeHtml(backup.filename)}</strong>
          <div class="muted" style="font-size: 0.85rem;">${dateStr} · ${backup.size_mb} MB</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn" onclick="downloadBackup('${escapeHtml(backup.filename)}')">Download</button>
          <button class="btn" onclick="restoreBackup('${escapeHtml(backup.filename)}')">Restore</button>
          <button class="btn" onclick="deleteBackup('${escapeHtml(backup.filename)}')" style="background: #dc2626;">Delete</button>
        </div>
      </div>
    `;
  }).join('');
  
  backupList.innerHTML = html;
}

async function createBackup() {
  if (!createBackupBtn) return;
  
  const originalText = createBackupBtn.textContent;
  createBackupBtn.textContent = 'Creating...';
  createBackupBtn.disabled = true;
  
  try {
    const payload = {};
    if (backupNameInput && backupNameInput.value.trim()) {
      payload.name = backupNameInput.value.trim();
    }
    
    const resp = await fetch('/api/backup/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert(`Backup created successfully: ${data.filename}`);
      if (backupNameInput) backupNameInput.value = '';
      await loadBackups();
    } else {
      alert(`Backup failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error creating backup: ${err.message}`);
  } finally {
    createBackupBtn.textContent = originalText;
    createBackupBtn.disabled = false;
  }
}

function downloadBackup(filename) {
  window.location.href = `/api/backup/download/${encodeURIComponent(filename)}`;
}

async function restoreBackup(filename) {
  if (!confirm(`Are you sure you want to restore from backup "${filename}"? This will overwrite current data.`)) {
    return;
  }
  
  try {
    const resp = await fetch('/api/backup/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert(`Backup restored successfully. Reloading...`);
      window.location.reload();
    } else {
      alert(`Restore failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error restoring backup: ${err.message}`);
  }
}

async function deleteBackup(filename) {
  if (!confirm(`Are you sure you want to delete backup "${filename}"? This cannot be undone.`)) {
    return;
  }
  
  try {
    const resp = await fetch('/api/backup/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert('Backup deleted successfully');
      await loadBackups();
    } else {
      alert(`Delete failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error deleting backup: ${err.message}`);
  }
}

if (createBackupBtn) {
  createBackupBtn.addEventListener('click', createBackup);
}

// Load backups when settings tab is opened
document.querySelectorAll('.settings-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    if (tab.getAttribute('data-tab') === 'backup') {
      loadBackups();
    }
  });
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

// ================== GALLERY RENDERING ==================

const galleryTargetSelect = document.getElementById('gallery-target-select');
const galleryGrid = document.getElementById('gallery-grid');

function renderGallery(targets) {
  // Update target dropdown
  if (galleryTargetSelect) {
    const options = '<option value="">-- Select a target --</option>' +
      Object.keys(targets).sort().map(domain => 
        `<option value="${escapeHtml(domain)}">${escapeHtml(domain)}</option>`
      ).join('');
    galleryTargetSelect.innerHTML = options;
  }
}

if (galleryTargetSelect) {
  galleryTargetSelect.addEventListener('change', async (e) => {
    const domain = e.target.value;
    if (!domain || !galleryGrid) {
      if (galleryGrid) galleryGrid.innerHTML = '';
      return;
    }
    
    galleryGrid.innerHTML = '<div class="section-placeholder">Loading screenshots...</div>';
    
    try {
      const resp = await fetch(`/api/gallery/${encodeURIComponent(domain)}`);
      if (!resp.ok) throw new Error('Failed to load gallery');
      const data = await resp.json();
      
      if (!data.success) {
        galleryGrid.innerHTML = `<div class="section-placeholder">${escapeHtml(data.message || 'Failed to load gallery')}</div>`;
        return;
      }
      
      const screenshots = data.screenshots || [];
      if (screenshots.length === 0) {
        galleryGrid.innerHTML = '<div class="section-placeholder">No screenshots available for this target.</div>';
        return;
      }
      
      const html = screenshots.map(shot => {
        const statusClass = shot.status_code >= 200 && shot.status_code < 300 ? 'status-2xx' :
                            shot.status_code >= 300 && shot.status_code < 400 ? 'status-3xx' :
                            shot.status_code >= 400 && shot.status_code < 500 ? 'status-4xx' : 'status-5xx';
        const statusBadge = shot.status_code ? `<span class="status-badge ${statusClass}">${shot.status_code}</span>` : '';
        
        return `
          <div class="gallery-card">
            <img class="gallery-image" src="/screenshots/${escapeHtml(shot.path)}" 
                 alt="${escapeHtml(shot.subdomain)}" 
                 onclick="window.open('/screenshots/${escapeHtml(shot.path)}', '_blank')" />
            <div class="gallery-info">
              <div class="gallery-subdomain">${escapeHtml(shot.subdomain)}</div>
              <a href="${escapeHtml(shot.url)}" target="_blank" class="gallery-url">${escapeHtml(shot.url)}</a>
              <div class="gallery-meta">
                ${statusBadge}
                ${shot.title ? `<span class="badge">${escapeHtml(shot.title)}</span>` : ''}
              </div>
            </div>
          </div>
        `;
      }).join('');
      
      galleryGrid.innerHTML = html;
    } catch (err) {
      galleryGrid.innerHTML = `<div class="section-placeholder">Error: ${escapeHtml(err.message)}</div>`;
    }
  });
}

// ================== FILTER PERSISTENCE ==================

// Save and restore report filters
function saveReportFilters(domain, filters) {
  try {
    const key = `reportFilters_${domain}`;
    localStorage.setItem(key, JSON.stringify(filters));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadReportFilters(domain) {
  try {
    const key = `reportFilters_${domain}`;
    const saved = localStorage.getItem(key);
    return saved ? JSON.parse(saved) : null;
  } catch (e) {
    return null;
  }
}

// Save checkbox states
function saveCheckboxState(id, checked) {
  try {
    localStorage.setItem(`checkbox_${id}`, checked ? '1' : '0');
  } catch (e) {
    // Ignore
  }
}

function loadCheckboxState(id, defaultValue = false) {
  try {
    const saved = localStorage.getItem(`checkbox_${id}`);
    if (saved === null) return defaultValue;
    return saved === '1' ? true : false;
  } catch (e) {
    return defaultValue;
  }
}

// Apply to all checkboxes on page
document.querySelectorAll('input[type="checkbox"][id]').forEach(checkbox => {
  const savedState = loadCheckboxState(checkbox.id);
  if (savedState !== null) {
    checkbox.checked = savedState;
  }
  checkbox.addEventListener('change', () => {
    saveCheckboxState(checkbox.id, checkbox.checked);
  });
});

// Enhance attachSubdomainFilters to persist state
const originalAttachSubdomainFilters = attachSubdomainFilters;
attachSubdomainFilters = function(detailEl) {
  originalAttachSubdomainFilters(detailEl);
  
  // Load saved filter state if available
  const domain = detailEl.querySelector('[data-domain]')?.getAttribute('data-domain');
  if (domain) {
    const saved = loadReportFilters(domain);
    if (saved) {
      const statusGroup = detailEl.querySelector('[data-status-filter]');
      const searchInput = detailEl.querySelector('[data-sub-search]');
      
      if (saved.statusFilters && statusGroup) {
        statusGroup.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          if (saved.statusFilters.includes(cb.value)) {
            cb.checked = true;
          } else {
            cb.checked = false;
          }
        });
      }
      
      if (saved.searchQuery && searchInput) {
        searchInput.value = saved.searchQuery;
      }
    }
  }
  
  // Save on change
  const statusGroup = detailEl.querySelector('[data-status-filter]');
  const searchInput = detailEl.querySelector('[data-sub-search]');
  
  const saveFilters = () => {
    if (domain) {
      const statusFilters = statusGroup 
        ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value)
        : [];
      const searchQuery = searchInput ? searchInput.value : '';
      saveReportFilters(domain, { statusFilters, searchQuery });
    }
  };
  
  if (statusGroup) {
    statusGroup.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', saveFilters);
    });
  }
  if (searchInput) {
    searchInput.addEventListener('input', saveFilters);
  }
};

console.log('[DEBUG] Script execution complete, starting event handlers and fetch');
renderWorkflowDiagram();
fetchState();

// Only auto-refresh on overview/monitoring pages, not on detail pages
// This prevents unnecessary refreshes on static pages like settings, gallery, etc.
const VIEWS_WITH_AUTO_REFRESH = ['overview', 'jobs', 'queue', 'workers', 'resources', 'monitors', 'logs'];
let pollIntervalId = null;

function startPolling() {
  if (pollIntervalId) return; // Already polling
  pollIntervalId = setInterval(() => {
    const currentView = getCurrentView();
    if (VIEWS_WITH_AUTO_REFRESH.includes(currentView)) {
      fetchState();
    }
  }, POLL_INTERVAL);
}

function getCurrentView() {
  const hash = location.hash ? location.hash.substring(1) : 'overview';
  return hash || 'overview';
}

// Start polling
startPolling();

// Also fetch when view changes to ensure fresh data
window.addEventListener('hashchange', () => {
  const currentView = getCurrentView();
  if (VIEWS_WITH_AUTO_REFRESH.includes(currentView)) {
    fetchState();
  }
});
</script>
</body>
</html>

"""


def snapshot_running_jobs() -> List[Dict[str, Any]]:
    with JOB_LOCK:
        results = []
        
        # Add running jobs
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
                "completed_at": None,
            })
        
        # Add completed jobs
        for job_key, job in COMPLETED_JOBS.items():
            steps = {name: dict(data) for name, data in (job.get("steps") or {}).items()}
            logs = [dict(entry) for entry in job.get("logs", [])]
            results.append({
                "domain": job.get("domain"),
                "started": job.get("started"),
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
                "status": job.get("status", "completed"),
                "message": job.get("message", ""),
                "progress": job.get("progress", 100),
                "last_update": job.get("last_update"),
                "thread_alive": False,
                "steps": steps,
                "logs": logs,
                "completed_at": job.get("completed_at"),
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
    
    # Include timeout tracking statistics
    timeout_stats = {}
    with TIMEOUT_TRACKER_LOCK:
        for domain, tracker in TIMEOUT_TRACKER.items():
            timeout_stats[domain] = {
                "errors": tracker["errors"],
                "last_error_time": tracker["last_error_time"],
                "backoff_delay": tracker["backoff_delay"],
            }
    
    return {
        "job_slots": {
            "limit": MAX_RUNNING_JOBS,
            "active": active_jobs,
            "queue": queue_len,
            "dynamic_mode": DYNAMIC_MODE_ENABLED,
        },
        "tools": tool_stats,
        "rate_limiting": {
            "current_delay": GLOBAL_RATE_LIMIT_DELAY,
            "max_auto_backoff": MAX_AUTO_BACKOFF_DELAY,
            "timeout_tracker": timeout_stats,
        },
        "dynamic_mode": get_dynamic_mode_status(),
        "auto_backup": get_auto_backup_status(),
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
            existing_status = RUNNING_JOBS[normalized].get('status', 'unknown')
            return True, f"A job for {normalized} is already {existing_status}. Continuing with existing scan."
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


def build_state_payload_summary() -> Dict[str, Any]:
    """
    Build a lightweight state payload with minimal subdomain data.
    This is much faster than build_state_payload() for large datasets.
    
    For each target, includes lightweight subdomain entries with only:
    - subdomain name
    - sources
    - httpx summary (status_code, title, webserver only)
    - nuclei/nikto finding counts (not full details)
    - screenshot path (not full metadata)
    
    This allows the dashboard to render basic views without loading full data.
    
    Optimizations:
    - Uses single JOIN query instead of N+1 queries (70-90% faster)
    - Batches subdomain processing per domain
    """
    db = get_db()
    cursor = db.cursor()
    
    # OPTIMIZATION: Single query with JOIN instead of N+1 queries
    # This is dramatically faster for large datasets (10,000+ subdomains)
    cursor.execute("""
        SELECT 
            t.domain, t.flags, t.options, t.comments,
            s.subdomain, s.data, s.interesting, s.comments as sub_comments
        FROM targets t
        LEFT JOIN subdomains s ON t.domain = s.domain
        ORDER BY t.domain, s.subdomain
    """)
    
    config = get_config()
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    
    # Process results in a single pass
    for row in cursor:
        domain = row[0]
        
        # Check if we've moved to a new domain
        if domain != current_domain:
            # Save previous domain's data if exists
            if current_domain is not None and current_target is not None:
                current_target["subdomains"] = subdomains
                # Calculate pending status
                try:
                    current_target["pending"] = target_has_pending_work(current_target, config)
                except Exception:
                    current_target["pending"] = True
                targets[current_domain] = current_target
            
            # Start new domain
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            
            current_target = {
                "flags": flags,
                "options": options,
                "comments": target_comments,
            }
            subdomains = {}
        
        # Process subdomain if present (LEFT JOIN may have NULL subdomain)
        subdomain = row[4]
        if subdomain is not None:
            try:
                full_data = json.loads(row[5])
                
                # Extract only lightweight fields
                lightweight_data = {
                    "sources": full_data.get("sources", []),
                }
                
                # Add minimal httpx data
                if "httpx" in full_data and full_data["httpx"] is not None:
                    httpx = full_data["httpx"]
                    lightweight_data["httpx"] = {
                        "status_code": httpx.get("status_code"),
                        "title": httpx.get("title", ""),
                        "webserver": httpx.get("webserver", httpx.get("server", "")),
                    }
                
                # Add nuclei/nikto counts only (not full findings)
                nuclei = full_data.get("nuclei", [])
                if nuclei:
                    lightweight_data["nuclei"] = nuclei  # Keep for severity calculation
                
                nikto = full_data.get("nikto", [])
                if nikto:
                    lightweight_data["nikto"] = nikto  # Keep for counts
                
                # Add screenshot path only
                if "screenshot" in full_data and full_data["screenshot"] is not None:
                    screenshot = full_data["screenshot"]
                    lightweight_data["screenshot"] = {
                        "path": screenshot.get("path")
                    }
                
                # Add interesting flag
                if row[6] is not None:
                    lightweight_data["interesting"] = bool(row[6])
                
                subdomains[subdomain] = lightweight_data
                
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain's data
    if current_domain is not None and current_target is not None:
        current_target["subdomains"] = subdomains
        # Calculate pending status
        try:
            current_target["pending"] = target_has_pending_work(current_target, config)
        except Exception:
            current_target["pending"] = True
        targets[current_domain] = current_target
    
    # Load completed jobs and merge with active targets
    completed_jobs = load_completed_jobs()
    for job_key, job_data in completed_jobs.items():
        domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
        
        if domain in targets:
            # Add completion timestamp to active target
            if not targets[domain].get("completed_at"):
                targets[domain]["completed_at"] = job_data.get("completed_at")
        else:
            # Domain not in active targets - create minimal entry from completed job
            # For completed jobs not in active state, include minimal lightweight data
            state_data = job_data.get("state", {})
            subdomains = state_data.get("subdomains", {})
            
            # Create lightweight subdomain entries for completed jobs too
            # Limit to first 100 for performance (configurable via MAX_COMPLETED_JOB_SUBDOMAINS)
            MAX_COMPLETED_JOB_SUBDOMAINS = 100
            lightweight_subs = {}
            for sub, sub_data in list(subdomains.items())[:MAX_COMPLETED_JOB_SUBDOMAINS]:
                lightweight_subs[sub] = {
                    "sources": sub_data.get("sources", []),
                    "httpx": {
                        "status_code": sub_data.get("httpx", {}).get("status_code"),
                        "title": sub_data.get("httpx", {}).get("title", ""),
                        "webserver": sub_data.get("httpx", {}).get("webserver", ""),
                    } if sub_data.get("httpx") else {},
                    "nuclei": sub_data.get("nuclei", []),
                    "nikto": sub_data.get("nikto", []),
                    "screenshot": {
                        "path": sub_data.get("screenshot", {}).get("path")
                    } if sub_data.get("screenshot") else {},
                }
            
            targets[domain] = {
                "subdomains": lightweight_subs,
                "flags": state_data.get("flags", {}),
                "options": job_data.get("options", {}),
                "comments": [],
                "completed_at": job_data.get("completed_at"),
                "pending": False,
                "from_completed_jobs": True,
            }
    
    # Get last updated time
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    return {
        "last_updated": last_updated,
        "targets": targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
    }


def build_state_payload() -> Dict[str, Any]:
    """
    Build complete state payload with all subdomain details.
    This is slower but includes full information.
    Use this for exports and detail pages only.
    """
    state = load_state()
    config = get_config()
    targets = state.get("targets", {})
    for info in targets.values():
        try:
            info["pending"] = target_has_pending_work(info, config)
        except Exception:
            info["pending"] = True
    
    # Load completed jobs and convert them to targets format for display
    completed_jobs = load_completed_jobs()
    completed_targets = {}
    for job_key, job_data in completed_jobs.items():
        # Extract domain from job key
        # Job keys are stored as "domain_timestamp" format (see add_completed_job function)
        # Example: "example.com_1702901234.567890"
        domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
        
        # Check if this domain exists in active targets
        if domain in targets:
            # Domain is still active in state.json, add completion metadata
            # Preserve all active data but mark as completed and add timestamp
            if not targets[domain].get("completed_at"):
                targets[domain]["completed_at"] = job_data.get("completed_at")
            # Keep pending status from active calculation above
        else:
            # Domain not in active targets, create from completed job data
            completed_targets[domain] = {
                "subdomains": job_data.get("state", {}).get("subdomains", {}),
                "flags": job_data.get("state", {}).get("flags", {}),
                "options": job_data.get("options", {}),
                "pending": False,
                "completed_at": job_data.get("completed_at"),
                "from_completed_jobs": True,
            }
    
    # Merge: completed targets first, then active targets (active takes precedence)
    # This ensures active scans override completed data for same domain
    all_targets = {**completed_targets, **targets}
    
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    return {
        "last_updated": state.get("last_updated"),
        "targets": all_targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
    }




def invalidate_state_cache() -> None:
    """Invalidate the state payload cache. Call this when state changes."""
    global STATE_CACHE
    with STATE_CACHE_LOCK:
        STATE_CACHE["etag"] = None
        STATE_CACHE["payload"] = None
        STATE_CACHE["last_updated"] = None


def build_state_payload_paginated(page: int = 1, per_page: int = 50, full: bool = False) -> Dict[str, Any]:
    """
    Build state payload with pagination support for large datasets.
    
    Args:
        page: Page number (1-indexed)
        per_page: Number of targets per page
        full: If True, return full data; if False, return summary
    
    Returns:
        Dict with paginated targets and metadata
    
    Optimizations:
    - Only loads requested page of targets from database
    - Includes pagination metadata (total_targets, total_pages, current_page)
    - Reduces memory usage and response time for large datasets
    """
    db = get_db()
    cursor = db.cursor()
    config = get_config()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    
    # Get total count for pagination metadata
    cursor.execute("SELECT COUNT(*) FROM targets")
    total_targets = cursor.fetchone()[0]
    total_pages = (total_targets + per_page - 1) // per_page  # Ceiling division
    
    # Load paginated targets with subdomains using optimized JOIN
    if full:
        # Full data: load everything for the page
        cursor.execute("""
            SELECT 
                t.domain, t.flags, t.options, t.comments,
                s.subdomain, s.data, s.interesting, s.comments as sub_comments
            FROM (
                SELECT domain, flags, options, comments
                FROM targets
                ORDER BY domain
                LIMIT ? OFFSET ?
            ) t
            LEFT JOIN subdomains s ON t.domain = s.domain
            ORDER BY t.domain, s.subdomain
        """, (per_page, offset))
    else:
        # Summary data: lightweight fields only
        cursor.execute("""
            SELECT 
                t.domain, t.flags, t.options, t.comments,
                s.subdomain, s.data, s.interesting, s.comments as sub_comments
            FROM (
                SELECT domain, flags, options, comments
                FROM targets
                ORDER BY domain
                LIMIT ? OFFSET ?
            ) t
            LEFT JOIN subdomains s ON t.domain = s.domain
            ORDER BY t.domain, s.subdomain
        """, (per_page, offset))
    
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    
    # Process results (same logic as non-paginated version)
    for row in cursor:
        domain = row[0]
        
        if domain != current_domain:
            if current_domain is not None and current_target is not None:
                current_target["subdomains"] = subdomains
                if not full:
                    try:
                        current_target["pending"] = target_has_pending_work(current_target, config)
                    except Exception:
                        current_target["pending"] = True
                targets[current_domain] = current_target
            
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            
            current_target = {
                "flags": flags,
                "options": options,
                "comments": target_comments,
            }
            subdomains = {}
        
        subdomain = row[4]
        if subdomain is not None:
            try:
                full_data = json.loads(row[5])
                
                if full:
                    # Full data: include everything
                    if row[6] is not None:
                        full_data["interesting"] = bool(row[6])
                    if row[7]:
                        full_data["comments"] = json.loads(row[7])
                    subdomains[subdomain] = full_data
                else:
                    # Summary: lightweight fields only
                    lightweight_data = {
                        "sources": full_data.get("sources", []),
                    }
                    
                    if "httpx" in full_data and full_data["httpx"] is not None:
                        httpx = full_data["httpx"]
                        lightweight_data["httpx"] = {
                            "status_code": httpx.get("status_code"),
                            "title": httpx.get("title", ""),
                            "webserver": httpx.get("webserver", httpx.get("server", "")),
                        }
                    
                    nuclei = full_data.get("nuclei", [])
                    if nuclei:
                        lightweight_data["nuclei"] = nuclei
                    
                    nikto = full_data.get("nikto", [])
                    if nikto:
                        lightweight_data["nikto"] = nikto
                    
                    if "screenshot" in full_data and full_data["screenshot"] is not None:
                        screenshot = full_data["screenshot"]
                        lightweight_data["screenshot"] = {
                            "path": screenshot.get("path")
                        }
                    
                    if row[6] is not None:
                        lightweight_data["interesting"] = bool(row[6])
                    
                    subdomains[subdomain] = lightweight_data
                
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain
    if current_domain is not None and current_target is not None:
        current_target["subdomains"] = subdomains
        if not full:
            try:
                current_target["pending"] = target_has_pending_work(current_target, config)
            except Exception:
                current_target["pending"] = True
        targets[current_domain] = current_target
    
    # Get last updated time
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    tool_info = {name: shutil.which(cmd) or "" for name, cmd in TOOLS.items()}
    
    payload = {
        "last_updated": last_updated,
        "targets": targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
        # Pagination metadata
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_targets": total_targets,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
    }
    
    # For full payload, merge completed jobs (like non-paginated version)
    if full:
        completed_jobs = load_completed_jobs()
        for job_key, job_data in completed_jobs.items():
            domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
            if domain in targets:
                if not targets[domain].get("completed_at"):
                    targets[domain]["completed_at"] = job_data.get("completed_at")
    
    return payload


def get_cached_state_payload(full: bool = False) -> Tuple[str, Dict[str, Any]]:
    """
    Get state payload with caching support.
    Returns (etag, payload) tuple.
    
    Args:
        full: If True, returns full payload. If False, returns summary.
    
    Returns:
        Tuple of (etag_string, payload_dict)
    """
    global STATE_CACHE
    
    # Get current last_updated time from database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    current_last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    # Check if we have a valid cache
    cache_key = f"{'full' if full else 'summary'}:{current_last_updated}"
    etag = hashlib.md5(cache_key.encode()).hexdigest()
    
    with STATE_CACHE_LOCK:
        if STATE_CACHE.get("etag") == etag and STATE_CACHE.get("payload") is not None:
            # Cache hit - return cached payload
            return etag, STATE_CACHE["payload"]
        
        # Cache miss - build new payload
        if full:
            payload = build_state_payload()
        else:
            payload = build_state_payload_summary()
        
        # Update cache
        STATE_CACHE["etag"] = etag
        STATE_CACHE["payload"] = payload
        STATE_CACHE["last_updated"] = current_last_updated
        
        return etag, payload


def generate_domain_detail_page(domain: str) -> str:
    """Generate a standalone page for domain details."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domain Detail: {domain}</title>
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
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}
.stat-card {{
  background: #1e293b;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid #334155;
}}
.stat-card .label {{
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #94a3b8;
  margin-bottom: 8px;
}}
.stat-card .value {{
  font-size: 28px;
  font-weight: 700;
  color: #f1f5f9;
}}
.section {{
  background: #1e293b;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
  border: 1px solid #334155;
}}
.section h2 {{
  margin: 0 0 16px 0;
  font-size: 1.5rem;
  color: #fbbf24;
}}
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
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
.badge {{
  display: inline-block;
  padding: 4px 12px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.85rem;
  margin: 2px 4px;
}}
.badge.complete {{
  background: #065f46;
  color: #a7f3d0;
}}
.badge.pending {{
  background: #78350f;
  color: #fde68a;
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
.muted {{
  color: #64748b;
  font-style: italic;
}}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
.link {{
  color: #60a5fa;
  text-decoration: none;
}}
.link:hover {{
  text-decoration: underline;
}}
.actions {{
  display: flex;
  gap: 12px;
  margin: 16px 0;
}}
.btn {{
  padding: 10px 20px;
  background: #2563eb;
  color: white;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
}}
.btn:hover {{
  background: #1d4ed8;
}}
.btn.secondary {{
  background: #475569;
}}
.btn.secondary:hover {{
  background: #334155;
}}
.table-pagination {{
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 16px;
  justify-content: flex-end;
}}
.table-pagination button {{
  padding: 6px 12px;
  background: #1e293b;
  border: 1px solid #334155;
  color: #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
}}
.table-pagination button:disabled {{
  opacity: 0.4;
  cursor: not-allowed;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="domain-title">Loading...</h1>
    <div class="subtitle">Domain Overview</div>
  </div>
  <div id="content">
    <div class="loading">Loading domain details...</div>
  </div>
</div>
<script>
const domain = {repr(domain)};
const DEFAULT_PAGE_SIZE = 50;

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

function initPagination(table, pagerEl, pageSize) {{
  if (!table || !pagerEl) return;
  const state = {{
    table,
    pagerEl,
    pageSize: pageSize || DEFAULT_PAGE_SIZE,
    currentPage: 1,
    totalPages: 1,
  }};
  
  pagerEl.addEventListener('click', (event) => {{
    const btn = event.target.closest('[data-page-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-page-action');
    if (action === 'prev') {{
      state.currentPage = Math.max(1, state.currentPage - 1);
    }} else if (action === 'next') {{
      state.currentPage = Math.min(state.totalPages, state.currentPage + 1);
    }} else if (action === 'first') {{
      state.currentPage = 1;
    }} else if (action === 'last') {{
      state.currentPage = state.totalPages;
    }}
    refreshPagination(table, state, pagerEl);
  }});
  
  table._paginationState = state;
  refreshPagination(table, state, pagerEl);
}}

function refreshPagination(table, state, pagerEl) {{
  const rows = Array.from(table.tBodies[0] ? table.tBodies[0].rows : []);
  let visibleCount = rows.length;
  
  state.totalPages = Math.max(1, Math.ceil(visibleCount / state.pageSize));
  if (state.currentPage > state.totalPages) {{
    state.currentPage = state.totalPages;
  }}
  
  const start = (state.currentPage - 1) * state.pageSize;
  const end = start + state.pageSize;
  
  rows.forEach((row, idx) => {{
    row.style.display = (idx >= start && idx < end) ? '' : 'none';
  }});
  
  if (state.totalPages <= 1) {{
    pagerEl.innerHTML = '';
    return;
  }}
  
  pagerEl.innerHTML = `
    <span style="color: #94a3b8; margin-right: auto;">${{visibleCount}} rows</span>
    <button data-page-action="first" ${{state.currentPage === 1 ? 'disabled' : ''}}>&laquo;</button>
    <button data-page-action="prev" ${{state.currentPage === 1 ? 'disabled' : ''}}>&lsaquo;</button>
    <span>Page ${{state.currentPage}} / ${{state.totalPages}}</span>
    <button data-page-action="next" ${{state.currentPage === state.totalPages ? 'disabled' : ''}}>&rsaquo;</button>
    <button data-page-action="last" ${{state.currentPage === state.totalPages ? 'disabled' : ''}}>&raquo;</button>
  `;
}}

async function loadDomainDetail() {{
  try {{
    const resp = await fetch(`/api/domain/${{encodeURIComponent(domain)}}`);
    if (!resp.ok) throw new Error('Failed to load domain data');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    document.getElementById('domain-title').textContent = domain;
    renderDomainDetail(data.data);
  }} catch (err) {{
    document.getElementById('content').innerHTML = `<div class="section"><p class="muted">Error: ${{escapeHtml(err.message)}}</p></div>`;
  }}
}}

function renderDomainDetail(info) {{
  const subdomains = info.subdomains || {{}};
  const flags = info.flags || {{}};
  const subKeys = Object.keys(subdomains);
  
  // Calculate stats
  let httpCount = 0;
  let nucleiCount = 0;
  let niktoCount = 0;
  let screenshotCount = 0;
  let maxSeverity = 'NONE';
  
  const severityOrder = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  
  subKeys.forEach(sub => {{
    const entry = subdomains[sub];
    if (entry.httpx) httpCount++;
    if (entry.screenshot) screenshotCount++;
    const nuclei = entry.nuclei || [];
    nucleiCount += nuclei.length;
    nuclei.forEach(finding => {{
      const sev = (finding.severity || 'INFO').toUpperCase();
      if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {{
        maxSeverity = sev;
      }}
    }});
    const nikto = entry.nikto || [];
    niktoCount += nikto.length;
    nikto.forEach(finding => {{
      const sev = (finding.severity || finding.risk || 'INFO').toUpperCase();
      if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {{
        maxSeverity = sev;
      }}
    }});
  }});
  
  const completedSteps = Object.values(flags).filter(Boolean).length;
  const totalSteps = Object.keys(flags).length;
  const progress = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;
  
  let html = `
    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Subdomains</div>
        <div class="value">${{subKeys.length}}</div>
      </div>
      <div class="stat-card">
        <div class="label">HTTP Responses</div>
        <div class="value">${{httpCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Screenshots</div>
        <div class="value">${{screenshotCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Nuclei Findings</div>
        <div class="value">${{nucleiCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Nikto Findings</div>
        <div class="value">${{niktoCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Max Severity</div>
        <div class="value"><span class="severity-pill ${{maxSeverity}}">${{maxSeverity}}</span></div>
      </div>
      <div class="stat-card">
        <div class="label">Progress</div>
        <div class="value">${{progress}}%</div>
      </div>
    </div>
    
    <div class="actions">
      <a href="/gallery/${{encodeURIComponent(domain)}}" class="btn">View Screenshots Gallery</a>
      <a href="/#reports" class="btn secondary" onclick="window.parent.postMessage({{type:'selectReport',domain:domain}}, '*')">View Full Report</a>
    </div>
    
    <div class="section">
      <h2>Scan Progress</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  const flagLabels = {{
    amass_done: 'Amass',
    subfinder_done: 'Subfinder',
    assetfinder_done: 'Assetfinder',
    findomain_done: 'Findomain',
    sublist3r_done: 'Sublist3r',
    crtsh_done: 'crt.sh',
    github_subdomains_done: 'GitHub Subdomains',
    dnsx_done: 'DNSx',
    ffuf_done: 'ffuf',
    httpx_done: 'httpx',
    waybackurls_done: 'Wayback URLs',
    gau_done: 'GAU',
    screenshots_done: 'Screenshots',
    nuclei_done: 'Nuclei',
    nikto_done: 'Nikto'
  }};
  
  Object.entries(flagLabels).forEach(([flag, label]) => {{
    const status = flags[flag] ? 'complete' : 'pending';
    html += `
      <tr>
        <td>${{label}}</td>
        <td><span class="badge ${{status}}">${{status === 'complete' ? '✅ Complete' : '⏳ Pending'}}</span></td>
      </tr>
    `;
  }});
  
  html += `
        </tbody>
      </table>
    </div>
    
    <div class="section">
      <h2>Subdomains (${{subKeys.length}})</h2>
      <table id="subdomains-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Subdomain</th>
            <th>Status</th>
            <th>HTTP Status</th>
            <th>Title</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  subKeys.forEach((sub, idx) => {{
    const entry = subdomains[sub];
    const httpx = entry.httpx || {{}};
    const nuclei = entry.nuclei || [];
    const nikto = entry.nikto || [];
    const findings = nuclei.length + nikto.length;
    const interesting = entry.interesting;
    
    let interestingBadge = '';
    if (interesting === true) {{
      interestingBadge = '<span class="badge" style="background: #10b981; color: white;">⭐ Interesting</span>';
    }} else if (interesting === false) {{
      interestingBadge = '<span class="badge" style="background: #ef4444; color: white;">🚫 Not Interesting</span>';
    }}
    
    html += `
      <tr>
        <td>${{idx + 1}}</td>
        <td><a href="/subdomain/${{encodeURIComponent(domain)}}/${{encodeURIComponent(sub)}}" class="link">${{escapeHtml(sub)}}</a></td>
        <td>${{interestingBadge}}</td>
        <td>${{httpx.status_code || '—'}}</td>
        <td>${{escapeHtml(httpx.title || '—')}}</td>
        <td>${{findings > 0 ? findings + ' findings' : '—'}}</td>
      </tr>
    `;
  }});
  
  html += `
        </tbody>
      </table>
      <div class="table-pagination" id="subdomains-pagination"></div>
    </div>
  `;
  
  document.getElementById('content').innerHTML = html;
  
  // Initialize pagination
  const table = document.getElementById('subdomains-table');
  const pagerEl = document.getElementById('subdomains-pagination');
  if (table && pagerEl) {{
    initPagination(table, pagerEl, DEFAULT_PAGE_SIZE);
  }}
}}

loadDomainDetail();
</script>
</body>
</html>
"""


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
  const interesting = info.interesting;
  const comments = info.comments || [];
  
  let html = '';
  
  // Marking and action buttons
  html += `
    <div class="section">
      <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 16px;">
        <button class="btn" onclick="markSubdomain(true)" style="background: #10b981;">Mark as Interesting</button>
        <button class="btn" onclick="markSubdomain(false)" style="background: #ef4444;">Mark as Not Interesting</button>
        <button class="btn secondary" onclick="markSubdomain(null)">Clear Mark</button>
        ${{interesting === true ? '<span class="badge" style="background: #10b981; color: white; margin-left: 8px;">⭐ Interesting</span>' : ''}}
        ${{interesting === false ? '<span class="badge" style="background: #ef4444; color: white; margin-left: 8px;">🚫 Not Interesting</span>' : ''}}
      </div>
    </div>
  `;
  
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
          <div class="field"><strong>URL</strong><div class="field-value">${{(httpx.url && (httpx.url.startsWith('http://') || httpx.url.startsWith('https://'))) ? `<a href="${{escapeHtml(httpx.url)}}" target="_blank" rel="noopener noreferrer" style="color: #60a5fa; text-decoration: none;">${{escapeHtml(httpx.url)}}</a>` : escapeHtml(httpx.url || '—')}}</div></div>
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
  
  // Comments section
  html += `
    <div class="section">
      <h2>Comments (${{comments.length}})</h2>
      <div style="margin-bottom: 16px;">
        <textarea id="comment-input" placeholder="Add a comment..." style="width: 100%; min-height: 80px; padding: 8px; background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 4px; font-family: inherit;"></textarea>
        <button class="btn" onclick="addComment()" style="margin-top: 8px;">Add Comment</button>
      </div>
      <div id="comments-list">
        ${{comments.length ? comments.map(c => `
          <div style="background: #0f172a; padding: 12px; margin-bottom: 8px; border-radius: 4px; border: 1px solid #334155;">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
              <span class="muted" style="font-size: 0.875rem;">${{fmtTime(c.timestamp)}}</span>
              <button class="btn secondary small" onclick="deleteComment('${{escapeHtml(c.id)}}')" style="padding: 4px 8px; font-size: 0.75rem;">Delete</button>
            </div>
            <div>${{escapeHtml(c.text)}}</div>
          </div>
        `).join('') : '<p class="muted">No comments yet</p>'}}
      </div>
    </div>
  `;
  
  document.getElementById('content').innerHTML = html;
}}

async function markSubdomain(interesting) {{
  try {{
    const resp = await fetch('/api/subdomain/mark', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, interesting }})
    }});
    const result = await resp.json();
    if (result.success) {{
      loadSubdomainDetail(); // Reload to show updated state
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error marking subdomain: ' + err.message);
  }}
}}

async function addComment() {{
  const input = document.getElementById('comment-input');
  const comment = input.value.trim();
  if (!comment) return;
  
  try {{
    const resp = await fetch('/api/subdomain/comment', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, comment, action: 'add' }})
    }});
    const result = await resp.json();
    if (result.success) {{
      input.value = '';
      loadSubdomainDetail(); // Reload to show new comment
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error adding comment: ' + err.message);
  }}
}}

async function deleteComment(commentId) {{
  if (!confirm('Delete this comment?')) return;
  
  try {{
    const resp = await fetch('/api/subdomain/comment', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, comment_id: commentId, action: 'delete' }})
    }});
    const result = await resp.json();
    if (result.success) {{
      loadSubdomainDetail(); // Reload to show updated list
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error deleting comment: ' + err.message);
  }}
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
.pagination {{
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin: 30px 0;
  padding: 20px 0;
}}
.pagination button {{
  background: #1e293b;
  color: #e2e8f0;
  border: 1px solid #334155;
  border-radius: 6px;
  padding: 8px 16px;
  cursor: pointer;
  font-size: 0.95rem;
  transition: all 0.2s;
}}
.pagination button:hover:not(:disabled) {{
  background: #334155;
  border-color: #60a5fa;
}}
.pagination button:disabled {{
  opacity: 0.4;
  cursor: not-allowed;
}}
.pagination .page-info {{
  color: #94a3b8;
  font-size: 0.95rem;
  margin: 0 8px;
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
  <div class="pagination" id="pagination-top"></div>
  <div id="gallery" class="gallery">
    <div class="loading">Loading screenshots...</div>
  </div>
  <div class="pagination" id="pagination-bottom"></div>
</div>
<div id="modal" class="modal">
  <div class="modal-close" onclick="closeModal()">×</div>
  <img id="modal-image" src="" alt="Screenshot" />
</div>
<script>
const domain = {repr(domain)};
let allScreenshots = [];
let currentPage = 1;
let screenshotsPerPage = 20;

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
    
    allScreenshots = data.screenshots;
    document.getElementById('gallery-title').textContent = `Screenshots Gallery: ${{domain}}`;
    document.getElementById('gallery-subtitle').textContent = `${{allScreenshots.length}} screenshots`;
    
    // Load screenshots per page from config if available
    try {{
      const configResp = await fetch('/api/settings');
      if (configResp.ok) {{
        const configData = await configResp.json();
        screenshotsPerPage = configData.config?.screenshots_per_page || 20;
      }}
    }} catch (e) {{
      // Use default if config fails to load
    }}
    
    renderPage();
  }} catch (err) {{
    document.getElementById('gallery').innerHTML = `<div class="empty">Error: ${{escapeHtml(err.message)}}</div>`;
  }}
}}

function renderPage() {{
  if (allScreenshots.length === 0) {{
    document.getElementById('gallery').innerHTML = '<div class="empty">No screenshots available for this domain.</div>';
    document.getElementById('pagination-top').innerHTML = '';
    document.getElementById('pagination-bottom').innerHTML = '';
    return;
  }}
  
  const totalPages = Math.ceil(allScreenshots.length / screenshotsPerPage);
  const startIdx = (currentPage - 1) * screenshotsPerPage;
  const endIdx = Math.min(startIdx + screenshotsPerPage, allScreenshots.length);
  const pageScreenshots = allScreenshots.slice(startIdx, endIdx);
  
  renderGallery(pageScreenshots);
  renderPagination(totalPages, 'pagination-top');
  renderPagination(totalPages, 'pagination-bottom');
}}

function renderPagination(totalPages, elementId) {{
  const paginationEl = document.getElementById(elementId);
  
  if (totalPages <= 1) {{
    paginationEl.innerHTML = '';
    return;
  }}
  
  const startIdx = (currentPage - 1) * screenshotsPerPage;
  const endIdx = Math.min(startIdx + screenshotsPerPage, allScreenshots.length);
  
  paginationEl.innerHTML = `
    <button onclick="goToPage(1)" ${{currentPage === 1 ? 'disabled' : ''}}>«</button>
    <button onclick="goToPage(${{currentPage - 1}})" ${{currentPage === 1 ? 'disabled' : ''}}>‹</button>
    <span class="page-info">Page ${{currentPage}} of ${{totalPages}} (showing ${{startIdx + 1}}-${{endIdx}} of ${{allScreenshots.length}})</span>
    <button onclick="goToPage(${{currentPage + 1}})" ${{currentPage === totalPages ? 'disabled' : ''}}>›</button>
    <button onclick="goToPage(${{totalPages}})" ${{currentPage === totalPages ? 'disabled' : ''}}>»</button>
  `;
}}

function goToPage(page) {{
  const totalPages = Math.ceil(allScreenshots.length / screenshotsPerPage);
  if (page < 1 || page > totalPages) return;
  currentPage = page;
  renderPage();
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
}}

function renderGallery(screenshots) {{
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
        
        # Domain detail page route
        if self.path.startswith("/domain/"):
            domain = unquote(self.path[len("/domain/"):]).strip().lower()
            if domain:
                self._send_bytes(generate_domain_detail_page(domain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
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
        
        # API endpoint for domain detail data
        if self.path.startswith("/api/domain/"):
            domain = unquote(self.path[len("/api/domain/"):]).strip().lower()
            if domain:
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target:
                    self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "data": target
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
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
                    # OPTIMIZATION: Load only recent history for subdomain detail page (limit for performance)
                    # Reduced to 500 entries for better performance with large datasets
                    history = load_domain_history(domain, limit=500)
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
        
        if self.path.startswith("/api/state"):
            # Parse query parameters
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            full = params.get("full", ["false"])[0].lower() in ("true", "1", "yes")
            
            # OPTIMIZATION: Pagination support for large datasets
            page = 1
            per_page = None  # None = no pagination (default for backward compatibility)
            if "page" in params:
                try:
                    page = max(1, int(params["page"][0]))
                except (ValueError, IndexError):
                    page = 1
            if "per_page" in params:
                try:
                    per_page = max(1, min(1000, int(params["per_page"][0])))  # Max 1000 per page
                except (ValueError, IndexError):
                    per_page = None
            
            # Get cached payload with ETag (pagination not cached - would explode cache)
            if per_page is None:
                etag, payload = get_cached_state_payload(full=full)
                
                # Check If-None-Match header for conditional requests
                client_etag = self.headers.get("If-None-Match")
                if client_etag and client_etag == etag:
                    # Client has current version - return 304 Not Modified
                    self.send_response(HTTPStatus.NOT_MODIFIED)
                    self.send_header("ETag", etag)
                    self.end_headers()
                    return
            else:
                # Paginated requests bypass cache
                if full:
                    payload = build_state_payload_paginated(page=page, per_page=per_page, full=True)
                else:
                    payload = build_state_payload_paginated(page=page, per_page=per_page, full=False)
                etag = None
            
            # Return payload with ETag header (if not paginated)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if etag:
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "must-revalidate")  # Require validation with origin
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api/settings":
            self._send_json({"config": get_config()})
            return
        if self.path == "/api/workers":
            # OPTIMIZATION: Workers endpoint for real-time updates (never cached)
            # Workers dashboard needs live data, not cached state
            self._send_json({"workers": snapshot_workers()})
            return
        if self.path == "/api/api-keys":
            self._send_json(get_all_api_keys())
            return
        if self.path == "/api/monitors":
            self._send_json({"monitors": list_monitors()})
            return
        if self.path == "/api/system-resources":
            self._send_json(get_system_resource_snapshot())
            return
        if self.path == "/api/dynamic-mode":
            self._send_json(get_dynamic_mode_status())
            return
        if self.path == "/api/auto-backup-status":
            self._send_json(get_auto_backup_status())
            return
        if self.path == "/api/cleanup-status":
            self._send_json(get_cleanup_status())
            return
        if self.path == "/api/backups":
            self._send_json({"backups": list_backups()})
            return
        if self.path.startswith("/api/backup/download/"):
            backup_filename = unquote(self.path[len("/api/backup/download/"):])
            
            # Reject filenames with path traversal sequences
            if ".." in backup_filename or "/" in backup_filename or "\\" in backup_filename:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid filename")
                return
            
            backup_path = BACKUPS_DIR / backup_filename
            
            # Security check: prevent path traversal and symlink attacks
            try:
                resolved_backup = backup_path.resolve()
                resolved_backups_dir = BACKUPS_DIR.resolve()
                
                # Use is_relative_to if available (Python 3.9+), fallback to string check
                try:
                    is_within_dir = resolved_backup.is_relative_to(resolved_backups_dir)
                except AttributeError:
                    # Fallback for Python < 3.9
                    is_within_dir = str(resolved_backup).startswith(str(resolved_backups_dir) + os.sep)
                
                if not is_within_dir:
                    raise ValueError("Outside backups dir")
                
                # Check if it's a symlink (additional security)
                if backup_path.is_symlink():
                    raise ValueError("Symlinks not allowed")
                
                # Verify file exists and is a regular file
                if not resolved_backup.exists() or not resolved_backup.is_file():
                    raise ValueError("Not a valid file")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            data = backup_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{backup_filename}"')
            self.end_headers()
            self.wfile.write(data)
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
        
        # Serve scan result files (nikto, nuclei, nmap, httpx JSON files)
        if self.path.startswith("/results/"):
            rel_path = unquote(self.path[len("/results/"):]).lstrip("/")
            if not rel_path:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            # Security: only allow JSON files with specific prefixes
            allowed_prefixes = ["nikto_", "nuclei_", "httpx_", "ffuf_"]
            if not any(rel_path.startswith(prefix) and rel_path.endswith(".json") for prefix in allowed_prefixes):
                self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
                return
            
            requested = (DATA_DIR / rel_path).resolve()
            base = DATA_DIR.resolve()
            try:
                # Prevent path traversal
                if not str(requested).startswith(str(base)):
                    raise ValueError("Outside data dir")
                # Prevent symlink attacks
                if requested.is_symlink():
                    raise ValueError("Symlinks not allowed")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            if not requested.exists() or not requested.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            data = requested.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{rel_path}"')
            self.end_headers()
            self.wfile.write(data)
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
                # OPTIMIZATION: Reduced from 5000 to 1000 for better performance
                # Load up to 1000 recent entries from database for command filtering
                # This is sufficient since we filter for commands (which are ~10% of logs)
                # and then slice to the requested limit (default 200, max 2000)
                events = load_domain_history(domain, limit=1000)
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
                # Load only the last 1000 events directly from database for better performance
                events = load_domain_history(domain, limit=1000)
            except RuntimeError as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self._send_json({"domain": domain, "events": events})
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
            "/api/api-keys",
            "/api/jobs/pause",
            "/api/jobs/resume",
            "/api/jobs/resume-all",
            "/api/targets/resume",
            "/api/monitors",
            "/api/monitors/delete",
            "/api/backup/create",
            "/api/backup/restore",
            "/api/backup/delete",
            "/api/cleanup/run",
            "/api/subdomain/mark",
            "/api/subdomain/comment",
            "/api/target/comment",
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
        
        if self.path == "/api/backup/create":
            name = payload.get("name", "")
            success, message, filename = create_backup(name if name else None)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "filename": filename}, status=status)
            return
        
        if self.path == "/api/backup/restore":
            filename = payload.get("filename", "")
            if not filename:
                self._send_json({"success": False, "message": "Filename is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            success, message = restore_backup(filename)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return
        
        if self.path == "/api/backup/delete":
            filename = payload.get("filename", "")
            if not filename:
                self._send_json({"success": False, "message": "Filename is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            success, message = delete_backup(filename)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return
        
        if self.path == "/api/cleanup/run":
            try:
                stats = run_cleanup()
                total = sum(stats.values())
                message = f"Cleanup completed: {stats['temp_files']} temp files, {stats['scan_results']} scan results, {stats['backups']} backups removed"
                self._send_json({"success": True, "message": message, "stats": stats}, status=HTTPStatus.OK)
            except Exception as exc:
                self._send_json({"success": False, "message": f"Cleanup failed: {str(exc)}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
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

        if self.path == "/api/api-keys":
            amass_keys = payload.get("amass", {})
            subfinder_keys = payload.get("subfinder", {})
            success, message = save_all_api_keys(amass_keys, subfinder_keys)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/subdomain/mark":
            domain = payload.get("domain", "").strip().lower()
            subdomain = payload.get("subdomain", "").strip().lower()
            interesting = payload.get("interesting")  # Can be true, false, or null
            
            if not domain or not subdomain:
                self._send_json({"success": False, "message": "Domain and subdomain are required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target or subdomain not in target.get("subdomains", {}):
                self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            # Update the interesting flag
            sub_data = target["subdomains"][subdomain]
            if interesting is None:
                sub_data.pop("interesting", None)
            else:
                sub_data["interesting"] = bool(interesting)
            
            save_state(state)
            self._send_json({"success": True, "message": "Subdomain marked successfully"})
            return

        if self.path == "/api/subdomain/comment":
            domain = payload.get("domain", "").strip().lower()
            subdomain = payload.get("subdomain", "").strip().lower()
            comment_text = payload.get("comment", "").strip()
            action = payload.get("action", "add")  # add or delete
            comment_id = payload.get("comment_id")
            
            if not domain or not subdomain:
                self._send_json({"success": False, "message": "Domain and subdomain are required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target or subdomain not in target.get("subdomains", {}):
                self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            sub_data = target["subdomains"][subdomain]
            comments = sub_data.get("comments", [])
            
            if action == "add":
                if not comment_text:
                    self._send_json({"success": False, "message": "Comment text is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                new_comment = {
                    "id": str(uuid.uuid4()),
                    "text": comment_text,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                comments.append(new_comment)
                sub_data["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment added", "comment": new_comment})
            elif action == "delete":
                if not comment_id:
                    self._send_json({"success": False, "message": "Comment ID is required for delete"}, status=HTTPStatus.BAD_REQUEST)
                    return
                original_count = len(comments)
                comments = [c for c in comments if c.get("id") != comment_id]
                if len(comments) == original_count:
                    self._send_json({"success": False, "message": "Comment not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                sub_data["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment deleted"})
            else:
                self._send_json({"success": False, "message": "Invalid action"}, status=HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/target/comment":
            domain = payload.get("domain", "").strip().lower()
            comment_text = payload.get("comment", "").strip()
            action = payload.get("action", "add")  # add or delete
            comment_id = payload.get("comment_id")
            
            if not domain:
                self._send_json({"success": False, "message": "Domain is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target:
                self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            comments = target.get("comments", [])
            
            if action == "add":
                if not comment_text:
                    self._send_json({"success": False, "message": "Comment text is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                new_comment = {
                    "id": str(uuid.uuid4()),
                    "text": comment_text,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                comments.append(new_comment)
                target["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment added", "comment": new_comment})
            elif action == "delete":
                if not comment_id:
                    self._send_json({"success": False, "message": "Comment ID is required for delete"}, status=HTTPStatus.BAD_REQUEST)
                    return
                original_count = len(comments)
                comments = [c for c in comments if c.get("id") != comment_id]
                if len(comments) == original_count:
                    self._send_json({"success": False, "message": "Comment not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                target["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment deleted"})
            else:
                self._send_json({"success": False, "message": "Invalid action"}, status=HTTPStatus.BAD_REQUEST)
            return

        success, message, cfg = update_config_settings(payload)
        status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
        self._send_json({"success": success, "message": message, "config": cfg}, status=status)

    def log_message(self, format: str, *args) -> None:
        log(f"HTTP {self.address_string()} - {format % args}")


def run_server(host: str, port: int, interval: int) -> None:
    global HTML_REFRESH_SECONDS, COMPLETED_JOBS
    config = get_config()
    refresh = interval or config.get("default_interval", DEFAULT_INTERVAL)
    HTML_REFRESH_SECONDS = max(5, refresh)
    ensure_dirs()
    
    # Load completed jobs from disk
    loaded_jobs = load_completed_jobs()
    with JOB_LOCK:
        COMPLETED_JOBS.clear()
        COMPLETED_JOBS.update(loaded_jobs)
    log(f"Loaded {len(loaded_jobs)} completed job(s) from disk.")
    
    start_monitor_worker()
    start_system_resource_worker()  # Start system resource monitoring
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
    parser.add_argument(
        "--skip-setup",
        action="store_true",
        help="Skip the first-run setup wizard (not recommended for first run)."
    )

    args = parser.parse_args()

    ensure_dirs()
    
    # Initialize database and migrate old data if needed
    ensure_database()
    
    # Check if this is the first run and run setup wizard
    cfg = get_config()
    setup_completed = cfg.get("setup_completed", False)
    
    if not setup_completed and not args.skip_setup:
        # Only run setup wizard in interactive mode
        if sys.stdin.isatty():
            try:
                run_setup_wizard()
                # Reload config after setup
                cfg = get_config()
            except KeyboardInterrupt:
                print("\n\nSetup interrupted by user.")
                print("You can run the setup wizard again next time,")
                print("or configure settings through the web UI.")
                print("\nContinuing with default settings...\n")
                # Mark setup as completed so we don't prompt again
                cfg["setup_completed"] = True
                save_config(cfg)
        else:
            log("First run detected but running in non-interactive mode.")
            log("Skipping setup wizard. You can configure settings through the web UI.")
            cfg["setup_completed"] = True
            save_config(cfg)
    
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
