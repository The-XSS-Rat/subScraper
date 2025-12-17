# Recon Command Center

Recon Command Center is a single-file orchestrator for common reconnaissance pipelines. It runs traditional subdomain enumeration tools, probes discovered hosts, and executes vulnerability scanning workflows while presenting live progress in a rich web UI.

## Highlights

- **Full pipeline automation** – Amass/Subfinder/Assetfinder/Findomain/Sublist3r feed ffuf, httpx, screenshot capture, nuclei, and nikto in one go.
- **Stateful & resumable** – Results live in `recon_data/state.json`, so re-running a target picks up exactly where it left off. Jobs can be paused/resumed live.
- **Live dashboard** – A modern SPA served from `main.py` tracks jobs, queue, worker slots, tool availability, and detailed per-program reports.
- **System resource monitoring** – Real-time monitoring of CPU, memory, disk, and network usage with automatic warnings when thresholds are exceeded. Helps ensure the system isn't overwhelmed.
- **System Logs** – Dedicated logs view with advanced filtering (by source, level, text search) and sorting. Filter preferences persist between reloads.
- **Actionable reports** – Each target gets a dedicated page with sortable/filterable tables, paginated views, per-tool sections, command history, severity badges, and a progress overview.
- **Command history & exports** – Every command executed is logged; you can export JSON or CSV snapshots at any time.
- **Monitors** – Point the UI at a newline-delimited URL (supports wildcards like `*.corp.com` or `corp.*`). The monitor polls the file, launches new jobs when entries appear, and surfaces health/status in its own tab.
- **Concurrency controls** – Configure max running jobs and per-tool worker caps so scans behave on your box.
- **Auto-install helpers** – Best-effort installers kick in when a required tool is missing.
- **Docker support** – Multi-platform Docker container with all tools pre-installed. Works on Linux (amd64, arm64, armv7).

## Usage

### Native Installation

```bash
# Install dependencies
pip3 install -r requirements.txt

# Launch the web UI (default: http://127.0.0.1:8342)
python3 main.py

# Run a one-off target directly from the CLI
python3 main.py example.com --wordlist ./w.txt --skip-nikto

# Wildcards are supported
python3 main.py 'acme.*'        # expands using Settings ➜ wildcard TLDs
python3 main.py '*.apps.acme.com'
```

### Docker Installation

The easiest way to get started with all tools pre-installed:

```bash
# Build the container (see DOCKER_BUILD.md for Mac-specific instructions)
docker build -t subscraper:latest .

# Run the container
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest

# Access the web interface at http://localhost:8342
```

For detailed Docker build instructions including multi-platform builds for Mac, see [DOCKER_BUILD.md](DOCKER_BUILD.md).

Inside the UI you can:

1. Launch new jobs from the Overview module.
2. Pause/resume running jobs in the Jobs module.
3. Inspect tool/worker utilization in Workers.
4. **Monitor system resources in the System Resources tab** – View real-time CPU, memory, disk, and network usage with automatic warnings.
5. View system logs with filtering and sorting in the Logs tab (filter by source, level, or search text).
6. Drill into the revamped Reports page to see per-program progress, completed vs pending steps, collapsible per-tool sections, paginated tables, and the max-severity badge.
7. Configure monitoring feeds under the Monitors tab – each monitor shows polling health, last fetch, number of pending entries, and per-entry dispatch status.
8. Export raw data or tweak defaults in Settings (concurrency, wordlists, skip flags, wildcard TLD expansion, etc.).

All output (jsonl history, tool artifacts, screenshots, monitor metadata) lives under `recon_data/`, making it easy to version, sync, or analyze with other tooling.

## System Resource Monitoring

The System Resources tab provides comprehensive real-time monitoring to help ensure your scans don't overwhelm the system:

### Monitored Metrics

- **CPU Usage**: Overall CPU utilization, per-core usage, load averages, and frequency
- **Memory Usage**: RAM consumption, available memory, and swap usage
- **Disk Usage**: Storage consumption, I/O operations (reads/writes)
- **Network I/O**: Bytes and packets sent/received, errors and drops
- **Application Metrics**: Process-specific CPU and memory usage, thread count

### Features

- **Real-time Updates**: Metrics refresh every 5 seconds
- **Historical Data**: View usage trends over the last 5 minutes with sparkline charts
- **Automatic Warnings**: Get alerts when resource usage exceeds safe thresholds:
  - CPU > 75% (Warning), > 90% (Critical)
  - Memory > 80% (Warning), > 90% (Critical)  
  - Disk > 85% (Warning), > 95% (Critical)
  - Swap > 50% (Warning - indicates memory pressure)
- **Visual Indicators**: Color-coded cards (green=normal, orange=warning, red=critical)
- **Persistent State**: Resource history is saved to disk for analysis

### API Access

Access resource metrics programmatically:

```bash
# Get current system resources
curl http://127.0.0.1:8342/api/system-resources
```

Response format:
```json
{
  "current": {
    "available": true,
    "timestamp": "2025-12-17T17:30:00Z",
    "cpu": {
      "percent": 45.2,
      "per_core": [52.1, 38.3, ...],
      "count_logical": 8,
      "count_physical": 4,
      "frequency_mhz": 2400,
      "load_avg_1m": 2.5,
      "load_avg_5m": 2.2,
      "load_avg_15m": 1.8
    },
    "memory": {
      "total_gb": 16.0,
      "used_gb": 8.5,
      "available_gb": 7.5,
      "percent": 53.1
    },
    "warnings": [...]
  },
  "history": [...]
}
```

## Development Notes

The project intentionally stays self-contained:

- Everything (scheduler, API server, UI) lives in `main.py`.
- No third-party web framework; the UI is rendered client-side with vanilla JS/HTML/CSS embedded in the script.
- Concurrency is managed with Python threads and lightweight gates (`ToolGate`) to keep tool usage predictable.
- State files are protected with a simple file lock to avoid concurrent writes.
- System resource monitoring uses `psutil` for cross-platform compatibility.

### Helpful Commands

```bash
# Format / validate
python3 -m py_compile main.py

# Inspect current jobs / queues
curl http://127.0.0.1:8342/api/state | jq

# Export recent command history for a program
curl 'http://127.0.0.1:8342/api/history/commands?domain=example.com'

# Monitor system resources
curl http://127.0.0.1:8342/api/system-resources | jq
```

Feel free to tailor the pipeline order, add custom steps, or integrate additional tooling. Contributions welcome!
