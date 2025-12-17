# New Features Guide

This document describes the new features added to the Recon Command Center.

## 1. Resume All Paused Scans

### What It Does
Resumes all paused jobs with a single click, saving you from having to resume each job individually.

### How to Use
1. Navigate to the **Jobs** section in the web UI
2. Look for the "Resume All Paused" button in the section header (right side)
3. Click the button
4. The button will show "Resuming..." while processing
5. A success message will appear showing how many jobs were resumed
6. The job list will automatically refresh

### When to Use
- After pausing multiple jobs for system maintenance
- When you want to continue all work after taking a break
- To quickly restart your reconnaissance pipeline

### API Usage
```bash
curl -X POST http://127.0.0.1:8342/api/jobs/resume-all \
  -H "Content-Type: application/json"
```

**Response**:
```json
{
  "success": true,
  "message": "Resumed 3 of 3 paused jobs.",
  "results": [
    {
      "domain": "example.com",
      "success": true,
      "message": "example.com resumed."
    }
  ]
}
```

---

## 2. Subdomain Detail Pages

### What It Does
Provides a dedicated, bookmarkable page for each subdomain with complete details including HTTP data, screenshots, and all vulnerability findings.

### How to Use
1. Click any subdomain link in the Reports section
2. You'll be taken to `/subdomain/{domain}/{subdomain}`
3. View all details about that specific subdomain
4. Click "← Back to Dashboard" to return

### What You'll See
- **Metadata**: Parent domain and discovery sources
- **HTTP Response**: Status code, title, server, content-type, technologies
- **Screenshot**: Full-size screenshot (if available)
- **Nuclei Findings**: Complete vulnerability table with severity, template, and location
- **Nikto Findings**: Detailed security scan results

### Navigation Features
- **Bookmarkable**: Save links for later reference
- **Shareable**: Send direct links to team members
- **Browser Integration**: Works with back/forward buttons
- **New Tabs**: Right-click to open in new tab

### URL Pattern
```
http://127.0.0.1:8342/subdomain/example.com/www.example.com
```

### API Usage
```bash
curl http://127.0.0.1:8342/api/subdomain/example.com/www.example.com
```

---

## 3. Screenshots Gallery

### What It Does
Displays all screenshots for a domain in a responsive grid layout with lazy loading for optimal performance. Perfect for identifying patterns across subdomains.

### How to Use
1. Go to any domain report in the Reports section
2. Look for the "View Screenshots Gallery" button in the report header
3. Click to open the gallery page
4. Scroll through thumbnails
5. Click any thumbnail to view full-size

### Gallery Features
- **Grid Layout**: Responsive, auto-filling columns
- **Lazy Loading**: Images load only as you scroll
- **Click to Expand**: View full-size in modal overlay
- **Rich Metadata**: See subdomain, URL, status code, title, and timestamp
- **Color-Coded Status**: Visual indicators for HTTP status codes
  - 🟢 Green (2xx): Success
  - 🔵 Blue (3xx): Redirect
  - 🟠 Orange (4xx): Client Error
  - 🔴 Red (5xx): Server Error

### Performance Benefits
- **Fast Initial Load**: Only visible images load immediately
- **Smooth Scrolling**: Images preload 50px before becoming visible
- **Low Memory**: Only active images consume resources
- **No Lag**: Native browser APIs, no heavy libraries

### Pattern Recognition
Use the gallery to spot:
- Common UI patterns across subdomains
- Consistent branding or design
- Error pages or misconfigurations
- Default installations
- Potential targets for further investigation

### URL Pattern
```
http://127.0.0.1:8342/gallery/example.com
```

### API Usage
```bash
curl http://127.0.0.1:8342/api/gallery/example.com
```

**Response**:
```json
{
  "success": true,
  "domain": "example.com",
  "screenshots": [
    {
      "subdomain": "www.example.com",
      "path": "example.com/screenshot_123.png",
      "url": "https://www.example.com",
      "title": "Example Domain",
      "status_code": 200,
      "captured_at": "2024-12-17T14:30:00Z"
    }
  ]
}
```

---

## Tips & Tricks

### Resume All
- The button only appears if there are paused jobs
- You can still resume individual jobs if needed
- Results show which jobs succeeded and which failed

### Subdomain Details
- Use the browser's bookmarks to save interesting findings
- Share direct links with your team for collaboration
- Open multiple subdomains in tabs for comparison

### Screenshots Gallery
- Use browser zoom (Ctrl/Cmd +/-) to adjust thumbnail size
- Click the modal background or press ESC to close full-size view
- Thumbnails maintain aspect ratio - no distortion
- Perfect for security assessments and reporting

### Performance
- Gallery loads 200px thumbnails, full images only on click
- Lazy loading works automatically, no configuration needed
- Works great even with 100+ screenshots

---

## Troubleshooting

### Resume All Not Working
- **Issue**: Button doesn't appear
- **Solution**: No jobs are currently paused

### Subdomain Page Shows Error
- **Issue**: "Subdomain not found"
- **Solution**: Run a scan first to collect subdomain data

### Screenshots Not Loading
- **Issue**: Thumbnails remain gray
- **Solution**: Scroll slowly, images load as you approach them
- **Alternative**: Check that screenshots were captured during the scan

### Gallery Page Empty
- **Issue**: "No screenshots available"
- **Solution**: Ensure screenshots are enabled in Settings and scan completed

---

## 4. System Resource Monitoring

### What It Does
Provides real-time monitoring of system resources (CPU, memory, disk, network) to help ensure reconnaissance scans don't overwhelm the system. Features automatic warnings when resource usage exceeds safe thresholds.

### How to Use
1. Navigate to the **System Resources** tab in the web UI
2. View real-time metrics updated every 5 seconds
3. Monitor historical usage trends over the last 5 minutes
4. Check for automatic warnings when thresholds are exceeded

### What You'll See
- **CPU Usage**: Overall utilization, per-core breakdown, load averages, frequency
- **Memory Usage**: RAM consumption, available memory, swap usage
- **Disk Usage**: Storage consumption, I/O operations (reads/writes)
- **Network I/O**: Data transfer statistics, packet counts, errors
- **Application Metrics**: Process-specific CPU/memory usage, thread counts

### Warning Thresholds
The system automatically generates warnings when resources exceed safe levels:
- **CPU**: Warning at 75%, Critical at 90%
- **Memory**: Warning at 80%, Critical at 90%
- **Disk**: Warning at 85%, Critical at 95%
- **Swap**: Warning at 50% (indicates memory pressure)

### Visual Indicators
- 🟢 **Green cards**: Normal operation
- 🟠 **Orange cards**: Warning threshold exceeded
- 🔴 **Red cards**: Critical threshold exceeded

### Features
- **Real-time Updates**: Metrics refresh automatically every 5 seconds
- **Historical Charts**: Sparkline visualizations show usage trends
- **Persistent State**: History saved to `recon_data/system_resources.json`
- **API Access**: Programmatic access via `/api/system-resources`
- **Cross-platform**: Works on Linux, macOS, and Windows (via psutil)

### Dependencies
The feature requires the `psutil` library:
```bash
pip3 install -r requirements.txt
```

If psutil is not available, the System Resources tab will display a message indicating monitoring is disabled.

### API Usage
```bash
# Get current system resources and history
curl http://127.0.0.1:8342/api/system-resources | jq
```

**Response**:
```json
{
  "current": {
    "available": true,
    "timestamp": "2025-12-17T17:30:00Z",
    "cpu": {
      "percent": 45.2,
      "per_core": [52.1, 38.3, 41.0, 49.5],
      "count_logical": 4,
      "count_physical": 2,
      "frequency_mhz": 2400.0,
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
    "disk": {
      "total_gb": 512.0,
      "used_gb": 128.5,
      "free_gb": 383.5,
      "percent": 25.1
    },
    "process": {
      "count": 3,
      "cpu_percent": 12.5,
      "memory_mb": 245.3,
      "threads": 15,
      "pid": 12345
    },
    "warnings": [
      {
        "severity": "warning",
        "resource": "cpu",
        "message": "CPU usage high at 76.5%",
        "value": 76.5,
        "threshold": 75
      }
    ]
  },
  "history": [
    {
      "timestamp": "2025-12-17T17:25:00Z",
      "cpu_percent": 42.1,
      "memory_percent": 51.2,
      "disk_percent": 25.1,
      "process_cpu_percent": 10.5,
      "process_memory_mb": 240.1,
      "warnings_count": 0
    }
  ]
}
```

### Use Cases
1. **System Health Monitoring**: Ensure scans aren't overwhelming the system
2. **Performance Tuning**: Identify resource bottlenecks and adjust concurrency settings
3. **Capacity Planning**: Understand resource requirements for different scan types
4. **Troubleshooting**: Diagnose performance issues and memory leaks
5. **Compliance**: Document system resource usage for security assessments

### Tips & Tricks
- Monitor the System Resources tab before starting large scans
- Adjust concurrency settings in the Settings tab if warnings appear frequently
- Use the historical charts to identify usage patterns and trends
- Check swap usage - high swap usage indicates the system needs more RAM
- Process metrics show the application's specific resource consumption

### Troubleshooting

**Issue**: "psutil not installed" message
- **Solution**: Run `pip3 install -r requirements.txt` to install dependencies

**Issue**: Metrics not updating
- **Solution**: Check browser console for errors, refresh the page

**Issue**: High resource warnings
- **Solution**: Reduce max_running_jobs or tool-specific concurrency limits in Settings

---

## Browser Compatibility

All features work in modern browsers:
- ✅ Chrome/Edge 76+
- ✅ Firefox 76+
- ✅ Safari 12.1+
- ✅ Opera 63+

**Required APIs**:
- Intersection Observer (for lazy loading)
- Fetch API (for AJAX requests)
- ES6+ JavaScript (arrow functions, async/await)

---

## Security Notes

- All new features have been security scanned (0 vulnerabilities)
- Input is properly sanitized and validated
- Screenshot paths are validated against directory traversal
- HTML output is properly escaped
- No external dependencies or CDNs used
- System resource monitoring uses read-only system APIs

---

## Contributing

Found a bug or have a feature request? Please open an issue on GitHub with:
- Feature name (Resume All, Subdomain Details, Screenshots Gallery, or System Resources)
- Steps to reproduce
- Expected vs actual behavior
- Browser and version
