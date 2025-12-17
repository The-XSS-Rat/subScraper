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

---

## Contributing

Found a bug or have a feature request? Please open an issue on GitHub with:
- Feature name (Resume All, Subdomain Details, or Screenshots Gallery)
- Steps to reproduce
- Expected vs actual behavior
- Browser and version
