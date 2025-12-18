# Quick Start Guide

## First-Time Setup

When you run subScraper for the first time, an **interactive setup wizard** will automatically launch to configure essential settings:

### What the Setup Wizard Configures
1. **Wordlist Path** - Path to subdomain wordlist for brute-force (optional)
2. **Concurrent Jobs** - Number of simultaneous scans (default: 1)
3. **Nikto Preferences** - Whether to skip Nikto scans by default
4. **Amass API Keys** - Configure data sources like Shodan, VirusTotal, SecurityTrails, etc.
5. **Subfinder API Keys** - Configure additional API sources

### Running the Setup Wizard
```bash
# First run - setup wizard launches automatically
python3 main.py

# Skip setup wizard (not recommended for first run)
python3 main.py --skip-setup
```

### After Setup
The wizard will display clear instructions on:
- ✅ What was configured
- 🚀 Commands to run next
- 📚 Where to find more information
- 🛠️ How to configure additional settings

All settings can be changed later through the web UI Settings tab.

---

## Dynamic Queue Management

### Enable Dynamic Mode
1. Open web UI at `http://127.0.0.1:8342`
2. Go to **Settings** → **Concurrency** tab
3. Scroll to "Dynamic Queue Management"
4. Check ☑️ **Enable Dynamic Mode**
5. Configure:
   ```
   Minimum concurrent jobs: 1
   Maximum concurrent jobs: 10
   CPU threshold: 75.0%
   Memory threshold: 80.0%
   ```
6. Click **Save Settings**

### What Happens
- System monitors CPU, memory, and load every 30 seconds
- Automatically adjusts concurrent jobs between 1-10
- See status in **Workers** tab: "🔄 Dynamic Mode Active"
- Watch logs for adjustment messages

### Requirements
```bash
pip3 install psutil
```

---

## Backup & Restore System

### Create Manual Backup
1. Go to **Settings** → **Backup & Restore** tab
2. Enter optional name (e.g., "before-upgrade")
3. Click **Create Backup**
4. Backup appears in list with Download/Restore/Delete buttons

### Enable Auto-Backup
1. Same tab, scroll to "Auto-Backup Settings"
2. Check ☑️ **Enable automatic backups**
3. Set interval: `3600` seconds (1 hour)
4. Set max count: `10` backups
5. Click **Save Settings**

### Restore from Backup
1. In backup list, find desired backup
2. Click **Restore** button
3. Confirm restoration
4. Page reloads automatically

### What's Backed Up
- All reconnaissance data (state.json)
- Configuration (config.json)
- Monitors (monitors.json)
- History (command logs)
- Screenshots (if any)

---

## API Quick Reference

### Dynamic Mode
```bash
# Check status
curl http://127.0.0.1:8342/api/dynamic-mode

# Enable via settings
curl -X POST http://127.0.0.1:8342/api/settings \
  -H "Content-Type: application/json" \
  -d '{"dynamic_mode_enabled": true}'
```

### Backups
```bash
# Create backup
curl -X POST http://127.0.0.1:8342/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"name": "my-backup"}'

# List backups
curl http://127.0.0.1:8342/api/backups

# Download backup
curl -O http://127.0.0.1:8342/api/backup/download/backup_my-backup_20241217_120000.tar.gz

# Restore backup
curl -X POST http://127.0.0.1:8342/api/backup/restore \
  -H "Content-Type: application/json" \
  -d '{"filename": "backup_my-backup_20241217_120000.tar.gz"}'
```

---

## Visual Location Guide

```
Web UI Navigation:
├── Overview (main dashboard)
├── Jobs (running scans)
├── Queue (pending jobs)
├── Workers ← Dynamic Mode shows here
│   └── "🔄 Dynamic Mode Active" badge
│   └── "Dynamic Mode" card with status
│   └── "💾 Auto-Backup" card (if enabled)
├── Targets (results)
├── Reports (detailed findings)
├── Monitors (feed tracking)
├── System Resources (CPU/memory/disk)
├── Logs (system logs)
└── Settings ← Configure here
    ├── General
    ├── Tool Toggles
    ├── Concurrency ← Dynamic Mode settings here
    ├── Backup & Restore ← Backup settings here
    ├── Tool Templates
    └── Toolchain
```

---

## Troubleshooting

### Dynamic Mode not working?
- Install psutil: `pip3 install psutil`
- Check Settings → Concurrency → Enable Dynamic Mode
- Verify in Workers tab: should see dynamic indicator

### Backup creation fails?
- Check disk space: `df -h`
- Verify permissions on `recon_data/backups/`
- Check logs for errors

### Auto-backup not running?
- Verify enabled in Settings → Backup & Restore
- Check interval is at least 300 seconds (5 minutes)
- See status in Workers tab: "💾 Auto-Backup" card

---

## Performance Tips

### Dynamic Mode
- Start conservative: min=1, max=4 for first run
- Increase max gradually if system handles well
- Lower thresholds (60-70%) for shared systems
- Raise thresholds (80-90%) for dedicated systems

### Backups
- Auto-backup interval: 1-4 hours for active development
- Keep count: 5-20 depending on disk space
- Manual backups before: upgrades, experiments, changes
- Download important backups for external storage

---

## Best Practices

✅ **DO:**
- Enable dynamic mode on resource-constrained systems
- Create manual backup before major changes
- Enable auto-backup for ongoing projects
- Test restoration periodically
- Download backups for critical data

❌ **DON'T:**
- Set dynamic max too high on shared servers
- Restore during active scans (stop jobs first)
- Forget to clean up old manual backups
- Rely solely on auto-backup (download important ones)
- Set auto-backup interval too low (<5 min)

---

## Examples

### Example 1: Resource-Limited VM
```json
{
  "dynamic_mode_enabled": true,
  "dynamic_mode_base_jobs": 1,
  "dynamic_mode_max_jobs": 4,
  "dynamic_mode_cpu_threshold": 70.0,
  "dynamic_mode_memory_threshold": 75.0
}
```

### Example 2: Dedicated Server
```json
{
  "dynamic_mode_enabled": true,
  "dynamic_mode_base_jobs": 2,
  "dynamic_mode_max_jobs": 16,
  "dynamic_mode_cpu_threshold": 85.0,
  "dynamic_mode_memory_threshold": 85.0
}
```

### Example 3: Production Backup Schedule
```json
{
  "auto_backup_enabled": true,
  "auto_backup_interval": 7200,
  "auto_backup_max_count": 12
}
```
2-hour interval, keep last 24 hours (12 backups)

---

See `DYNAMIC_AND_BACKUP.md` for complete documentation.
