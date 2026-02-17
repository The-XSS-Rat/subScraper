# Docker Build Instructions for Mac (Multi-platform)

This guide explains how to build the subScraper Docker container on macOS for multiple platforms.

## What's New

**Persistent Completed Job Reports**: As of the latest version, completed scan reports now persist in the dashboard and across container restarts. All job history is stored in `recon_data/completed_jobs.json` and automatically loaded on startup.

## Prerequisites

1. **Install Docker Desktop for Mac**
   - Download from: https://www.docker.com/products/docker-desktop
   - Install and start Docker Desktop

2. **Enable BuildKit and Multi-platform Support**
   
   Docker Desktop for Mac includes buildx by default, but you need to create a builder:

   ```bash
   # Create a new builder instance
   docker buildx create --name multiplatform --driver docker-container --use
   
   # Bootstrap the builder
   docker buildx inspect --bootstrap
   ```

## Building the Container

### Option 1: Build for Your Current Platform (Fastest)

If you just want to build for your Mac's architecture:

```bash
# For Apple Silicon Macs (M1/M2/M3)
docker build -t subscraper:latest .

# For Intel Macs
docker build -t subscraper:latest .
```

### Option 2: Build for Multiple Platforms

To build a multi-platform image that works on different architectures:

```bash
# Build for multiple platforms and push to a registry
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t yourusername/subscraper:latest \
  --push .

# Or build and load for local use (single platform at a time)
docker buildx build --platform linux/amd64 \
  -t subscraper:latest \
  --load .
```

### Option 3: Build for Specific Platform

If you need to build specifically for a different platform:

```bash
# For Linux AMD64 (most cloud servers)
docker buildx build --platform linux/amd64 \
  -t subscraper:amd64 \
  --load .

# For Linux ARM64 (AWS Graviton, Raspberry Pi 4)
docker buildx build --platform linux/arm64 \
  -t subscraper:arm64 \
  --load .

# For Linux ARM v7 (Raspberry Pi 3)
docker buildx build --platform linux/arm/v7 \
  -t subscraper:armv7 \
  --load .
```

## Running the Container

### First-Time Setup (Required)

On the first run, you need to create an admin account. Run the container in interactive mode:

```bash
# Create recon_data directory first (if it doesn't exist)
mkdir -p recon_data

# Run in interactive mode to create admin account
docker run -it \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest

# Follow the prompts to:
# 1. Create an admin account (username and password)
# 2. Configure basic settings (or skip and configure later via web UI)
```

After the admin account is created and the server starts, you can:
- Press `Ctrl+C` to stop the server
- Remove the container: `docker rm subscraper`
- Run in detached mode (see "Basic Run" below)

**Important**: The admin account and all configuration is stored in the `recon_data` volume, so you only need to do this once.

### Basic Run

After initial setup, run in detached mode:

```bash
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest
```

**Important**: The `recon_data` volume mount is required to persist:
- Scan results and state (`state.json`)
- Configuration settings (`config.json`)
- Completed job reports (`completed_jobs.json`) - *keeps scan history visible*
- Domain history logs (`history/`)
- Screenshots (`screenshots/`)
- Backup files (`backups/`)
- Monitor configurations (`monitors.json`)

Without the volume mount, all data will be lost when the container stops.

### Run with Custom Configuration

```bash
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  -v $(pwd)/wordlists:/app/wordlists \
  -e PYTHONUNBUFFERED=1 \
  subscraper:latest
```

### Run with Interactive Shell

```bash
docker run -it \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest \
  /bin/bash
```

### Run a One-off Scan

```bash
docker run --rm \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest \
  python3 main.py example.com --wordlist ./wordlists/common.txt
```

## Accessing the Web Interface

Once the container is running, access the web interface at:
- http://localhost:8342

## Data Persistence and Management

### Understanding Data Persistence

All application data is stored in the `recon_data` directory, which should be mounted as a volume:

```
recon_data/
├── state.json              # Scan results and subdomain data
├── config.json             # Application configuration
├── completed_jobs.json     # Job history (keeps reports visible)
├── monitors.json           # Monitor configurations
├── system_resources.json   # Resource monitoring data
├── history/                # Domain-specific command logs
├── screenshots/            # Captured screenshots
└── backups/               # Automatic and manual backups
```

### Backing Up Data

**Method 1: Copy the entire directory**
```bash
# While container is running
docker cp subscraper:/app/recon_data ./backup_$(date +%Y%m%d)
```

**Method 2: Use built-in backup feature**
1. Access the web interface at http://localhost:8342
2. Go to Settings → Backup & Restore
3. Click "Create Backup"
4. Backups are saved to `recon_data/backups/`

### Restoring Data

**Method 1: Restore from directory backup**
```bash
# Stop the container
docker stop subscraper

# Restore the data
cp -r ./backup_20231217/* ./recon_data/

# Start the container
docker start subscraper
```

**Method 2: Use built-in restore feature**
1. Access the web interface
2. Go to Settings → Backup & Restore
3. Select a backup and click "Restore"

### Migrating to a New Container

To migrate data to a new container:

```bash
# Stop old container
docker stop subscraper

# Backup data
cp -r ./recon_data ./recon_data_backup

# Remove old container
docker rm subscraper

# Start new container with same volume
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest
```

All completed job reports, scan results, and configuration will be preserved.

## Docker Compose (Optional)

### First-Time Setup with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  subscraper:
    build: .
    container_name: subscraper
    ports:
      - "8342:8342"
    volumes:
      # Required: Persists all scan data, job history, and configuration
      - ./recon_data:/app/recon_data
      # Optional: Custom wordlists for subdomain brute-forcing
      - ./wordlists:/app/wordlists
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8342/api/state"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
```

**First Run**: Create admin account in interactive mode:

```bash
# Build and run in interactive mode for first-time setup
docker-compose run --rm subscraper

# Follow the prompts to create admin account
# After setup, stop with Ctrl+C

# Then start normally in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

**Data Persistence**: The `recon_data` volume ensures:
- ✅ Completed job reports remain visible in dashboard
- ✅ All scan results persist across container restarts
- ✅ Configuration and settings are preserved
- ✅ Backup files are accessible

## Troubleshooting

### Issue: "ERROR: No admin account exists"

If the container exits immediately with this error, you need to create an admin account first:

```bash
# Run in interactive mode to create admin account
docker run -it \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest

# Or with docker-compose:
docker-compose run --rm subscraper
```

Follow the prompts to create an admin account. The account is saved in `recon_data/users.json` and persists across container restarts.

### Issue: "no matching manifest"

This means the image wasn't built for your platform. Rebuild with:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t subscraper:latest --load .
```

### Issue: Tools not found

Some tools may fail to install on certain architectures. Check the build logs:

```bash
docker buildx build --platform linux/arm64 -t subscraper:latest --load . --progress=plain
```

### Issue: Permission denied

If you get permission errors with mounted volumes:

```bash
# On Mac, ensure Docker has access to the directory in:
# Docker Desktop -> Settings -> Resources -> File Sharing
```

## Performance Tips

1. **Use BuildKit Cache**: BuildKit caches layers efficiently, making rebuilds faster

2. **Allocate More Resources**: In Docker Desktop settings, increase:
   - CPUs: 4+ cores recommended
   - Memory: 8GB+ recommended

3. **Use .dockerignore**: Create a `.dockerignore` file to exclude unnecessary files:

```
recon_data/
__pycache__/
*.pyc
.git/
.gitignore
```

## Platform-Specific Notes

### Apple Silicon (M1/M2/M3)

- Native ARM64 builds are fastest on Apple Silicon
- Use `--platform linux/arm64` for native builds
- Cross-compilation to AMD64 works but is slower

### Intel Macs

- Native AMD64 builds
- Use `--platform linux/amd64` for native builds
- Can build ARM images but slower due to emulation

## Advanced: Multi-platform Registry Push

To build and push to Docker Hub for all platforms:

```bash
# Login to Docker Hub
docker login

# Build and push multi-platform image
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t yourusername/subscraper:latest \
  -t yourusername/subscraper:v1.0.0 \
  --push .
```

Then others can pull with:

```bash
docker pull yourusername/subscraper:latest
```

Docker will automatically pull the correct architecture for their system.

## Cleanup

```bash
# Stop and remove container
docker stop subscraper && docker rm subscraper

# Remove image
docker rmi subscraper:latest

# Remove builder
docker buildx rm multiplatform

# Clean up build cache
docker buildx prune -f
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/The-XSS-Rat/subScraper/issues
- Check Docker logs: `docker logs subscraper`
