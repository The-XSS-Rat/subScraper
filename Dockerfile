# Multi-platform Dockerfile for subScraper reconnaissance tool
# Supports linux/amd64, linux/arm64, linux/arm/v7

FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies and Go from Debian repository
# This ensures compatibility across all platforms and avoids download issues
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    ca-certificates \
    golang \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment variables
ENV GOPATH="/root/go" \
    GOBIN="/root/go/bin"

ENV PATH="${GOBIN}:${PATH}"

# Install reconnaissance tools using Go
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/gwen001/github-subdomains@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@latest

# Install ffuf
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Install gowitness for screenshots
RUN go install -v github.com/sensepost/gowitness@latest

# Install findomain (binary release) - optional, architecture-specific
# Declare TARGETARCH for architecture detection (defaults to amd64 if not set by buildx)
# Note: When building without buildx, TARGETARCH will default to amd64
ARG TARGETARCH
RUN case ${TARGETARCH:-amd64} in \
        "amd64") FINDOMAIN_ARCH="x86_64" ;; \
        "arm64") FINDOMAIN_ARCH="aarch64" ;; \
        "arm") FINDOMAIN_ARCH="armv7" ;; \
        *) FINDOMAIN_ARCH="x86_64" ;; \
    esac && \
    wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-${FINDOMAIN_ARCH}.zip" -O findomain.zip && \
    unzip -q findomain.zip && \
    chmod +x findomain && \
    mv findomain /usr/local/bin/ && \
    rm findomain.zip || echo "Findomain installation skipped for ${TARGETARCH:-amd64}"

# Install Python-based tool (sublist3r)
# Note: nikto-parser was removed as it doesn't exist in PyPI
RUN pip install --no-cache-dir sublist3r

# Install nikto (Perl-based) from GitHub
# First install Perl and dependencies
RUN apt-get update && apt-get install -y \
    perl \
    libnet-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/* && \
    git clone https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Install nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy application files
COPY main.py /app/
COPY README.md /app/

# Create data directory
# This directory stores all application data including:
# - state.json: scan results and subdomain data
# - config.json: application configuration
# - completed_jobs.json: job history (NEW - keeps reports visible in dashboard)
# - monitors.json: monitor configurations
# - history/: domain-specific command logs
# - screenshots/: captured screenshots
# - backups/: automatic and manual backups
RUN mkdir -p /app/recon_data

# Declare volume for persistent data
# Mount this directory to preserve data across container restarts:
#   docker run -v $(pwd)/recon_data:/app/recon_data ...
VOLUME ["/app/recon_data"]

# Expose port for web interface
EXPOSE 8342

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8342/api/state || exit 1

# Default command - launch web server
CMD ["python3", "main.py", "--host", "0.0.0.0", "--port", "8342"]
