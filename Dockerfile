# Multi-platform Dockerfile for subScraper reconnaissance tool
# Uses Kali Linux base image with pre-installed security tools
# Supports linux/amd64, linux/arm64

FROM kalilinux/kali-rolling AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    GO_VERSION=1.21.5

# Update and install base dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for many recon tools)
ARG TARGETARCH
RUN case ${TARGETARCH} in \
        "amd64") GO_ARCH="amd64" ;; \
        "arm64") GO_ARCH="arm64" ;; \
        *) GO_ARCH="amd64" ;; \
    esac && \
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}" \
    GOPATH="/root/go" \
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

# Install findomain (binary release)
RUN case ${TARGETARCH} in \
        "amd64") FINDOMAIN_ARCH="x86_64" ;; \
        "arm64") FINDOMAIN_ARCH="aarch64" ;; \
        *) FINDOMAIN_ARCH="x86_64" ;; \
    esac && \
    wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-${FINDOMAIN_ARCH}.zip" -O findomain.zip && \
    unzip -q findomain.zip && \
    chmod +x findomain && \
    mv findomain /usr/local/bin/ && \
    rm findomain.zip || echo "Findomain installation skipped for ${TARGETARCH}"

# Install Python-based tools and psutil for system monitoring
RUN pip3 install --no-cache-dir --break-system-packages sublist3r nikto-parser psutil

# Install nikto (Perl-based)
RUN apt-get update && apt-get install -y nikto && rm -rf /var/lib/apt/lists/*

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
