# Stable Python Base
FROM python:3.11-slim

# Install Bash required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    whois \
    nmap \
    dnsutils \
    curl \
    jq \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -r recongroup && useradd -r -g recongroup -d /app reconuser

WORKDIR /app

# Install Python required dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Concede execution privileges and transfer ownership
RUN chmod +x core/automated_recon.sh && \
    chown -R reconuser:recongroup /app

# Switch execution to unprivileged user
USER reconuser

# Port used by Flask API
EXPOSE 5000

# Init Gateway
CMD ["python", "web/routes.py"]
