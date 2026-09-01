FROM python:3.11-slim

# System deps for Slither + solc
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Slither + solc
RUN pip install --no-cache-dir slither-analyzer solc-select
RUN solc-select install 0.8.20 && solc-select use 0.8.20

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY vulnhunt/ vulnhunt/

# Data directory (SQLite DB lives here)
RUN mkdir -p /app/vulnhunt/data /app/vulnhunt/pocs

# Volumes for persistence across deploys
VOLUME ["/app/vulnhunt/data"]

# Default: single scan cycle (Railway will restart it via CMD loop)
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "vulnhunt", "watch", "--interval", "300", "--execute"]
