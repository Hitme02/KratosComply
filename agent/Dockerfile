FROM python:3.11-slim

LABEL maintainer="KratosComply Team"
LABEL description="KratosComply Compliance Agent - Offline-first compliance evidence scanner"
LABEL version="1.0.0"

WORKDIR /app

# Install system dependencies (git for commit detection, patch for applying diffs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Copy agent source code
# Note: Build context should be the project root (parent of agent/)
# Exclude venv, __pycache__, and other build artifacts
COPY agent/agent/ /app/agent/agent/
COPY agent/__init__.py /app/agent/
COPY agent/cli.py /app/agent/cli.py
COPY agent/pyproject.toml /app/pyproject.toml

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    typer==0.12.3 \
    pynacl==1.5.0 \
    pyyaml==6.0.2 \
    click==8.1.7

# Create keystore directory with proper permissions
RUN mkdir -p /root/.kratos/keys && \
    chmod 700 /root/.kratos/keys

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Copy and set up entrypoint script
COPY agent/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command (show help)
CMD ["--help"]
