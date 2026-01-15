FROM python:3.11-slim

LABEL maintainer="KratosComply Team"
LABEL description="KratosComply Compliance Agent - Offline-first compliance evidence scanner"
LABEL version="2.7.0"

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

# Install Python dependencies with better layer caching
# Upgrade pip first (small layer, caches well)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install lightweight dependencies first (cached separately)
# Pin numpy<2.0 for compatibility with torch 2.0.1
RUN pip install --no-cache-dir \
    typer==0.12.3 \
    pynacl==1.5.0 \
    pyyaml==6.0.2 \
    click==8.1.7 \
    "numpy<2.0"

# Install torch separately (heavy ~500MB, caches independently)
# NOTE: This step takes 5-10 minutes due to PyTorch size
RUN pip install --no-cache-dir torch==2.0.1 --index-url https://download.pytorch.org/whl/cpu

# Install sentence-transformers last (depends on torch, downloads ~80MB model)
# NOTE: Model download adds 1-2 minutes
# Using version compatible with huggingface_hub
RUN pip install --no-cache-dir "sentence-transformers==2.3.1" "huggingface_hub==0.19.4"

# Clean up to reduce image size (but keep .dist-info for package metadata)
RUN find /usr/local/lib/python3.11/site-packages -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true && \
    find /usr/local/lib/python3.11/site-packages -type f -name "*.pyc" -delete 2>/dev/null || true && \
    find /usr/local/lib/python3.11/site-packages -type f -name "*.pyo" -delete 2>/dev/null || true && \
    rm -rf /root/.cache/pip && \
    rm -rf /tmp/*

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
