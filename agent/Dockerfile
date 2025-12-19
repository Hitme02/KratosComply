FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (git for commit detection, patch for applying diffs)
RUN apt-get update && apt-get install -y \
    git \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Copy agent files
COPY agent/ /app/

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create keystore directory
RUN mkdir -p /root/.kratos/keys

# Set entrypoint
ENTRYPOINT ["python", "-m", "agent.cli"]
