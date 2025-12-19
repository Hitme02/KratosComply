FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend files
COPY backend/ /app/

# Install Python dependencies directly
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy python-dotenv httpx psycopg2-binary pynacl

# Expose port
EXPOSE 8000

# Set PYTHONPATH to current directory
ENV PYTHONPATH=/app

# Run backend
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
