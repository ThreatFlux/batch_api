# Use Python 3.8 slim image as base
FROM python:3.8-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt .
COPY setup.py .
COPY pyproject.toml .
COPY README.md .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Copy source code
COPY src/ src/
COPY tests/ tests/

# Create necessary directories
RUN mkdir -p data output

# Copy data files
COPY *.csv data/

# Set Python path
ENV PYTHONPATH=/app/src

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set default command
ENTRYPOINT ["python", "-m", "threat_model"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import threat_model; print('Health check passed')" || exit 1

# Labels
LABEL maintainer="Security Team" \
      version="0.1.0" \
      description="Microsoft 365 Threat Model Generator" \
      org.opencontainers.image.source="https://github.com/yourusername/threat-model-generator"