# Use builder stage for compiling dependencies
FROM threatflux/python-builder:main AS builder

# Copy dependency files
COPY requirements.txt .
COPY setup.py .
COPY pyproject.toml .
COPY README.md .
COPY src src/
# Install build dependencies and project in development mode
RUN pip3 install --user --no-cache-dir -r requirements.txt


# Development stage
FROM threatflux/python-builder:main AS development

# Copy installed dependencies from builder
COPY --from=builder /home/python_builder/.local /home/python_builder/.local

# Copy source code and tests
COPY src/ src/
COPY tests/ tests/
COPY docs/ docs/
COPY setup.py .
COPY pyproject.toml .
COPY README.md .
COPY requirements.txt .
USER root

RUN mkdir -p data output && \
    chown -R python_builder:python_builder data output src tests docs
USER python_builder
# Create necessary directories
RUN pip3 install -e ".[dev]"

# Copy data files
COPY office_suite_description_mitre_dump.csv data/
COPY idp_description_mitre_dump.csv data/
COPY audit_operations.csv data/

# Set Python path
ENV PYTHONPATH=/workspace/src

# Production stage
FROM threatflux/python-builder:main AS production

# Copy installed dependencies from builder
COPY --from=builder /home/python_builder/.local /home/python_builder/.local

# Copy only necessary source code
COPY src/ src/

# Create and setup directories
RUN mkdir -p data output && \
    chown -R python_builder:python_builder data output

# Copy data files
COPY office_suite_description_mitre_dump.csv data/
COPY idp_description_mitre_dump.csv data/
COPY audit_operations.csv data/

# Set Python path
ENV PYTHONPATH=/workspace/src

# Add metadata
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="wyattroersma@gmail.com" \
      org.opencontainers.image.url="https://github.com/ThreatFlux/batch_api" \
      org.opencontainers.image.documentation="https://github.com/ThreatFlux/batch_api" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/batch_api" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.title="batch_api" \
      org.opencontainers.image.description="ThreatFlux Microsoft 365 Threat Model Generator"

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python3 -c "import threat_model; print('Health check passed')" || exit 1

# Set entrypoint and default command
ENTRYPOINT ["python3", "-m", "threat_model"]
CMD ["--help"]