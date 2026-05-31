# =============================================================================
# Dockerfile — Vulnerable JWT API (Person 1)
# =============================================================================
# Builds a containerised version of the intentionally vulnerable Flask API.
#
# Build:  docker build -t jwt-lab-api .
# Run:    docker run -p 5001:5001 jwt-lab-api
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="JWT Lab Team"
LABEL description="Intentionally vulnerable JWT authentication API — CTF/educational use only"

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Generate RSA keys at build time
RUN python generate_keys.py

# Expose Flask port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/')"

# Run the vulnerable API
CMD ["python", "app.py"]
