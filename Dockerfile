# Amadioha Cyber Defense — Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 amadioha && \
    chown -R amadioha:amadioha /app

USER amadioha

# Expose port for Flask app
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Run Gunicorn in production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "sync", "--timeout", "120", "amadioha.web:app"]
