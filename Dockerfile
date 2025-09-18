# Python slim base
FROM python:3.11-slim

# Prevents Python from writing pyc files & enables unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    WEB_CONCURRENCY=2

# System deps (runtime libs for lxml; no heavy dev toolchains)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Copy dependency lists first to leverage Docker cache
COPY requirements.txt /app/requirements.txt

# Install Python deps
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copy app code (and model file if present)
COPY . /app

# Use a non-root user for security
RUN useradd -m -u 1001 appuser
USER 1001

# Cloud Run will send traffic to $PORT
EXPOSE 8080

# Start via gunicorn
CMD exec gunicorn -w ${WEB_CONCURRENCY} -b 0.0.0.0:${PORT} app:app
