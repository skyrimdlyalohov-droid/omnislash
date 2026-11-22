# Omnislash — Pre-Flight OSINT Isolation Module
# Stage: OSIS (OSINT Isolation)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OMNISLASH_CACHE_DIR=/data

# Local DNS resolver (unbound) for forced resolution via local unbound/coredns (DoH/DoT)
RUN apt-get update \
    && apt-get install -y --no-install-recommends unbound \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY engine.py .

RUN pip install --no-cache-dir requests

RUN mkdir -p /data

# targets file input and verified-manifest output
CMD ["python3", "engine.py", \
     "--targets", "/app/targets.txt", \
     "--out", "/app/targets_verified.json"]
