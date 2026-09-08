FROM python:3.11-slim

WORKDIR /app

# System deps for geoip and build if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libicu-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# GeoIP database should be mounted via docker-compose (recommended) or copied:
# COPY GeoLite2-City.mmdb /app/GeoLite2-City.mmdb
# Get the free GeoLite2-City.mmdb from MaxMind (requires free account + license key).

# Default (for backward): the monolithic worker
# For split architecture:
#   command: python ingest.py          # scale this for high event volume
#   command: python dispatcher.py      # usually 1
#   command: python report_generator.py # scale this for report generation

CMD ["python", "workerV3.py"]
