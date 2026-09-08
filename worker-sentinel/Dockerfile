FROM python:3.11-slim

WORKDIR /app

# System dependencies for build processes and geoip
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libicu-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Wrapper, der -std=c++17 an das Ende aller g++ Aufrufe anfügt
# Dies übersteuert das von PyICU 2.10.2 hartkodierte -std=c++11
RUN printf '#!/bin/sh\nexec /usr/bin/g++ "$@" -std=c++17\n' > /usr/local/bin/g++ && \
    chmod +x /usr/local/bin/g++

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "workerV3.py"]
