# Offizielles, schlankes Python-Image verwenden
FROM python:3.11-slim

# Arbeitsverzeichnis im Container festlegen
WORKDIR /app
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Systemabhängigkeiten (falls für aiomysql/Kryptografie benötigt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libicu-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Requirements kopieren und installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Den restlichen Quellcode kopieren (deine main.py etc.)
COPY . .

# Port freigeben, auf dem Uvicorn lauscht
EXPOSE 8000

# Server starten
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
