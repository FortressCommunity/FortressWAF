FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/models/persisted

# The shared corpus volume is empty on first run. Seed it from the bundled
# training data so training has a base set before the collector adds live
# samples. The script only copies files that are missing, so an existing volume
# is never overwritten.
COPY docker-seed-corpus.sh /usr/local/bin/seed-corpus
RUN chmod +x /usr/local/bin/seed-corpus

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["sh", "-c", "/usr/local/bin/seed-corpus && exec uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 2"]
