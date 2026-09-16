FROM python:3.14-slim

# Build stage only needs compilers if a wheel is missing; keep slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY rules/ ./rules/

# Runtime data dir (SQLite + uploads); mount a volume here in compose.
RUN mkdir -p data/uploads

ENV LOGSENTINEL_HOST=0.0.0.0 \
    LOGSENTINEL_PORT=8000 \
    LOGSENTINEL_DB_PATH=/app/data/logsentinel.db

WORKDIR /app/backend

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]