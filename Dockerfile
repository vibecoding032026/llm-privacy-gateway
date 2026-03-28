# ── Stage 1: build deps ────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
# Strip UI-only packages (streamlit, pandas) from gateway requirements
RUN grep -vE "^streamlit|^pandas" requirements.txt > requirements.gateway.txt && \
    pip install --no-cache-dir --prefix=/install -r requirements.gateway.txt

# ── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL version="1.5.0"
LABEL maintainer="LLM Privacy Gateway"
LABEL description="FastAPI gateway that masks/de-masks sensitive data before sending to LLM"

# System deps: poppler for PDF rendering, tesseract for OCR (Vietnamese)
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    tesseract-ocr \
    tesseract-ocr-vie \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ ./app/

# Create non-root user and data directories
RUN groupadd -g 1001 gateway && \
    useradd -m -u 1001 -g gateway gateway && \
    mkdir -p /data/logs/audit /data/logs/requests /data/logs/usage /data/logs/mail \
             /data/chroma_db && \
    chown -R gateway:gateway /data /app

USER gateway

VOLUME ["/data"]

ENV DB_PATH=/data/users.db \
    LOG_DIR=/data/logs \
    CHROMA_PATH=/data/chroma_db \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
