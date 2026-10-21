FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_DB_PATH=/data/gateway_logs.sqlite3

WORKDIR /app

COPY requirements.txt ./
COPY requirements-ai.txt ./
ARG INSTALL_AI=false
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_AI" = "true" ]; then pip install --no-cache-dir -r requirements-ai.txt; fi \
    && mkdir -p /data \
    && chown 10001:10001 /data

COPY main.py ./main.py
COPY detectors.py providers.py ./
COPY static ./static

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
