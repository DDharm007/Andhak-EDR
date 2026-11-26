FROM python:3.12-slim

WORKDIR /app

RUN useradd --create-home --shell /bin/bash andhak && mkdir -p /app/.local-data && chown -R andhak:andhak /app

COPY backend/pyproject.toml /app/backend/pyproject.toml
COPY backend/app /app/backend/app
COPY docs/contracts/DATABASE_SCHEMA.sql /app/docs/contracts/DATABASE_SCHEMA.sql

RUN pip install --no-cache-dir /app/backend

ENV PYTHONUNBUFFERED=1
ENV ANDHAK_EDR_HOST=0.0.0.0
ENV ANDHAK_EDR_PORT=8010
ENV ANDHAK_EDR_DATA_DIR=/app/.local-data

USER andhak
WORKDIR /app/backend

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/api/v1/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
