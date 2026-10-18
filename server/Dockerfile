FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CSFM_DATA_DIR=/var/lib/comsense

RUN groupadd --system comsense && useradd --system --gid comsense --home /app comsense

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

RUN mkdir -p /var/lib/comsense && chown comsense:comsense /var/lib/comsense
USER comsense
VOLUME ["/var/lib/comsense"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

# The app sits behind Caddy, which terminates TLS and sets X-Forwarded-For.
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "1"]
