FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PFM_DATA_DIR=/var/lib/pfmanager

RUN groupadd --system pfmanager && useradd --system --gid pfmanager --home /app pfmanager

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

RUN mkdir -p /var/lib/pfmanager && chown pfmanager:pfmanager /var/lib/pfmanager
USER pfmanager
VOLUME ["/var/lib/pfmanager"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

# The app sits behind Caddy, which terminates TLS and sets X-Forwarded-For.
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "1"]
