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
# 8000: web console (plain HTTP, publish only through an HTTPS reverse proxy)
# 10443: agent listener (TLS terminated here; forward the firewall-facing port to it)
EXPOSE 8000 10443

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

CMD ["python", "-m", "app.serve"]
