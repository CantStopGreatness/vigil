FROM python:3.12-slim

WORKDIR /app
# FORWARDED_ALLOW_IPS: set to your reverse proxy's address so rate limiting sees real client IPs.
# The default trusts only loopback, so X-Forwarded-For can't be spoofed when exposed directly.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VIGIL_DB=/data/vigil.db FORWARDED_ALLOW_IPS=127.0.0.1

COPY pyproject.toml README.md ./
COPY vigil ./vigil
RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 1000 vigil \
 && mkdir /data && chown vigil /data

USER vigil
VOLUME /data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
# One worker on purpose: the rate limiter and concurrency cap are in-process.
CMD ["uvicorn", "vigil.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--no-server-header"]
