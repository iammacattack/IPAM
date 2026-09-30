# NEXTDC IPAM POC - API image. Build context is the repository root.
FROM python:3.13-slim AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    IPAM_SEED_DIR=/app/seed \
    IPAM_MIGRATIONS_DIR=/app/api/migrations \
    IPAM_WEB_DIR=/app/web

WORKDIR /app
COPY api/requirements.txt api/requirements.txt
RUN pip install -r api/requirements.txt

COPY engine engine
RUN pip install ./engine

COPY api api
COPY seed seed
COPY web web

RUN useradd --system --uid 10001 --no-create-home ipam
USER ipam
WORKDIR /app/api
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/healthz', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]

# Test runner: same image plus pytest/httpx and the test suite.
FROM app AS test
USER root
RUN pip install "pytest>=8,<10" "httpx>=0.27,<1"
COPY tests /app/tests
USER ipam
WORKDIR /app
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"]
