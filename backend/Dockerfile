# CUDA-capable base for every Aetheris application microservice.
# The engine's built-in BuildKit frontend is intentional. A syntax=docker/dockerfile
# pin pulls docker/dockerfile from Docker Hub before the build and aborts when
# registry-1.docker.io does not resolve.
# PostgreSQL/Redis/MinIO remain vendor images; API/Celery/report/RAG/OCR services
# all inherit this image and can probe/use the NVIDIA device when admitted by
# the shared adaptive GPU semaphore.
FROM nvidia/cuda:12.6.3-runtime-ubuntu24.04 AS dependencies

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

WORKDIR /app

# archive.ubuntu.com returns intermittent HTTP 400s once a plain-HTTP install
# gets large (fontconfig, ffmpeg, tesseract). A small HTTP install of
# ca-certificates succeeds; the remaining packages are fetched over HTTPS,
# which does not hit those 400s.
RUN set -eux; \
    printf '%s\n' \
      'Acquire::Retries "5";' \
      'Acquire::http::Timeout "120";' \
      'Acquire::https::Timeout "120";' \
      'Acquire::http::Pipeline-Depth "0";' \
      'Acquire::https::Pipeline-Depth "0";' \
      'Acquire::http::No-Cache "true";' \
      'Acquire::BrokenProxy "true";' \
      'APT::Update::Error-Mode "any";' \
      > /etc/apt/apt.conf.d/99-no-pipeline; \
    n=0; \
    until apt-get update && apt-get install -y --no-install-recommends ca-certificates; do \
      n=$((n + 1)); \
      if [ "$n" -ge 5 ]; then \
        echo "ca-certificates install failed after ${n} attempts" >&2; \
        exit 1; \
      fi; \
      echo "ca-certificates install failed (attempt ${n}/5), retrying..."; \
      rm -rf /var/lib/apt/lists/*; \
      sleep $((n * 5)); \
    done; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
        -e 's|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' \
        /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
        -e 's|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' \
        /etc/apt/sources.list; \
    fi; \
    n=0; \
    until apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-venv python3-pip \
        build-essential libpq-dev gcc curl pkg-config \
        libewf-dev libtsk-dev \
        fuse3 libfuse2t64 \
        fonts-liberation fontconfig ffmpeg \
        tesseract-ocr tesseract-ocr-eng; do \
      n=$((n + 1)); \
      if [ "$n" -ge 5 ]; then \
        echo "apt install failed after ${n} attempts" >&2; \
        exit 1; \
      fi; \
      echo "apt install failed (attempt ${n}/5), retrying..."; \
      rm -rf /var/lib/apt/lists/*; \
      sleep $((n * 5)); \
    done; \
    python3 -m venv /opt/venv; \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install CUDA-enabled PyTorch first.  Compose can override TORCH_INDEX_URL for
# a driver/toolkit validated wheel channel. Requirements then reuse that torch.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cu130
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip --retries 20 \
    && python -m pip install --retries 20 --index-url "${TORCH_INDEX_URL}" torch torchvision \
    && python -m pip install --retries 20 -r requirements.txt

# This argument is intentionally below every dependency installation. The
# Windows starter changes it once per launch so only application layers rebuild.
FROM dependencies AS application
ARG AETHERIS_APP_BUILD_ID=source
COPY . .
RUN test -n "$AETHERIS_APP_BUILD_ID" && python -m compileall -q app
LABEL org.aetheris.application-build="$AETHERIS_APP_BUILD_ID"
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
