FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUTOPEN_HOME=/workspace

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ⬇ нужно, чтобы из core дергать `docker run` (будем использовать docker.sock)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl fping docker.io ca-certificates \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libxml2 libxslt1.1 \
    fonts-dejavu fonts-noto-core \
 && rm -rf /var/lib/apt/lists/*

COPY autopen.py /app/autopen.py
COPY core /app/core

CMD ["sleep","infinity"]
