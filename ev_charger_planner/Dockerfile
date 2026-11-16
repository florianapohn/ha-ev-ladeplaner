ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.11-alpine3.18
FROM ${BUILD_FROM}

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8099", "--proxy-headers", "--forwarded-allow-ips", "*"]
