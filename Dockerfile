FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git gcc libpq-dev libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002
