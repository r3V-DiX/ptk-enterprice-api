FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git gcc libpq-dev libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install crlfuzz (CRLF injection scanner)
RUN curl -sL https://github.com/dwisiswant0/crlfuzz/releases/latest/download/crlfuzz_linux_amd64 \
    -o /usr/local/bin/crlfuzz && chmod +x /usr/local/bin/crlfuzz

# Install cariddi (web crawler + secrets discovery)
RUN curl -sL https://github.com/edoardottt/cariddi/releases/latest/download/cariddi_linux_amd64 \
    -o /usr/local/bin/cariddi && chmod +x /usr/local/bin/cariddi

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002
