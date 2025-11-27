FROM python:3.12-slim

RUN set -eux; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg2 ca-certificates apt-transport-https \
        gcc g++ make build-essential \
        unixodbc-dev libssl3 && \
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] \
        https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/microsoft.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql18 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*



WORKDIR /app

COPY app ./app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt 


CMD ["uvicorn", "app.main:app","--host", "0.0.0.0", "--port", "8000"]
