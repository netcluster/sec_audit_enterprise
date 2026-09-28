# Imagen base ligera con Python 3.11
FROM python:3.11-slim-bookworm

# Instalar dependencias de sistema mínimas y herramientas de red
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    nmap \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario sin privilegios para ejecución segura (SECURITY_GUIDELINES.md)
RUN useradd -m -u 1001 -s /bin/bash secaudit && \
    mkdir -p /app /app/logs /app/reports/exports /app/config/keys && \
    chown -R secaudit:secaudit /app

WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY --chown=secaudit:secaudit . /app

# Cambiar a usuario no-root
USER secaudit

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
