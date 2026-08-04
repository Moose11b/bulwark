FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    git \
    wget \
    unzip \
    perl \
    gcc \
    libpq-dev \
    libcap2-bin \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NA="amd64"; else NA="arm64"; fi && \
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_${NA}.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent 2>/dev/null || true

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

RUN pip install --no-cache-dir \
    fastapi==0.115.5 \
    uvicorn[standard]==0.32.1 \
    python-multipart==0.0.12

RUN pip install --no-cache-dir \
    sqlalchemy[asyncio]==2.0.36 \
    asyncpg==0.30.0 \
    alembic==1.14.0 \
    greenlet==3.1.1

RUN pip install --no-cache-dir \
    pydantic==2.10.1 \
    pydantic-settings==2.6.1 \
    email-validator==2.2.0

RUN pip install --no-cache-dir \
    celery==5.4.0 \
    redis==5.2.0 \
    celery-redbeat==2.2.0 \
    flower==2.0.1

RUN pip install --no-cache-dir \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    svix==1.36.0

RUN pip install --no-cache-dir \
    httpx==0.28.0 \
    requests==2.32.3 \
    beautifulsoup4==4.12.3 \
    dnspython==2.7.0 \
    python-nmap==0.7.1

RUN pip install --no-cache-dir \
    stripe==11.3.0

RUN pip install --no-cache-dir \
    weasyprint==62.3 \
    jinja2==3.1.4

RUN pip install --no-cache-dir \
    slack-sdk==3.33.4 \
    aiosmtplib==3.0.2

RUN pip install --no-cache-dir \
    python-dotenv==1.0.1 \
    structlog==24.4.0 \
    tenacity==9.0.0 \
    pytz==2024.2

# Test dependencies. The image installs an explicit package list rather than
# requirements.txt, so these were previously missing and the documented
# `docker compose exec backend pytest` could not run at all.
RUN pip install --no-cache-dir \
    pytest==8.3.4 \
    pytest-asyncio==0.24.0 \
    anyio==4.6.2.post1

COPY . .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as a non-root user. Nmap needs raw-socket capability for SYN scans;
# we keep it functional by granting only the nmap binary that capability
# while everything else runs unprivileged.
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap 2>/dev/null || true && \
    mkdir -p /app/reports && \
    useradd -m -u 10001 bulwark && \
    chown -R bulwark:bulwark /app && \
    chown -R bulwark:bulwark /opt/nikto 2>/dev/null || true

USER bulwark

EXPOSE 8000
