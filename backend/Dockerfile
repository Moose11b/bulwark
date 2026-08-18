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

# Nikto, pinned to a release tag. An unpinned clone of master made builds
# unreproducible and trusted whatever HEAD happened to be that day.
RUN git clone --depth 1 --branch 2.6.1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Nuclei, pinned. The previous unauthenticated releases/latest API lookup was
# rate-limited (60/hr/IP) and broke builds intermittently with an empty
# version string; a pin is reproducible and needs no API call.
ARG NUCLEI_VERSION=3.9.0
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NA="amd64"; else NA="arm64"; fi && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NA}.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent 2>/dev/null || true

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# requirements.txt is the single source of truth for Python dependencies.
# A hand-maintained list here had already drifted from it (the pydyf pin
# that keeps WeasyPrint working was missing, and the test dependencies were
# absent entirely).
RUN pip install --no-cache-dir -r requirements.txt

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
