# syntax=docker/dockerfile:1
# PureOS-CPC — encrypted comms server
# Part of SRV-HTZNR-EU-SWS · Synapse security layer

FROM python:3.12-slim AS base
WORKDIR /app

# Install deps (pycryptodome for AES/RSA)
RUN pip install --no-cache-dir pycryptodome

# Non-root user
RUN groupadd -r cpc && useradd -r -g cpc cpc

COPY --chown=cpc:cpc . .

USER cpc

# server.py listens on 5000, client.py connects to 5001
EXPOSE 5000 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',5000)); s.close()" || exit 1

CMD ["python", "server.py"]
