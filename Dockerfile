# syntax=docker/dockerfile:1.7
# =============================================================================
# Secure Secrets Management Sandbox — runtime image
# =============================================================================
# Single stage on purpose: the service is pure Python plus one wheel, so there
# is no build toolchain to discard. What is *not* here matters more than what
# is: no shell utilities beyond the slim base, no package manager at runtime,
# no compiler, no root process.
#
# Build context is the repository root (compose sets context: ..).
#
#   docker build -t cloudguard/secretsd:local .
#
# The container is expected to run with:
#   --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="CloudGuard Secure Secrets Management Sandbox" \
      org.opencontainers.image.description="AES-256-GCM envelope secrets service with hashed-token policies" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/kaveh8866/Secure-Secrets-Management-Sandbox"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

# Unprivileged service account, fixed uid so a bind-mounted volume has
# predictable ownership across hosts.
RUN groupadd --gid 10001 secretsd \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin secretsd

WORKDIR /app

# Dependency layer first: source edits do not re-resolve the wheel.
COPY src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY src/secretsd ./secretsd
COPY configs ./configs

# /data is the only writable location at runtime; /etc/secretsd is the default
# policy path and is mounted read-only by compose.
RUN mkdir -p /data /etc/secretsd \
 && cp configs/policies.toml /etc/secretsd/policies.toml \
 && chown -R 10001:10001 /data \
 && chmod 0700 /data

USER 10001:10001

EXPOSE 8200

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/healthz', timeout=2)"]

# Signals are handled in-process: SIGTERM drains the listener and exits 0.
STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "secretsd"]
