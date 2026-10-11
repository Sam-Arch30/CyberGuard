# =====================================================================
# CyberGuard AI - Backend Service Multi-Stage Hardened Dockerfile
# Section 74: Non-root container, multi-stage compilation, immutable filesystem
# =====================================================================

# ---------------------------------------------------------------------
# Stage 1: Builder (Compiles C extensions and Python wheels)
# ---------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies for compiling wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Build Python wheels in isolated directory
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ---------------------------------------------------------------------
# Stage 2: Hardened Production Runtime (Lean, Non-Root)
# ---------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Install only minimal runtime shared libraries (curl for container healthcheck, libpq5 for PostgreSQL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Security: Create dedicated unprivileged system user and group (UID/GID 10001)
RUN groupadd -g 10001 cyberguard && \
    useradd -u 10001 -g cyberguard -s /bin/bash -m -d /home/cyberguard cyberguard

WORKDIR /app

# Copy compiled Python packages from builder stage to unprivileged user's directory
COPY --from=builder --chown=cyberguard:cyberguard /root/.local /home/cyberguard/.local

# Create application data and storage directories with proper ownership
RUN mkdir -p \
    /app/backend/data/storage \
    /app/backend/data/eml_store \
    /app/backend/data/reports \
    /app/backend/data/backups \
    && chown -R cyberguard:cyberguard /app

# Copy application source code with unprivileged user ownership
COPY --chown=cyberguard:cyberguard backend/ /app/backend/
COPY --chown=cyberguard:cyberguard scripts/ /app/scripts/
COPY --chown=cyberguard:cyberguard alembic.ini /app/alembic.ini

# Security: Switch to non-root user
USER cyberguard

# Environment settings
ENV PATH=/home/cyberguard/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV CYBERGUARD_ENV=PRODUCTION

# Expose internal API service port
EXPOSE 8000

# Container healthcheck using liveness probe
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Start production ASGI server bound to 0.0.0.0:8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
