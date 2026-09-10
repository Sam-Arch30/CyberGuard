# =====================================================================
# MailTrace AI - Backend Service Dockerfile
# =====================================================================
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies: curl for container healthcheck, libpq for Postgres
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application package and Alembic configuration
COPY backend/ ./backend/
COPY alembic.ini .

# Set Python runtime environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Start Uvicorn server bound to 0.0.0.0:8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
