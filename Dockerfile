FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1


WORKDIR /app


COPY requirements.txt ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


COPY . .


# Add startup script
COPY docker-entrypoint.sh /docker-entrypoint.sh


RUN chmod +x /docker-entrypoint.sh


# Create the two directories the application writes to, before the chown.
#
# These are the mount points for the storage and logs named volumes. Docker
# seeds a fresh named volume from whatever the image has at that path,
# including ownership, so creating them here -- owned by appuser -- is what
# makes those volumes writable. Without this the volumes come up empty and
# root-owned, and the container dies in logging_setup.py at import time,
# before uvicorn starts.
RUN mkdir -p /app/storage /app/logs


# Create non-root user
RUN addgroup --system app && \
    adduser --system --ingroup app appuser && \
    chown -R appuser:app /app /docker-entrypoint.sh


USER appuser


EXPOSE 8000


# Uses the interpreter already present rather than curl, which the slim image
# does not carry. Drives `depends_on: service_healthy` and any orchestrator
# probing the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"


ENTRYPOINT ["/docker-entrypoint.sh"]