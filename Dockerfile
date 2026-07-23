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


# Create non-root user
RUN addgroup --system app && \
    adduser --system --ingroup app appuser && \
    chown -R appuser:app /app /docker-entrypoint.sh


USER appuser


EXPOSE 8000


ENTRYPOINT ["/docker-entrypoint.sh"]