#!/bin/sh
set -e

echo "Running database migrations..."

alembic upgrade head

echo "Checking database revision..."

CURRENT_REVISION=$(alembic current | grep -o '[a-zA-Z0-9_]\{10,\}' | head -1)

HEAD_REVISION=$(alembic heads | grep -o '[a-zA-Z0-9_]\{10,\}' | head -1)


if [ "$CURRENT_REVISION" != "$HEAD_REVISION" ]; then
    echo "Database migration mismatch!"
    echo "Current: $CURRENT_REVISION"
    echo "Expected: $HEAD_REVISION"
    exit 1
fi


echo "Database is up to date."

echo "Starting TechPulse API..."

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --proxy-headers