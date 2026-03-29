#!/usr/bin/env bash
set -e

mkdir -p /var/data/backups

if [ ! -f "/var/data/database.db" ] && [ -f "./database.db" ]; then
  echo "Kopijuoju pradine database.db i persistent disk..."
  cp ./database.db /var/data/database.db
fi

chmod 664 /var/data/database.db || true

exec gunicorn --bind 0.0.0.0:${PORT:-10000} app:app