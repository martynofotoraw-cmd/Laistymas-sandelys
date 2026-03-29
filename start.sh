#!/usr/bin/env bash
set -e

mkdir -p backups

exec gunicorn --bind 0.0.0.0:${PORT:-10000} app:app
