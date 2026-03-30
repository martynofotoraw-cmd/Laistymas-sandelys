#!/bin/bash

mkdir -p backups

gunicorn app:app
