#!/bin/sh
set -eu

mkdir -p /etc/nginx/ssl

if [ ! -f /etc/nginx/ssl/lab.crt ] || [ ! -f /etc/nginx/ssl/lab.key ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout /etc/nginx/ssl/lab.key \
    -out /etc/nginx/ssl/lab.crt \
    -subj "/CN=autopentest-lab.local/O=AutoPenTest Lab/OU=Validation"
fi

exec nginx -g "daemon off;"
