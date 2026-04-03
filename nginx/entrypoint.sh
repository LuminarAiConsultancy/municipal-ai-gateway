#!/bin/sh
set -e

# Generate a self-signed TLS certificate if none is provided.
# For production, replace these files with a certificate from
# Let's Encrypt or your organization's certificate authority.
if [ ! -f /etc/nginx/ssl/cert.pem ]; then
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem \
        -subj "/CN=localhost/O=Municipal AI Gateway" \
        2>/dev/null
    echo "Generated self-signed TLS certificate for local testing."
    echo "Replace with a real certificate before production use."
fi

exec nginx -g "daemon off;"
