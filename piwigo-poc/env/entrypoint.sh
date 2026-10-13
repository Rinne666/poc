#!/bin/sh
# piwigo-poc entrypoint — make Piwigo-writable dirs accessible to www-data,
# then exec Apache.

set -eu

chown -R www-data:www-data /var/www/html/_data /var/www/html/upload /var/www/html/local 2>/dev/null || true
mkdir -p /var/www/html/_data /var/www/html/upload /var/www/html/local
chmod -R u+rwX,g+rwX /var/www/html/_data /var/www/html/upload /var/www/html/local 2>/dev/null || true

exec "$@"
