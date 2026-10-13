#!/usr/bin/env bash
# Drive the install.php wizard to a known webmaster credential.
# After this, the fixture has id=1 webmaster (piwigo-poc-webmaster),
# id=2 guest. The PoCs do not log in as the webmaster, but the row needs
# to exist for the WS layer to operate.

set -euo pipefail

BASE="${BASE:-http://localhost:8089}"
WEB_USER="piwigo-poc-webmaster"
WEB_PASS="piwigo-poc-password"

echo "[install] driving POST $BASE/install.php"
HTTP=$(curl -s -o /tmp/install-response.html -w '%{http_code}' \
  "$BASE/install.php" \
  -d "install=1" \
  -d "prefix=piwigo_" \
  -d "dbhost=db" \
  -d "dbuser=piwigo" \
  -d "dbpasswd=piwigo-poc" \
  -d "dbname=piwigo" \
  -d "dblayer=mysqli" \
  -d "admin_name=$WEB_USER" \
  -d "admin_pass1=$WEB_PASS" \
  -d "admin_pass2=$WEB_PASS" \
  -d "admin_mail=piwigo-poc@example.com" \
  -d "language=en_UK")
echo "[install] HTTP $HTTP"
echo "[install] response saved to /tmp/install-response.html"

# Verify
USERS=$(docker exec piwigo-poc-db mysql --user=piwigo --password=piwigo-poc -N -e \
  "SELECT COUNT(*) FROM piwigo_users;")
echo "[install] piwigo_users count: $USERS (expect 2: $WEB_USER, guest)"
