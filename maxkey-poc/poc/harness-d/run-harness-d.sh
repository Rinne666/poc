#!/usr/bin/env bash
# =============================================================================
#  run-harness-d.sh — reproduce the synchroniser-assigned local password.
#
#  ###########################################################################
#  #  THIS SCRIPT *WAS EXECUTED BY THE AUDIT*. Its output is captured under   #
#  #  ../harness-results/harness-D-sync-default-password.txt. See ../RESULTS.md #
#  #  for what it does and does not prove.                                  #
#  ###########################################################################
#
#  WHAT THIS IS
#    Starts a local MySQL and a local OpenLDAP container, loads MaxKey's own
#    schema from the audited tree, compiles the project's real synchroniser and
#    login classes, and runs the probe.
#
#    It contacts NO third-party system and needs NO MaxKey deployment.
#
#  IMPORTANT CONTEXT
#    The MySQL and OpenLDAP instances are LOCAL containers created here. The
#    DB is seeded with MaxKey's own maxkey.sql, and the LDAP directory holds
#    two synthetic employees. Nothing pre-existing is touched.
#
#  PREREQUISITES
#    * A JDK 17+ (set JAVA_HOME, or a JDK on PATH)
#    * Docker running
#    * Network access to Maven Central on first run
#
#  USAGE
#    ./run-harness-d.sh
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-/opt/homebrew/Cellar/openjdk/26.0.2.1/libexec/openjdk.jdk/Contents/Home}"
JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"

if [ ! -x "$JAVAC" ]; then
  echo "ERROR: no javac at $JAVAC"
  echo "Set JAVA_HOME to a JDK 17+ installation and re-run."
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required (two local containers are started by this script)."
  exit 2
fi

MAXKEY_REPO="${MAXKEY_REPO:-/Users/rinne/Desktop/github/MaxKey}"
BASELINE="3e5662b1a91291c0d85de826544119c86e77d8e6"
SCHEMA="$MAXKEY_REPO/deployment/docker/docker-mysql/docker-entrypoint-initdb.d/latest/maxkey.sql"
MYSQL_PORT="${MYSQL_PORT:-13306}"
LDAP_PORT="${LDAP_PORT:-1389}"
DB_PW="maxkey123"
RESULT="../harness-results/harness-D-sync-default-password.txt"

if [ ! -f "$SCHEMA" ]; then
  echo "ERROR: MaxKey schema not found at $SCHEMA"
  echo "Set MAXKEY_REPO to a checkout of dromara/MaxKey."
  exit 2
fi

LIB=lib
CLASSES=classes
HARNESS=classes-h
mkdir -p "$LIB" "$CLASSES" "$HARNESS" ../harness-results

# ---------------------------------------------------------------- dependencies
echo "### Fetching dependencies (skipped if already present)"
fetch() {
  local url="https://repo1.maven.org/maven2/$1"
  local f="$LIB/$(basename "$1")"
  [ -f "$f" ] || curl -sS --max-time 120 -f -o "$f" "$url" 2>/dev/null || rm -f "./$f"
}
fetch org/dromara/mybatis-jpa-extra/mybatis-jpa-extra/3.4.6/mybatis-jpa-extra-3.4.6.jar
fetch org/dromara/mybatis-jpa-extra/mybatis-jpa-extra-spring/3.4.6/mybatis-jpa-extra-spring-3.4.6.jar
fetch org/springframework/spring-core/7.0.8/spring-core-7.0.8.jar
fetch org/springframework/spring-beans/7.0.8/spring-beans-7.0.8.jar
fetch org/springframework/spring-context/7.0.8/spring-context-7.0.8.jar
fetch org/springframework/spring-jdbc/7.0.8/spring-jdbc-7.0.8.jar
fetch org/springframework/spring-tx/7.0.8/spring-tx-7.0.8.jar
fetch org/springframework/spring-aop/7.0.8/spring-aop-7.0.8.jar
fetch org/springframework/spring-expression/7.0.8/spring-expression-7.0.8.jar
fetch org/springframework/spring-web/7.0.8/spring-web-7.0.8.jar
fetch org/springframework/spring-webmvc/7.0.8/spring-webmvc-7.0.8.jar
fetch org/springframework/spring-orm/7.0.8/spring-orm-7.0.8.jar
fetch org/springframework/data/spring-data-jpa/4.0.0/spring-data-jpa-4.0.0.jar
fetch org/springframework/data/spring-data-commons/4.0.0/spring-data-commons-4.0.0.jar
fetch org/springframework/security/spring-security-core/7.1.0-RC1/spring-security-core-7.1.0-RC1.jar
fetch org/springframework/security/spring-security-crypto/7.1.0-RC1/spring-security-crypto-7.1.0-RC1.jar
fetch org/springframework/security/spring-security-web/7.1.0-RC1/spring-security-web-7.1.0-RC1.jar
fetch org/springframework/security/spring-security-ldap/7.1.0-RC1/spring-security-ldap-7.1.0-RC1.jar
fetch jakarta/persistence/jakarta.persistence-api/3.2.0/jakarta.persistence-api-3.2.0.jar
fetch jakarta/annotation/jakarta.annotation-api/3.0.0/jakarta.annotation-api-3.0.0.jar
fetch jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar
fetch jakarta/validation/jakarta.validation-api/3.1.0/jakarta.validation-api-3.1.0.jar
fetch jakarta/transaction/jakarta.transaction-api/2.0.1/jakarta.transaction-api-2.0.1.jar
fetch jakarta/el/jakarta.el-api/5.0.1/jakarta.el-api-5.0.1.jar
fetch org/glassfish/expressly/expressly/5.0.0/expressly-5.0.0.jar
fetch org/hibernate/validator/hibernate-validator/9.0.1.Final/hibernate-validator-9.0.1.Final.jar
fetch org/mybatis/mybatis/3.5.19/mybatis-3.5.19.jar
fetch org/mybatis/mybatis-spring/3.0.4/mybatis-spring-3.0.4.jar
fetch org/passay/passay/1.6.2/passay-1.6.2.jar
fetch joda-time/joda-time/2.14.2/joda-time-2.14.2.jar
fetch org/apache/commons/commons-lang3/3.20.0/commons-lang3-3.20.0.jar
fetch org/apache/commons/commons-collections4/4.5.0/commons-collections4-4.5.0.jar
fetch commons-logging/commons-logging/1.3.6/commons-logging-1.3.6.jar
fetch commons-codec/commons-codec/1.21.0/commons-codec-1.21.0.jar
fetch org/slf4j/slf4j-api/2.0.0/slf4j-api-2.0.0.jar
fetch org/slf4j/slf4j-simple/2.0.0/slf4j-simple-2.0.0.jar
fetch com/fasterxml/jackson/core/jackson-annotations/2.22/jackson-annotations-2.22.jar
fetch com/fasterxml/jackson/core/jackson-core/2.21.4/jackson-core-2.21.4.jar
fetch com/fasterxml/jackson/core/jackson-databind/2.21.4/jackson-databind-2.21.4.jar
fetch com/mysql/mysql-connector-j/9.7.0/mysql-connector-j-9.7.0.jar
fetch org/bouncycastle/bcprov-jdk18on/1.83/bcprov-jdk18on-1.83.jar
fetch com/github/ben-manes/caffeine/caffeine/3.2.0/caffeine-3.2.0.jar
CP="$(ls "$LIB"/*.jar | tr '\n' ':')"

# ------------------------------------------------------------------- containers
echo
echo "### Starting local containers (MySQL + OpenLDAP)"
docker rm -f v3-mysql v3-ldap >/dev/null 2>&1

docker run -d --name v3-mysql -e MYSQL_ROOT_PASSWORD="$DB_PW" -e MYSQL_DATABASE=maxkey \
  -p "$MYSQL_PORT":3306 mysql:8.0 \
  --character-set-server=utf8mb3 --collation-server=utf8mb3_general_ci \
  --innodb-default-row-format=DYNAMIC --innodb-strict-mode=OFF --sql-mode='' >/dev/null

docker run -d --name v3-ldap -p "$LDAP_PORT":389 \
  -e LDAP_ORGANISATION="MaxKey" -e LDAP_DOMAIN="maxkey.io" -e LDAP_ADMIN_PASSWORD=admin \
  osixia/openldap:1.5.0 >/dev/null

cleanup() {
  echo
  echo "### Removing the local containers"
  docker rm -f v3-mysql v3-ldap >/dev/null 2>&1
}
trap cleanup EXIT

for i in $(seq 1 60); do
  docker exec v3-mysql mysqladmin ping -uroot -p"$DB_PW" --silent >/dev/null 2>&1 && break
  sleep 2
done
sleep 10

echo "### Loading MaxKey's own schema from $MAXKEY_REPO"
docker exec v3-mysql mysql -uroot -p"$DB_PW" \
  -e "drop database if exists maxkey; create database maxkey character set utf8mb3 collate utf8mb3_general_ci;" 2>/dev/null
docker exec -i v3-mysql mysql -uroot -p"$DB_PW" maxkey < "$SCHEMA" 2>&1 | grep -vi warning | head -5

TABLES=$(docker exec v3-mysql mysql -uroot -p"$DB_PW" maxkey -N \
  -e "select count(*) from information_schema.tables where table_schema='maxkey';" 2>/dev/null)
echo "    tables created: $TABLES (expected 44)"

echo "### Loading synthetic employees into the local LDAP directory"
docker cp orgs.ldif v3-ldap:/tmp/orgs.ldif >/dev/null
docker exec v3-ldap ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=maxkey,dc=io" -w admin -f /tmp/orgs.ldif 2>&1 | grep -c "adding new entry" \
  | sed 's/^/    entries added: /'

# --------------------------------------------------------------------- compile
echo
echo "### Compiling MaxKey's own classes from $MAXKEY_REPO @ ${BASELINE:0:7}"
SP="$MAXKEY_REPO/maxkey-entity/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-commons/maxkey-core/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-commons/maxkey-common/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-commons/maxkey-crypto/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-commons/maxkey-ldap/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-commons/maxkey-cache/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-starter/maxkey-starter-ip2location/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-persistence/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-authentications/maxkey-authentication-core/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-authentications/maxkey-authentication-provider/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-synchronizers/maxkey-synchronizer/src/main/java"
SP="$SP:$MAXKEY_REPO/maxkey-synchronizers/maxkey-synchronizer-ldap/src/main/java"

# javac follows -sourcepath, so these entry points pull in their own deps.
# NOTE: the exit status of javac is checked directly. Piping into grep would
# invert the test, because grep exits 1 when it matches nothing -- i.e. on a
# perfectly successful compile.
echo "### Compiling the product's own classes"
if ! "$JAVAC" -nowarn -proc:none -cp "$CP" -sourcepath "$SP" -d "$CLASSES" \
      "$MAXKEY_REPO/maxkey-entity/src/main/java/org/dromara/maxkey/entity/idm/UserInfo.java" \
      "$MAXKEY_REPO/maxkey-commons/maxkey-crypto/src/main/java/org/dromara/maxkey/crypto/password/NoOpPasswordEncoder.java" \
      "$MAXKEY_REPO/maxkey-persistence/src/main/java/org/dromara/maxkey/persistence/service/impl/UserInfoServiceImpl.java" \
      "$MAXKEY_REPO/maxkey-persistence/src/main/java/org/dromara/maxkey/persistence/service/impl/CnfPasswordPolicyServiceImpl.java" \
      "$MAXKEY_REPO/maxkey-persistence/src/main/java/org/dromara/maxkey/persistence/service/impl/LoginServiceImpl.java" \
      "$MAXKEY_REPO/maxkey-authentications/maxkey-authentication-provider/src/main/java/org/dromara/maxkey/authn/realm/jdbc/JdbcAuthenticationRealm.java" \
      "$MAXKEY_REPO/maxkey-synchronizers/maxkey-synchronizer-ldap/src/main/java/org/dromara/maxkey/synchronizer/ldap/LdapUsersService.java" \
      > "$CLASSES/javac.log" 2>&1; then
  echo "COMPILE FAILED for the product classes:"
  head -20 "$CLASSES/javac.log"
  exit 1
fi
echo "    product classes compiled: $(find "$CLASSES" -name '*.class' | wc -l | tr -d ' ')"

if ! "$JAVAC" -nowarn -proc:none -cp "$CP:$CLASSES" -d "$HARNESS" \
      v3/SyncDefaultPasswordProbe.java > "$HARNESS/javac.log" 2>&1; then
  echo "COMPILE FAILED for the probe:"
  head -20 "$HARNESS/javac.log"
  exit 1
fi
echo "    probe compiled OK"

# ------------------------------------------------------------------------- run
run_probe() {
  "$JAVA" -cp "$CP:$CLASSES:$HARNESS" \
    -Dorg.slf4j.simpleLogger.defaultLogLevel=warn \
    -Dv3.jdbc="jdbc:mysql://127.0.0.1:$MYSQL_PORT/maxkey?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC" \
    -Dv3.ldap.url="ldap://127.0.0.1:$LDAP_PORT" \
    "$@"
}

# a real bcrypt hash of an unrelated, user-chosen password
OTHERPW='{bcrypt}$2a$10$3MVcPfNH9OW8dxdIjpx83OtnPJUOlP8uU5RjQhgpMCyIC6DK7gz0y'

{
  echo "###########################################################################"
  echo "# HARNESS D -- synchroniser-assigned local password (finding: sync default password)"
  echo "###########################################################################"
  echo "# generated by the audit. Real MaxKey classes, real MySQL, real OpenLDAP."
  echo "# see harness-d/README.md for exactly what was and was not replaced."
  echo "#"
  echo "# PART 1 syncs a NEW account.  PART 2 first overwrites the stored password"
  echo "# with a value the attacker cannot derive, then re-syncs the SAME account."
  echo
  echo "==================== PART 1: fresh sync of a NEW account ===================="
  run_probe v3.SyncDefaultPasswordProbe
  echo
  echo "==================== PART 2: re-sync of an EXISTING account ================="
  echo "# the account's password is first replaced with an unrelated bcrypt hash,"
  echo "# simulating a user who has already changed their password."
  echo "-- setting zhangsan's password to an unrelated hash --"
  docker exec v3-mysql mysql -uroot -p"$DB_PW" maxkey \
    -e "update mxk_userinfo set password='$OTHERPW' where username='zhangsan';" 2>&1 | grep -v Warning
  echo "-- re-syncing --"
  run_probe -Dv3.keep=1 v3.SyncDefaultPasswordProbe
} | tee "$RESULT"

echo
echo "=============================================================================="
echo " Output saved to $RESULT"
echo " Note: MySQL and OpenLDAP here are LOCAL containers started by this script."
echo " No production or third-party MaxKey deployment was contacted."
echo "=============================================================================="
