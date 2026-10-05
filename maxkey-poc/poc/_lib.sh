#!/usr/bin/env bash
# =============================================================================
# _lib.sh — shared helpers and SAFETY GUARD for the MaxKey PoC scripts.
#
# ############################################################################
# #  NOT EXECUTED BY THE AUDIT.                                          #
# #  These scripts were WRITTEN but NEVER RUN. The audit environment had #
# #  no network access and no runnable MaxKey instance. Every "EXPECTED   #
# #  IF VULNERABLE" block below is a prediction, not an observation.      #
# ############################################################################
# =============================================================================

# ----------------------------------------------------------------------------
# Safety guard. Two independent opt-ins are required so that a fat-fingered
# run against a production or shared instance is not possible by accident.
# ----------------------------------------------------------------------------
poc_guard() {
  local script_name="$1"

  cat <<'BANNER'
==============================================================================
  MaxKey PoC script — UNAUTHORISED USE PROHIBITED
==============================================================================
  This script SENDS AUTHENTICATION ATTEMPTS to a live MaxKey instance.
  It must only ever be pointed at a DISPOSABLE test instance that you
  own and have explicitly authorised.
  It will attempt real logins, which can lock accounts and write history.
==============================================================================
BANNER

  if [ "${POC_I_HAVE_AUTHORIZATION:-}" != "1" ]; then
    echo
    echo "REFUSING TO RUN: POC_I_HAVE_AUTHORIZATION is not set to 1."
    echo
    echo "If you own a disposable MaxKey instance and are authorised to test it, re-run with:"
    echo
    echo "    POC_I_HAVE_AUTHORIZATION=1 POC_TARGET_HOST=http://127.0.0.1:8080 ./$script_name"
    echo
    echo "This refusal is deliberate. Do not work around it on a real system."
    exit 2
  fi

  local host="${POC_TARGET_HOST:-}"
  if [ -z "$host" ]; then
    echo
    echo "REFUSING TO RUN: POC_TARGET_HOST is not set."
    echo "Set it to the BASE URL of your disposable instance, e.g. http://127.0.0.1:8080"
    exit 2
  fi

  # Second opt-in: anything that does not look like a loopback / private-range
  # host requires an extra, deliberate confirmation. This is the guard that
  # stops a copy-pasted POC_TARGET_HOST from hitting a real deployment.
  if ! poc_is_private_host "$host"; then
    if [ "${POC_I_CONFIRM_DISPOSABLE:-}" != "1" ]; then
      echo
      echo "REFUSING TO RUN: '$host' is not a loopback or private-range address."
      echo "MaxKey audit PoCs must never be aimed at a routable host."
      echo
      echo "If '$host' really is your own disposable instance, re-run with BOTH:"
      echo
      echo "    POC_I_HAVE_AUTHORIZATION=1 POC_I_CONFIRM_DISPOSABLE=1 POC_TARGET_HOST=$host ./$script_name"
      echo
      exit 2
    fi
  fi

  cat <<BANNER2
------------------------------------------------------------------------------
  Running against : $host
  Script          : $script_name
  Timestamp       : $(date -u '+%Y-%m-%dT%H:%M:%SZ')
------------------------------------------------------------------------------
BANNER2
}

poc_is_private_host() {
  local h="$1"
  # strip scheme
  h="${h#*://}"
  h="${h%%/*}"
  h="${h%%:*}"           # strip port
  case "$h" in
    localhost|127.*|0.0.0.0|::1) return 0 ;;
    10.*)                      return 0 ;;
    192.168.*)                 return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    host.docker.internal)     return 0 ;;
    *.localhost)               return 0 ;;
  esac
  return 1
}

# ----------------------------------------------------------------------------
# Verdict helpers. THREE separate counters, because a run that reached the
# application and a run that never did must not be summarised the same way.
# ----------------------------------------------------------------------------
POC_N_VULNERABLE=0
POC_N_FIXED=0
POC_N_INCONCLUSIVE=0

poc_vulnerable() {
  POC_N_VULNERABLE=$((POC_N_VULNERABLE + 1))
  echo "  [VULNERABLE]   $*"
}

poc_fixed() {
  POC_N_FIXED=$((POC_N_FIXED + 1))
  echo "  [FIXED]        $*"
}

poc_inconclusive() {
  POC_N_INCONCLUSIVE=$((POC_N_INCONCLUSIVE + 1))
  echo "  [INCONCLUSIVE] $*"
}

poc_info() { echo "  [INFO]         $*"; }
poc_warn() { echo "  [WARN]         $*"; }

poc_summary() {
  local name="$1"
  echo
  echo "=============================================================================="
  echo " SUMMARY for $name"
  echo "   matched the VULNERABLE hypothesis : $POC_N_VULNERABLE"
  echo "   matched the FIXED hypothesis      : $POC_N_FIXED"
  echo "   inconclusive                       : $POC_N_INCONCLUSIVE"
  echo
  if [ "$((POC_N_VULNERABLE + POC_N_FIXED))" -eq 0 ]; then
    echo "   INTERPRETATION: NO VERDICT WAS REACHED."
    echo "   Nothing was proven either way. Fix the test setup before drawing any"
    echo "   conclusion. Do NOT report this run as evidence of a fix."
  elif [ "$POC_N_INCONCLUSIVE" -gt 0 ]; then
    echo "   INTERPRETATION: MIXED / PARTIAL result. Some checks were inconclusive."
    echo "   Resolve every [INCONCLUSIVE] line above before drawing a conclusion."
  elif [ "$POC_N_FIXED" -gt 0 ]; then
    echo "   INTERPRETATION: the FIXED hypothesis held. This instance did not exhibit"
    echo "   the predicted behaviour. A refusal can also mean the instance was already"
    echo "   remediated or misconfigured; confirm which before reporting the finding"
    echo "   as not-reproducible."
  else
    echo "   INTERPRETATION: every assertion matched the VULNERABLE hypothesis."
  fi
  echo "=============================================================================="
}

# ----------------------------------------------------------------------------
# HTTP helper.
#   poc_curl METHOD URL [curl args...]
#   Prints the HTTP status code, so it can be used as  CODE=$(poc_curl ...).
#
#   IMPORTANT: because callers invoke this inside a command substitution, it runs
#   in a SUBSHELL and any variable it assigns is lost in the parent. So the body,
#   the stderr capture and the reachability flag are all written to DETERMINISTIC
#   per-PID files, which survive the subshell. Read them with poc_body, poc_err
#   and poc_reached.
#
#   The reachability flag matters: a "000" means the request never completed, so
#   NOTHING was learned about the application. It must never be scored as FIXED.
# ----------------------------------------------------------------------------
POC_TMP_PREFIX="${TMPDIR:-/tmp}/maxkey-poc.$$"
POC_BODY_FILE="${POC_TMP_PREFIX}.body"
POC_ERR_FILE="${POC_TMP_PREFIX}.err"
POC_STATUS_FILE="${POC_TMP_PREFIX}.status"

poc_curl() {
  local method="$1"; shift
  local url="$1"; shift

  local code rc
  code=$(curl -sS --max-time 20 -o "$POC_BODY_FILE" -w '%{http_code}' \
              -X "$method" "$url" "$@" 2>"$POC_ERR_FILE")
  rc=$?

  if [ "$rc" -ne 0 ] || [ -z "$code" ] || [ "$code" = "000" ]; then
    printf 'no' > "$POC_STATUS_FILE"
    printf '000'
  else
    printf 'yes' > "$POC_STATUS_FILE"
    printf '%s' "$code"
  fi
}

poc_reached() {
  [ "$(cat "$POC_STATUS_FILE" 2>/dev/null)" = "yes" ] && echo yes || echo no
}

poc_body() { cat "$POC_BODY_FILE" 2>/dev/null; }
poc_err()  { cat "$POC_ERR_FILE"  2>/dev/null; }

poc_cleanup() {
  rm -f "$POC_BODY_FILE" "$POC_ERR_FILE" "$POC_STATUS_FILE"
  return 0
}

# Abort a check chain when the target is simply not reachable. Without this, a
# refused TCP connection silently becomes a "FIXED" verdict, which is the single
# most misleading failure mode these scripts could have.
poc_require_reachable() {
  local what="$1"
  if [ "$(poc_reached)" != "yes" ]; then
    echo
    echo "  [INCONCLUSIVE] the request to $what never completed."
    echo "  curl said: $(poc_err | head -2)"
    echo "  This is a connectivity problem, NOT a result. The application was never"
    echo "  asked, so nothing has been proven in either direction."
    POC_N_INCONCLUSIVE=$((POC_N_INCONCLUSIVE + 1))
    poc_summary "${2:-this run}"
    exit 4
  fi
}

require() {
  # usage: require VAR_NAME "explanation"
  local v="${!1:-}"
  if [ -z "$v" ]; then
    echo
    echo "MISSING REQUIRED ENVIRONMENT VARIABLE: $1"
    echo "  $2"
    exit 2
  fi
}
