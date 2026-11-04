#!/usr/bin/env bash
# Platform side of ADR-0010 for one application namespace: a ZITADEL project, a
# PKCE web app for the shell and a machine user (client_credentials, JWT access
# tokens) for non-browser callers. Idempotent: re-running finds what exists.
# The machine user's secret goes into a Secret in the app namespace; nothing is printed.
#   ./idp-client.sh <namespace> [frontend-origin]
set -euo pipefail
NS=${1:?namespace}; ORIGIN=${2:-http://commons-grid-dynamics.$NS.svc}
PAT=$(kubectl -n zitadel get secret iam-admin-pat -o jsonpath='{.data.pat}' | base64 -d)
Z=http://$(kubectl -n zitadel get svc zitadel -o jsonpath='{.spec.clusterIP}'):8080
H=(-sS -H "Host: localhost:8080" -H "Authorization: Bearer $PAT" -H "Content-Type: application/json")
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(\"d$1\"))" 2>/dev/null || true; }

PROJ=$(curl "${H[@]}" -X POST $Z/management/v1/projects/_search -d "{\"queries\":[{\"nameQuery\":{\"name\":\"$NS\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}" | j "['result'][0]['id']")
[ -n "$PROJ" ] || PROJ=$(curl "${H[@]}" -X POST $Z/management/v1/projects -d "{\"name\":\"$NS\",\"projectRoleAssertion\":true}" | j "['id']")

WEB=$(curl "${H[@]}" -X POST $Z/management/v1/projects/$PROJ/apps/_search -d '{"queries":[{"nameQuery":{"name":"shell","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' | j "['result'][0]['oidcConfig']['clientId']")
[ -n "$WEB" ] || WEB=$(curl "${H[@]}" -X POST $Z/management/v1/projects/$PROJ/apps/oidc -d "{\"name\":\"shell\",\"redirectUris\":[\"$ORIGIN/callback\",\"http://localhost:8080/callback\"],\"postLogoutRedirectUris\":[\"$ORIGIN/\"],\"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],\"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\",\"OIDC_GRANT_TYPE_REFRESH_TOKEN\"],\"appType\":\"OIDC_APP_TYPE_WEB\",\"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_NONE\",\"accessTokenType\":\"OIDC_TOKEN_TYPE_JWT\",\"devMode\":true}" | j "['clientId']")

MU=$(curl "${H[@]}" -X POST $Z/management/v1/users/_search -d "{\"queries\":[{\"userNameQuery\":{\"userName\":\"$NS-client\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}" | j "['result'][0]['id']")
[ -n "$MU" ] || MU=$(curl "${H[@]}" -X POST $Z/management/v1/users/machine -d "{\"userName\":\"$NS-client\",\"name\":\"$NS test client\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}" | j "['userId']")
# the secret is only readable at generation time: (re)generate when the namespace holds none
if [ -z "$(kubectl -n "$NS" get secret idp-client -o jsonpath='{.data.client_secret}' 2>/dev/null)" ]; then
  R=$(curl "${H[@]}" -X PUT $Z/management/v1/users/$MU/secret -d '{}')
  CID=$(echo "$R" | j "['clientId']"); CSEC=$(echo "$R" | j "['clientSecret']")
  kubectl -n "$NS" create secret generic idp-client --from-literal=client_id="$CID" --from-literal=client_secret="$CSEC" \
    --from-literal=issuer=http://localhost:8080 --from-literal=token_endpoint="http://zitadel.zitadel.svc:8080/oauth/v2/token" \
    --from-literal=project_id="$PROJ" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fi
echo "project=$PROJ shell_client_id=$WEB machine_user=$MU secret=$NS/idp-client"
