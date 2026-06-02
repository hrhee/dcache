#!/usr/bin/env bash
# configure-keycloak.sh
#
# Sets up the Keycloak realm for the dCache token-exchange end-to-end test.
#
# Run this once after `docker compose up -d` (Keycloak needs to be ready).
#
# What it creates:
#   - Realm "dcache-test"
#   - OIDC Identity Provider "hidah" (backed by HiDAH at localhost:8085)
#   - Client "dcache-client" (confidential, service accounts enabled)
#   - User "testuser" linked to HiDAH identity testuser-001
#   - Token-exchange permission: dcache-client may exchange hidah tokens
#
# Requirements: curl, jq

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8081}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="dcache-test"
HIDAH_HOST_URL="http://host.docker.internal:8085"   # reached from inside Keycloak container
HIDAH_BROWSER_URL="http://localhost:8085"             # reached from browser / token iss

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

get_token() {
  curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=$KC_ADMIN&password=$KC_ADMIN_PASS" \
    | jq -r .access_token
}

kc() {   # kc <method> <path> [body]
  local method="$1" path="$2" body="${3:-}"
  local token
  token=$(get_token)
  if [[ -n "$body" ]]; then
    curl -sf -X "$method" "$KC_URL$path" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -d "$body"
  else
    curl -sf -X "$method" "$KC_URL$path" \
      -H "Authorization: Bearer $token"
  fi
}

kc_get_id() {  # kc_get_id <clients|users|...> <clientId|username>
  local type="$1" key="$2"
  kc GET "/admin/realms/$REALM/$type?$(echo "$type" | grep -q user && echo username || echo clientId)=$key" \
    | jq -r '.[0].id'
}

wait_for_keycloak() {
  echo "Waiting for Keycloak at $KC_URL ..."
  local i=0
  until curl -sf "$KC_URL/health/ready" > /dev/null 2>&1; do
    i=$((i+1))
    if [[ $i -ge 30 ]]; then
      echo "ERROR: Keycloak did not become ready in time." >&2
      exit 1
    fi
    sleep 5
  done
  echo "Keycloak is ready."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

wait_for_keycloak

# 1. Create realm
echo "→ Creating realm '$REALM'..."
kc POST "/admin/realms" \
  '{"realm": "'"$REALM"'", "enabled": true, "displayName": "dCache Test"}' \
  2>/dev/null || echo "  (realm may already exist, continuing)"

# 2. Create HiDAH identity provider
#    Server-side calls (tokenUrl, jwksUrl, userInfoUrl) use host.docker.internal
#    so Keycloak can reach HiDAH from inside the Docker network.
#    authorizationUrl uses localhost because the browser follows this redirect.
#    issuer must match HiDAH's EXTERNAL_ADDRESS (the iss claim in tokens).
echo "→ Creating HiDAH identity provider..."
kc POST "/admin/realms/$REALM/identity-provider/instances" \
  '{
    "alias": "hidah",
    "displayName": "HiDAH (mock Helmholtz ID)",
    "providerId": "oidc",
    "enabled": true,
    "trustEmail": true,
    "firstBrokerLoginFlowAlias": "first broker login",
    "config": {
      "clientId": "test-client",
      "clientSecret": "test-client-secret",
      "authorizationUrl": "'"$HIDAH_BROWSER_URL"'/oauth2/auth",
      "tokenUrl": "'"$HIDAH_HOST_URL"'/oauth2/token",
      "userInfoUrl": "'"$HIDAH_HOST_URL"'/oauth2/userinfo",
      "jwksUrl": "'"$HIDAH_HOST_URL"'/oauth2/jwk",
      "issuer": "'"$HIDAH_BROWSER_URL"'",
      "validateSignature": "true",
      "useJwksUrl": "true",
      "pkceEnabled": "false",
      "defaultScope": "openid email profile"
    }
  }' 2>/dev/null || echo "  (hidah IdP may already exist, continuing)"

# 3. Create dcache-client (confidential, token-exchange capable)
echo "→ Creating 'dcache-client'..."
kc POST "/admin/realms/$REALM/clients" \
  '{
    "clientId": "dcache-client",
    "enabled": true,
    "protocol": "openid-connect",
    "clientAuthenticatorType": "client-secret",
    "secret": "dcache-client-secret",
    "serviceAccountsEnabled": true,
    "directAccessGrantsEnabled": true,
    "publicClient": false
  }' 2>/dev/null || echo "  (dcache-client may already exist, continuing)"

# 4. Create testuser in Keycloak realm
echo "→ Creating user 'testuser'..."
kc POST "/admin/realms/$REALM/users" \
  '{
    "username": "testuser",
    "email": "testuser@helmholtz.example",
    "emailVerified": true,
    "enabled": true,
    "firstName": "Test",
    "lastName": "User"
  }' 2>/dev/null || echo "  (testuser may already exist, continuing)"

TESTUSER_ID=$(kc_get_id "users" "testuser")
echo "  testuser Keycloak ID: $TESTUSER_ID"

# 5. Link testuser to HiDAH identity (sub = testuser-001 from hidah-profiles.json)
echo "→ Linking testuser to HiDAH identity (sub=testuser-001)..."
kc POST "/admin/realms/$REALM/users/$TESTUSER_ID/federated-identity/hidah" \
  '{
    "identityProvider": "hidah",
    "userId": "testuser-001",
    "userName": "testuser"
  }' 2>/dev/null || echo "  (federated identity may already exist, continuing)"

# 6. Enable token-exchange permissions on the HiDAH IdP
echo "→ Enabling token-exchange permissions on HiDAH IdP..."
IDP_PERMS=$(kc PUT "/admin/realms/$REALM/identity-provider/instances/hidah/management/permissions" \
  '{"enabled": true}')
echo "  IdP permissions response: $IDP_PERMS"

TOKEN_EXCHANGE_PERM_ID=$(echo "$IDP_PERMS" | jq -r '.scopePermissions."token-exchange"')
echo "  Token-exchange permission ID: $TOKEN_EXCHANGE_PERM_ID"

# 7. Get realm-management client's internal ID (it owns the authz resource server)
REALM_MGMT_ID=$(kc GET "/admin/realms/$REALM/clients?clientId=realm-management" | jq -r '.[0].id')
echo "  realm-management ID: $REALM_MGMT_ID"

# 8. Get dcache-client's internal ID
DCACHE_CLIENT_ID=$(kc GET "/admin/realms/$REALM/clients?clientId=dcache-client" | jq -r '.[0].id')
echo "  dcache-client ID: $DCACHE_CLIENT_ID"

# 9. Create a client policy that grants dcache-client the exchange right
echo "→ Creating token-exchange policy for dcache-client..."
POLICY=$(kc POST "/admin/realms/$REALM/clients/$REALM_MGMT_ID/authz/resource-server/policy/client" \
  '{
    "name": "allow-dcache-client",
    "type": "client",
    "logic": "POSITIVE",
    "decisionStrategy": "UNANIMOUS",
    "clients": ["'"$DCACHE_CLIENT_ID"'"]
  }') 2>/dev/null || true
POLICY_ID=$(echo "$POLICY" | jq -r '.id // empty')

if [[ -z "$POLICY_ID" ]]; then
  # Policy may already exist — fetch its ID
  POLICY_ID=$(kc GET "/admin/realms/$REALM/clients/$REALM_MGMT_ID/authz/resource-server/policy?name=allow-dcache-client" \
    | jq -r '.[0].id')
fi
echo "  Policy ID: $POLICY_ID"

# 10. Attach the policy to the token-exchange scope permission
echo "→ Attaching policy to token-exchange permission..."
kc PUT "/admin/realms/$REALM/clients/$REALM_MGMT_ID/authz/resource-server/permission/scope/$TOKEN_EXCHANGE_PERM_ID" \
  '{
    "id": "'"$TOKEN_EXCHANGE_PERM_ID"'",
    "name": "token-exchange.permission.idp.hidah",
    "type": "scope",
    "logic": "POSITIVE",
    "decisionStrategy": "UNANIMOUS",
    "policies": ["'"$POLICY_ID"'"]
  }' > /dev/null

echo ""
echo "✓ Keycloak configured successfully."
echo ""
echo "  Realm:        $REALM"
echo "  IdP alias:    hidah  (mock Helmholtz ID at $HIDAH_BROWSER_URL)"
echo "  Client:       dcache-client  (secret: dcache-client-secret)"
echo "  Test user:    testuser  (linked to HiDAH sub=testuser-001)"
echo ""
echo "Next steps:"
echo "  1. python3 get-token.py        # get a HiDAH access token"
echo "  2. export TOKEN=<token>"
echo "  3. curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:2880/"
