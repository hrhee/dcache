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
#   - Token-exchange permission via KC 26 client attributes (oidc.token.exchange.grant.allowed)
#
# Requirements: curl, jq

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8081}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="dcache-test"
HIDAH_HOST_URL="http://hidah:8080"                    # reached from inside Keycloak container via compose network
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
  until curl -sf "$KC_URL/realms/master" > /dev/null 2>&1; do
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
#    Server-side calls (tokenUrl, jwksUrl, userInfoUrl) use the compose service name (hidah:8080)
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

# 2b. Enable JWT Authorization Grant on the HiDAH identity provider
echo "→ Enabling JWT Authorization Grant on HiDAH IdP..."
HIDAH_IDP=$(kc GET "/admin/realms/$REALM/identity-provider/instances/hidah")
UPDATED_IDP=$(echo "$HIDAH_IDP" | jq '.config.jwtAuthorizationGrantEnabled = "true" | .config.jwtAuthorizationGrantAssertionReuseAllowed = "true"')
kc PUT "/admin/realms/$REALM/identity-provider/instances/hidah" "$UPDATED_IDP" \
  2>/dev/null || echo "  (could not update hidah IdP, continuing)"

# 3. Create dcache-client (confidential, JWT authorization grant capable)
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
    "publicClient": false,
    "attributes": {
      "oauth2.jwt.authorization.grant.enabled": "true",
      "oauth2.jwt.authorization.grant.idp": "hidah",
      "oauth2.jwt.authorization.grant.audience": "[{\"key\":\"hidah\",\"value\":\"test-client\"}]"
    }
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

echo ""
echo "✓ Keycloak configured successfully."
echo ""
echo "  Realm:        $REALM"
echo "  IdP alias:    hidah  (mock Helmholtz ID at $HIDAH_BROWSER_URL)"
echo "  Client:       dcache-client  (secret: dcache-client-secret)"
echo "  Test user:    testuser  (linked to HiDAH sub=testuser-001)"
echo ""
echo "  JWT Authorization Grant is enabled via KC 26.6 attributes:"
echo "    oauth2.jwt.authorization.grant.enabled = true"
echo "    oauth2.jwt.authorization.grant.idp = hidah"
echo "    hidah IdP: jwtAuthorizationGrantEnabled = true"
echo ""
echo "Next steps:"
echo "  1. TOKEN=\$(python3 get-token.py)   # get a HiDAH access token"
echo "  2. curl -k -H \"Authorization: Bearer \$TOKEN\" https://localhost:2881/"
