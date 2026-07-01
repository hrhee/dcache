#!/usr/bin/env bash
# configure-keycloak-preexchange.sh
#
# Layers the RFC 8693 pre-exchange test scenario on top of an already-configured
# realm (run ./configure-keycloak.sh first). Requires the pre-exchange overlay
# stack to be up:
#   podman compose -f docker-compose.yml -f docker-compose.pre-exchange.yml \
#     up -d hidah-shared mock-preexchange
#
# What it adds:
#   - OIDC Identity Provider "preexchange-mock" (backed by mock-preexchange,
#     which itself verifies tokens from the second HiDAH instance, hidah-shared,
#     before re-minting them) — this is what Keycloak actually trusts when
#     validating the re-minted assertion sent via RFC 7523
#   - JWT Authorization Grant flags on that IdP
#   - A dedicated client "dcache-client-preexchange", separate from
#     dcache-client, wired to the preexchange-mock IdP. Keycloak 26.6.1's
#     oauth2.jwt.authorization.grant.idp client attribute is single-valued —
#     a client can only be wired to one IdP at a time — so this scenario
#     cannot share dcache-client without repeatedly flipping that attribute.
#     dcache-client itself is never touched.
#   - A federated identity link from the existing "testuser" to the
#     preexchange-mock IdP (same underlying user, second IdP-link binding)
#
# Requirements: curl, jq

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8081}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="dcache-test"
MOCK_HOST_URL="http://mock-preexchange:8080"   # reached from inside Keycloak container via compose network

# ---------------------------------------------------------------------------
# Helpers (duplicated from configure-keycloak.sh rather than shared, so this
# script stays standalone and trivially deletable)
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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "→ Checking realm '$REALM' already exists..."
if ! kc GET "/admin/realms/$REALM" > /dev/null 2>&1; then
  echo "ERROR: realm '$REALM' not found. Run ./configure-keycloak.sh first." >&2
  exit 1
fi

# 1. Create the preexchange-mock identity provider.
#    clientId/clientSecret are required fields by KC's API but functionally
#    inert here — this IdP link is only ever used for JWT Authorization Grant
#    signature trust (jwksUrl/issuer), never for a browser login flow.
echo "→ Creating 'preexchange-mock' identity provider..."
kc POST "/admin/realms/$REALM/identity-provider/instances" \
  '{
    "alias": "preexchange-mock",
    "displayName": "Mock RFC 8693 pre-exchange endpoint",
    "providerId": "oidc",
    "enabled": true,
    "trustEmail": true,
    "firstBrokerLoginFlowAlias": "first broker login",
    "config": {
      "clientId": "unused",
      "clientSecret": "unused",
      "authorizationUrl": "'"$MOCK_HOST_URL"'/oauth2/token",
      "tokenUrl": "'"$MOCK_HOST_URL"'/oauth2/token",
      "jwksUrl": "'"$MOCK_HOST_URL"'/jwks",
      "issuer": "'"$MOCK_HOST_URL"'",
      "validateSignature": "true",
      "useJwksUrl": "true",
      "pkceEnabled": "false"
    }
  }' 2>/dev/null || echo "  (preexchange-mock IdP may already exist, continuing)"

# 2. Enable JWT Authorization Grant on the preexchange-mock identity provider.
echo "→ Enabling JWT Authorization Grant on preexchange-mock IdP..."
MOCK_IDP=$(kc GET "/admin/realms/$REALM/identity-provider/instances/preexchange-mock")
UPDATED_IDP=$(echo "$MOCK_IDP" | jq '
  .config.jwtAuthorizationGrantEnabled = "true"
  | .config.jwtAuthorizationGrantAssertionReuseAllowed = "true"
  | .config.jwtAuthorizationGrantAllowClientIdAsAudience = "true"
')
kc PUT "/admin/realms/$REALM/identity-provider/instances/preexchange-mock" "$UPDATED_IDP" \
  2>/dev/null || echo "  (could not update preexchange-mock IdP, continuing)"

# 3. Create a SEPARATE client for this scenario, rather than adding a second
#    entry to dcache-client's audience map. Keycloak 26.6.1's
#    oauth2.jwt.authorization.grant.idp attribute is single-valued -- a client
#    can only have JWT Authorization Grant enabled for ONE identity provider at
#    a time (confirmed experimentally: setting it to "hidah,preexchange-mock"
#    or a JSON array is rejected with "Identity Provider is not allowed for the
#    client"). Reusing dcache-client here would mean flipping its .idp
#    attribute away from "hidah" and back again to toggle between the two
#    scenarios, which risks breaking the primary flow. A dedicated client
#    keeps this fully isolated and additive: dcache-client is never touched.
echo "→ Creating 'dcache-client-preexchange' client..."
kc POST "/admin/realms/$REALM/clients" \
  '{
    "clientId": "dcache-client-preexchange",
    "enabled": true,
    "protocol": "openid-connect",
    "clientAuthenticatorType": "client-secret",
    "secret": "dcache-client-preexchange-secret",
    "serviceAccountsEnabled": true,
    "directAccessGrantsEnabled": true,
    "publicClient": false,
    "attributes": {
      "oauth2.jwt.authorization.grant.enabled": "true",
      "oauth2.jwt.authorization.grant.idp": "preexchange-mock",
      "oauth2.jwt.authorization.grant.audience": "[{\"key\":\"preexchange-mock\",\"value\":\"preexchange-mock\"}]"
    }
  }' 2>/dev/null || echo "  (dcache-client-preexchange may already exist, continuing)"

# 4. Link the existing testuser to the preexchange-mock IdP too (same
#    underlying HiDAH identity, sub=testuser-001, second IdP-link binding).
echo "→ Linking testuser to preexchange-mock identity (sub=testuser-001)..."
TESTUSER_ID=$(kc_get_id "users" "testuser")
kc POST "/admin/realms/$REALM/users/$TESTUSER_ID/federated-identity/preexchange-mock" \
  '{
    "identityProvider": "preexchange-mock",
    "userId": "testuser-001",
    "userName": "testuser"
  }' 2>/dev/null || echo "  (federated identity may already exist, continuing)"

echo ""
echo "✓ Pre-exchange scenario configured successfully."
echo ""
echo "  IdP alias:    preexchange-mock  (mock RFC 8693 endpoint at http://localhost:8082)"
echo "  Client:       dcache-client-preexchange  (secret: dcache-client-preexchange-secret)"
echo ""
echo "Next steps:"
echo "  1. TOKEN=\$(python3 get-token-shared.py)   # get a token from the SHARED HiDAH client"
echo "  2. Apply dcache.conf.pre-exchange.snippet to your dCache instance and restart it"
echo "  3. curl -k -H \"Authorization: Bearer \$TOKEN\" https://localhost:2881/"
