# Local test path for the RFC 8693 pre-exchange hop

The default stack in this directory (`docker-compose.yml`, `configure-keycloak.sh`,
`get-token.py`) never exercises `gplazma2-oidc-te`'s optional pre-exchange hop
(`TokenExchange.preExchange()`): HiDAH's token already carries `aud=test-client`,
exactly what the local Keycloak's `hidah` IdP link accepts, so the hop is simply
never needed for that token.

This adds a second, **opt-in** scenario that forces the pre-exchange hop to run,
without changing anything about the default stack.

## What's added

| Thing | Purpose |
|---|---|
| `docker-compose.pre-exchange.yml` | overlay compose file — new services only |
| `hidah-shared` (port 8086) | second HiDAH instance, client `shared-client` — its tokens carry an audience the primary `hidah` IdP link does not accept |
| `mock-preexchange` (port 8082) | stands in for the real Helmholtz AAI `/oauth2/token` pre-exchange endpoint — genuinely verifies `hidah-shared` tokens against its JWKS before re-minting them with a new audience |
| `configure-keycloak-preexchange.sh` | adds a second Keycloak IdP link (`preexchange-mock`) plus a dedicated client `dcache-client-preexchange`, on top of the realm `configure-keycloak.sh` already created -- a separate client is required because Keycloak 26.6.1's JWT Authorization Grant `idp` attribute is single-valued per client, so `dcache-client` itself is never touched |
| `get-token-shared.py` | PKCE flow against `hidah-shared` |
| `dcache.conf.pre-exchange.snippet` | dCache config block wiring `gplazma.oidc-te.pre-exchange-*` at the mock endpoint |

## Walkthrough

```bash
cd packages/system-test/keycloak

# 1. Base stack (unchanged) -- skip if already running
podman compose up -d
./configure-keycloak.sh
# Apply gplazma.conf.snippet to your dCache instance's gplazma.conf if you
# haven't already (needed for oidc-te to be in the auth chain at all) --
# dcache.conf.pre-exchange.snippet below is self-contained and replaces
# dcache.conf.snippet, so you don't need that one separately.

# 2. Bring up the pre-exchange overlay
podman compose -f docker-compose.yml -f docker-compose.pre-exchange.yml \
  up -d hidah-shared mock-preexchange
./configure-keycloak-preexchange.sh

# 3. Sanity-check the mock directly
curl -sf http://localhost:8082/healthz
curl -sf http://localhost:8082/jwks | python3 -m json.tool   # one RSA key, kid=mock-preexchange-1

# 4. Get a token from the shared HiDAH client
TOKEN=$(python3 get-token-shared.py)

# 5. Negative test -- confirm the mock actually verifies, rather than rubber-stamping
curl -s -u mock-preexchange-client:mock-preexchange-secret \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=garbage.not.a.jwt" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "audience=preexchange-mock" \
  --data-urlencode "scope=openid" \
  http://localhost:8082/oauth2/token
# Expected: HTTP 400, {"error": "invalid_grant", ...} -- NOT a 200

# 6. (Optional debugging fallback) replicate both hops by hand
NEW_TOKEN=$(curl -s -u mock-preexchange-client:mock-preexchange-secret \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$TOKEN" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "audience=preexchange-mock" \
  --data-urlencode "scope=openid" \
  http://localhost:8082/oauth2/token | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8081/realms/dcache-test/protocol/openid-connect/token \
  -d "client_id=dcache-client-preexchange" -d "client_secret=dcache-client-preexchange-secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion=$NEW_TOKEN" | python3 -m json.tool
# Expected: {"access_token": "eyJ...", ...} with preferred_username=testuser inside

# 7. Point dCache at it -- apply dcache.conf.pre-exchange.snippet (after the
#    dcache.layout=... line) to packages/system-test/target/dcache/etc/dcache.conf,
#    then:
packages/system-test/target/dcache/bin/dcache restart dCacheDomain

# 8. Full end-to-end request
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:2881/
```

**Success criteria**: HTTP 200 with a WebDAV listing, and `var/log/dCacheDomain.log`'s
gPlazma trace shows `oidc-te OPTIONAL:OK` -> `oidc SUFFICIENT:OK` ->
`UserNamePrincipal[testuser]` -- the same shape as the real Helmholtz AAI flow
documented in the project's dev notes, now fully local and repeatable.

## Notes

- **This scenario uses its own Keycloak client, `dcache-client-preexchange`,
  separate from `dcache-client`.** Keycloak 26.6.1's
  `oauth2.jwt.authorization.grant.idp` client attribute is single-valued -- a
  client can only be wired to one identity provider at a time (confirmed
  experimentally; a comma-separated or JSON-array value is rejected with
  "Identity Provider is not allowed for the client"). Sharing `dcache-client`
  between both scenarios would mean flipping that attribute back and forth,
  risking the default flow -- a dedicated client avoids that entirely.
  `configure-keycloak.sh`'s realm/client/user setup is never touched by
  `configure-keycloak-preexchange.sh`, and can be re-run safely at any time.
- **Tear down with the same `-f` flags used to bring things up**:
  `podman compose -f docker-compose.yml -f docker-compose.pre-exchange.yml down`.
  Mixing `-f` sets between `up` and `down` can behave inconsistently.
- `mock-preexchange` generates a fresh RSA keypair on every container start --
  restarting it invalidates previously re-minted tokens. Keycloak re-fetches its
  JWKS automatically on the next validation attempt; no manual step needed.
