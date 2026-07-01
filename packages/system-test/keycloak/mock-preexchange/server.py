#!/usr/bin/env python3
"""
mock-preexchange/server.py — minimal RFC 8693 token-exchange endpoint for local testing.

Stands in for the real Helmholtz AAI /oauth2/token endpoint that gplazma2-oidc-te's
optional pre-exchange hop (TokenExchange.preExchange()) talks to. Genuinely verifies
the incoming subject_token against the issuing HiDAH instance's JWKS (signature,
issuer, audience, expiry) before re-minting a new JWT with a different audience,
signed with its own ephemeral key — it does not rubber-stamp whatever it's handed.

Endpoints:
  GET  /healthz      -> 200, for the compose healthcheck
  GET  /jwks          -> this server's own public JWK set
  POST /oauth2/token  -> the pre-exchange endpoint itself (RFC 8693 token-exchange)

Configuration is via environment variables (matching the docker-compose.pre-exchange.yml
service definition):
  HIDAH_JWKS_URL              JWKS endpoint of the HiDAH instance whose tokens we accept
  HIDAH_ISSUER                expected "iss" claim on incoming subject_token
  EXPECTED_AUDIENCE           expected "aud" claim on incoming subject_token
  REMINTED_AUDIENCE           "aud" claim stamped into the re-minted JWT
  PRE_EXCHANGE_CLIENT_ID      HTTP Basic Auth username this endpoint requires
  PRE_EXCHANGE_CLIENT_SECRET  HTTP Basic Auth password this endpoint requires
  PORT                        listen port (default 8080)
"""

import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

HIDAH_JWKS_URL = os.environ["HIDAH_JWKS_URL"]
HIDAH_ISSUER = os.environ["HIDAH_ISSUER"]
EXPECTED_AUDIENCE = os.environ["EXPECTED_AUDIENCE"]
REMINTED_AUDIENCE = os.environ["REMINTED_AUDIENCE"]
PRE_EXCHANGE_CLIENT_ID = os.environ["PRE_EXCHANGE_CLIENT_ID"]
PRE_EXCHANGE_CLIENT_SECRET = os.environ["PRE_EXCHANGE_CLIENT_SECRET"]
PORT = int(os.environ.get("PORT", "8080"))

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
KID = "mock-preexchange-1"
CLAIMS_TO_COPY = ("sub", "preferred_username", "name", "email")

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_jwk = json.loads(RSAAlgorithm.to_jwk(_private_key.public_key()))
_public_jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})

_jwks_cache = {"fetched_at": 0.0, "keys": None}
JWKS_CACHE_TTL_SECONDS = 300


def fetch_hidah_jwks():
    now = time.time()
    if _jwks_cache["keys"] is not None and now - _jwks_cache["fetched_at"] < JWKS_CACHE_TTL_SECONDS:
        return _jwks_cache["keys"]
    with urllib.request.urlopen(HIDAH_JWKS_URL, timeout=10) as resp:
        keys = json.load(resp)["keys"]
    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = now
    return keys


def verify_subject_token(token):
    """Cryptographically verify token against HiDAH's JWKS. Raises jwt.PyJWTError on failure."""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    keys = fetch_hidah_jwks()
    matching = [k for k in keys if k.get("kid") == kid] if kid else keys
    if not matching:
        # kid mismatch is itself a verification failure, not a lookup error
        raise jwt.InvalidTokenError(f"no matching key for kid={kid!r} in HiDAH JWKS")

    last_error = None
    for jwk in matching:
        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            return jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                issuer=HIDAH_ISSUER,
                audience=EXPECTED_AUDIENCE,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as e:
            last_error = e
    raise last_error


def mint_reexchanged_token(claims):
    now = int(time.time())
    payload = {k: claims[k] for k in CLAIMS_TO_COPY if k in claims}
    payload.update({
        "iss": "http://mock-preexchange:8080",
        "aud": REMINTED_AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "jti": secrets.token_hex(16),
    })
    return jwt.encode(payload, _private_key, algorithm="RS256", headers={"kid": KID})


def check_basic_auth(auth_header):
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[len("Basic "):]).decode()
        username, _, password = decoded.partition(":")
    except Exception:
        return False
    return username == PRE_EXCHANGE_CLIENT_ID and password == PRE_EXCHANGE_CLIENT_SECRET


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
        elif self.path == "/jwks":
            self._send_json(200, {"keys": [_public_jwk]})
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/oauth2/token":
            self._send_json(404, {"error": "not_found"})
            return

        if not check_basic_auth(self.headers.get("Authorization")):
            self._send_json(401, {"error": "invalid_client"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        params = {k: v[0] for k, v in parse_qs(body).items()}

        if params.get("grant_type") != GRANT_TYPE:
            self._send_json(400, {"error": "unsupported_grant_type"})
            return
        if not params.get("subject_token"):
            self._send_json(400, {"error": "invalid_request", "error_description": "missing subject_token"})
            return
        if params.get("subject_token_type") != TOKEN_TYPE or params.get("requested_token_type") != TOKEN_TYPE:
            self._send_json(400, {"error": "invalid_request", "error_description": "unsupported token type"})
            return
        if params.get("audience") != REMINTED_AUDIENCE:
            self._send_json(400, {
                "error": "invalid_target",
                "error_description": f"this endpoint only mints for audience={REMINTED_AUDIENCE!r}",
            })
            return

        try:
            claims = verify_subject_token(params["subject_token"])
        except jwt.PyJWTError as e:
            self._send_json(400, {"error": "invalid_grant", "error_description": str(e)})
            return
        except urllib.error.URLError as e:
            self._send_json(502, {"error": "temporarily_unavailable", "error_description": str(e)})
            return

        new_token = mint_reexchanged_token(claims)
        self._send_json(200, {
            "access_token": new_token,
            "issued_token_type": TOKEN_TYPE,
            "token_type": "N_A",
        })


def main():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"mock-preexchange listening on :{PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
