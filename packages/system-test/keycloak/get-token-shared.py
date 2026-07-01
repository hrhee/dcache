#!/usr/bin/env python3
"""
get-token-shared.py — Obtain a token from the SECOND HiDAH instance (hidah-shared)
via PKCE authorization code flow, for testing the RFC 8693 pre-exchange hop.

This is get-token.py's PKCE flow, pointed at hidah-shared instead of the primary
hidah instance. The token it returns has aud=shared-client, which the primary
Keycloak "hidah" IdP link does NOT accept directly — it must go through the
mock-preexchange endpoint first (gplazma.oidc-te.pre-exchange-url), unlike the
default get-token.py flow which Keycloak accepts unmodified.

Usage:
  python3 get-token-shared.py              # uses defaults below
  HIDAH_URL=http://localhost:8086 python3 get-token-shared.py

The printed token is what a client (or gplazma2-oidc-te) presents as subject_token
to the pre-exchange endpoint, not something dCache accepts directly:
  TOKEN=$(python3 get-token-shared.py)
  curl -H "Authorization: Bearer $TOKEN" https://localhost:2881/   # only works if
                                                                    # dCache's oidc-te
                                                                    # pre-exchange hop
                                                                    # is configured
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

HIDAH_URL   = os.environ.get("HIDAH_URL",      "http://localhost:8086")
CLIENT_ID   = os.environ.get("HIDAH_CLIENT_ID", "shared-client")
CLIENT_SECRET = os.environ.get("HIDAH_CLIENT_SECRET", "shared-client-secret")
CALLBACK_PORT = int(os.environ.get("CALLBACK_PORT", "8998"))
REDIRECT_URI  = f"http://localhost:{CALLBACK_PORT}/callback"


def pkce_pair():
    verifier  = secrets.token_urlsafe(48)
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


_auth_result: dict = {}


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        _auth_result["code"]  = params.get("code",  [None])[0]
        _auth_result["error"] = params.get("error", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><p>Token obtained. You may close this tab.</p></body></html>")

    def log_message(self, *_):
        pass


def main():
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)

    auth_url = (
        f"{HIDAH_URL}/oauth2/auth"
        f"?response_type=code"
        f"&client_id={urllib.parse.quote(CLIENT_ID)}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        f"&scope=openid+email+profile"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )

    server = http.server.HTTPServer(("localhost", CALLBACK_PORT), _CallbackHandler)

    def serve_one():
        server.handle_request()

    t = threading.Thread(target=serve_one, daemon=True)
    t.start()

    print(f"Opening browser for hidah-shared login ...", file=sys.stderr)
    print(f"  URL: {auth_url}", file=sys.stderr)
    webbrowser.open(auth_url)

    t.join(timeout=120)

    if _auth_result.get("error"):
        print(f"ERROR: auth flow returned error: {_auth_result['error']}", file=sys.stderr)
        sys.exit(1)

    code = _auth_result.get("code")
    if not code:
        print("ERROR: no auth code received (timeout or cancelled).", file=sys.stderr)
        sys.exit(1)

    # Exchange code for tokens
    token_data = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri":  REDIRECT_URI,
        "code":          code,
        "code_verifier": verifier,
    }).encode()

    req = urllib.request.Request(
        f"{HIDAH_URL}/oauth2/token",
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            token_response = json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"ERROR: token exchange failed ({e.code}): {body}", file=sys.stderr)
        sys.exit(1)

    id_token = token_response.get("id_token")
    if not id_token:
        print(f"ERROR: no id_token in response: {token_response}", file=sys.stderr)
        sys.exit(1)

    print(f"Got token (expires_in={token_response.get('expires_in')}s)", file=sys.stderr)
    print(id_token)


if __name__ == "__main__":
    main()
