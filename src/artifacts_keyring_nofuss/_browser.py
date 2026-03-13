"""Auth flow: OAuth2 authorization code with PKCE via system browser."""

from __future__ import annotations

import base64
import hashlib
import http.server
import logging
import secrets
import threading
import urllib.parse
import webbrowser

import requests

from . import _constants as C

log = logging.getLogger(__name__)


class BrowserProvider:
    name = "browser"

    def get_token(self, tenant_id: str) -> str | None:
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = (
            hashlib.sha256(code_verifier.encode("ascii"))
            .digest()
        )
        code_challenge_b64 = (
            base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("ascii")
        )

        # Start a one-shot local HTTP server to capture the redirect
        auth_code: str | None = None
        error: str | None = None
        server_ready = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal auth_code, error
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                auth_code = qs.get("code", [None])[0]
                error = qs.get("error_description", qs.get("error", [None]))[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if auth_code:
                    self.wfile.write(b"<html><body><h3>Authentication complete. You can close this tab.</h3></body></html>")
                else:
                    self.wfile.write(b"<html><body><h3>Authentication failed. You can close this tab.</h3></body></html>")

            def log_message(self, format, *args):
                log.debug(format, *args)

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = httpd.server_address[1]
        redirect_uri = f"http://localhost:{port}"

        def serve():
            server_ready.set()
            httpd.handle_request()

        server_thread = threading.Thread(target=serve, daemon=True)
        server_thread.start()
        server_ready.wait()

        authorize_url = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
            + urllib.parse.urlencode({
                "client_id": C.CLIENT_ID,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": C.SCOPE,
                "code_challenge": code_challenge_b64,
                "code_challenge_method": "S256",
            })
        )

        log.info("Opening browser for authentication...")
        if not webbrowser.open(authorize_url):
            log.warning("Could not open browser. Visit this URL manually:\n%s", authorize_url)

        # Wait for the browser redirect (up to 5 minutes)
        server_thread.join(timeout=300)
        httpd.server_close()

        if not auth_code:
            if error:
                log.debug("browser auth error: %s", error)
            return None

        # Exchange auth code for token
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        try:
            resp = requests.post(
                token_url,
                data={
                    "client_id": C.CLIENT_ID,
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                },
                timeout=30,
            )
            resp.raise_for_status()
        except requests.RequestException:
            log.debug("token exchange failed", exc_info=True)
            return None

        return resp.json().get("access_token")
