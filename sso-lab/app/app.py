"""A small web app that signs users in with OpenID Connect.

The same file runs as App A and App B (see compose.yaml). It talks to mini-entra
here, and it talks to Microsoft Entra ID the same way: it learns every URL from
the discovery document and checks tokens with the keys the IdP publishes.
To point it at Entra you change ISSUER, CLIENT_ID and the secret.

Teaching code: in a real project use a maintained library (MSAL, Authlib),
HTTPS everywhere, Secure cookies, and a shared session store.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

APP_NAME = os.environ["APP_NAME"]
PORT = int(os.environ["PORT"])
PUBLIC_URL = os.environ["PUBLIC_URL"]          # where the browser reaches this app
OTHER_APP_URL = os.getenv("OTHER_APP_URL", "")
ISSUER = os.environ["ISSUER"]                  # who we trust to sign users in
CLIENT_ID = os.environ["CLIENT_ID"]            # this app's ID in the IdP
with open(os.environ["CLIENT_SECRET_FILE"]) as f:
    CLIENT_SECRET = f.read().strip()           # proves to the IdP that we are this app
COLOR = os.getenv("APP_COLOR", "#0b6b6b")
REDIRECT_URI = PUBLIC_URL + "/auth/callback"
SCOPES = "openid profile"
CLOCK_SKEW = 300                               # seconds of clock difference we accept


def log(msg):
    print(f"[{APP_NAME}] {msg}", flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# 1. Discovery and keys: everything the app needs to know about the IdP
# ---------------------------------------------------------------------------
_metadata, _keys = None, {}


def fetch_json(url, data=None):
    body = urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:  # the IdP explains errors in a JSON body
        return json.load(e)


def metadata():
    global _metadata
    if _metadata is None:
        doc = fetch_json(ISSUER + "/.well-known/openid-configuration")
        if doc.get("issuer") != ISSUER:
            raise RuntimeError(f"discovery says issuer {doc.get('issuer')}, expected {ISSUER}")
        _metadata = doc
        log(f"read the discovery document; keys are at {doc['jwks_uri']}")
    return _metadata


def signing_key(kid):
    if kid not in _keys:  # a key we have not seen: the IdP may have rotated keys, so re-fetch
        _keys.clear()
        for k in fetch_json(metadata()["jwks_uri"])["keys"]:
            if k.get("kty") == "RSA" and k.get("use", "sig") == "sig":
                _keys[k["kid"]] = (int.from_bytes(b64url_decode(k["n"]), "big"),
                                   int.from_bytes(b64url_decode(k["e"]), "big"))
        log(f"fetched {len(_keys)} public signing key(s) from jwks_uri")
    return _keys.get(kid)


# ---------------------------------------------------------------------------
# 2. Checking an ID token. Each check below stops one kind of attack.
# ---------------------------------------------------------------------------
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rs256_verify(data: bytes, signature: bytes, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(signature, "big")
    if len(signature) != k or s >= n:
        return False
    t = SHA256_DIGEST_INFO + hashlib.sha256(data).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), expected)


def validate_id_token(token: str, expected_nonce: str) -> dict:
    """Return the claims if every check passes; raise ValueError naming the failed check."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except ValueError:
        raise ValueError("not a JWT (expected three base64url parts)")
    # 1. Signature: was it made with the IdP's private key, and is it unchanged?
    if header.get("alg") != "RS256":
        raise ValueError(f"alg is {header.get('alg')!r}; only RS256 is accepted")
    key = signing_key(header.get("kid"))
    if key is None:
        raise ValueError("signed with a key the IdP does not publish")
    if not rs256_verify(f"{header_b64}.{payload_b64}".encode(), b64url_decode(signature_b64), *key):
        raise ValueError("signature check failed: the token was changed or not made by the IdP")
    # 2. Issuer: made by the IdP (and tenant) we trust?
    if claims.get("iss") != ISSUER:
        raise ValueError(f"iss is {claims.get('iss')}; expected {ISSUER}")
    # 3. Audience: made for this app, not for another one?
    if claims.get("aud") != CLIENT_ID:
        raise ValueError(f"aud is {claims.get('aud')}; this app is {CLIENT_ID}")
    # 4. Time: still valid?
    now = time.time()
    if now > claims.get("exp", 0) + CLOCK_SKEW:
        raise ValueError("the token has expired")
    if now < claims.get("nbf", 0) - CLOCK_SKEW:
        raise ValueError("the token is not valid yet")
    # 5. Nonce: made for this sign-in, not replayed from an older one?
    if not hmac.compare_digest(str(claims.get("nonce", "")), expected_nonce):
        raise ValueError("nonce does not match this sign-in")
    return claims


# ---------------------------------------------------------------------------
# 3. What the app remembers (in memory; with several copies use Redis or a database)
# ---------------------------------------------------------------------------
pending = {}   # state -> {"nonce", "verifier", "created"}: sign-ins in progress
sessions = {}  # session cookie value -> {"claims", "id_token"}
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        route = {
            "/": self.home,
            "/login": self.login,
            "/auth/callback": self.callback,
            "/logout": self.logout,
            "/auth/frontchannel-logout": self.frontchannel_logout,
            "/admin": self.admin,
            "/api/me": self.api_me,
            "/health": self.health,
        }.get(url.path)
        route(q) if route else self.page(404, "Not found", "<p>No page here.</p>")

    # ----- start a sign-in: send the browser to the IdP -----
    def login(self, q):
        state = secrets.token_urlsafe(16)      # ties the answer to this browser (stops CSRF)
        nonce = secrets.token_urlsafe(16)      # ties the ID token to this sign-in (stops replay)
        verifier = secrets.token_urlsafe(48)   # PKCE: only this server knows it
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        with lock:
            pending[state] = {"nonce": nonce, "verifier": verifier, "created": time.time()}
        params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "response_mode": "query",
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if q.get("prompt") in ("login", "none", "select_account"):
            params["prompt"] = q["prompt"]
        log(f"/login: new sign-in (state {state[:6]}..., nonce {nonce[:6]}...) "
            "-> send the browser to the IdP")
        self.redirect(metadata()["authorization_endpoint"] + "?" + urlencode(params),
                      [f"login_state={state}; Path=/auth; Max-Age=600; HttpOnly; SameSite=Lax"])

    # ----- the browser comes back from the IdP with a code -----
    def callback(self, q):
        if "error" in q:
            log(f"/auth/callback: the IdP sent an error: {q['error']}")
            return self.page(400, "Sign-in failed", f"<p><b>{html.escape(q['error'])}</b>: "
                             f"{html.escape(q.get('error_description', ''))}</p>")
        state, mine = q.get("state", ""), self.cookie("login_state") or ""
        if not state or not hmac.compare_digest(state, mine):
            log("/auth/callback: state does not match this browser's login_state cookie -> refuse")
            return self.page(400, "Sign-in refused", "<p>This answer belongs to a sign-in that "
                             "this browser did not start (the <code>state</code> does not "
                             "match).</p>")
        with lock:
            flow = pending.pop(state, None)
        if not flow or time.time() - flow["created"] > 600:
            return self.page(400, "Sign-in expired", "<p>Please sign in again.</p>")
        log("/auth/callback: state matches this browser's cookie -> OK")

        # Back channel: server to server, with the secret and the PKCE verifier.
        tokens = fetch_json(metadata()["token_endpoint"], {
            "grant_type": "authorization_code",
            "code": q.get("code", ""),
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": flow["verifier"],
        })
        if "id_token" not in tokens:
            log(f"token endpoint refused: {tokens.get('error')}: {tokens.get('error_description')}")
            return self.page(400, "Sign-in failed", f"<p>The token endpoint said: "
                             f"<b>{html.escape(str(tokens.get('error')))}</b> "
                             f"{html.escape(str(tokens.get('error_description', '')))}</p>")
        log("back channel: swapped the code for an ID token at the token endpoint")
        try:
            claims = validate_id_token(tokens["id_token"], flow["nonce"])
        except ValueError as e:
            log(f"ID token rejected: {e}")
            return self.page(401, "Sign-in refused", f"<p>{html.escape(str(e))}</p>")
        log("ID token checks: signature OK, iss OK, aud OK, exp OK, nonce OK")

        session_id = secrets.token_urlsafe(32)
        with lock:
            sessions[session_id] = {"claims": claims, "id_token": tokens["id_token"]}
        log(f"signed in {claims.get('name')} (oid {claims.get('oid')}) -> app session cookie set")
        self.redirect("/", [f"session={session_id}; Path=/; HttpOnly; SameSite=Lax",
                            "login_state=; Path=/auth; Max-Age=0"])

    # ----- sign-out -----
    def logout(self, q):
        with lock:
            sessions.pop(self.cookie("session") or "", None)
        log("/logout: app session ended -> send the browser to the IdP to end its session too")
        url = metadata()["end_session_endpoint"] + "?" + urlencode(
            {"post_logout_redirect_uri": PUBLIC_URL + "/", "client_id": CLIENT_ID})
        self.redirect(url, ["session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"])

    def frontchannel_logout(self, q):
        if q.get("iss") != ISSUER:
            return self.page(400, "Wrong issuer", "<p>Unknown issuer.</p>")
        with lock:
            gone = [k for k, s in sessions.items() if s["claims"].get("sid") == q.get("sid")]
            for k in gone:
                del sessions[k]
        log(f"front-channel logout from the IdP: ended {len(gone)} session(s)")
        self.page(200, "Signed out", "<p>Signed out.</p>")

    # ----- pages -----
    def current_session(self):
        session = sessions.get(self.cookie("session") or "")
        if session and time.time() > session["claims"]["exp"]:
            return None  # the session lasts as long as the ID token
        return session

    def home(self, q):
        session = self.current_session()
        other = (f" · <a href='{html.escape(OTHER_APP_URL)}'>Open the other app</a>"
                 if OTHER_APP_URL else "")
        if not session:
            return self.page(200, "Not signed in", "<p>This app does not know who you are.</p>"
                             f"<p><a class='btn' href='/login'>Sign in with Mini Entra</a>{other}</p>")
        c = session["claims"]
        rows = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(fmt(k, v))}</td></tr>"
                       for k, v in c.items())
        h, p, s = session["id_token"].split(".")
        self.page(200, f"Hello, {html.escape(c.get('name', ''))}",
                  f"<p>Signed in as <b>{html.escape(c.get('preferred_username', ''))}</b>.</p>"
                  f"<p><a href='/admin'>Admin page</a> · <a href='/api/me'>/api/me</a>{other} · "
                  f"<a href='/logout'>Sign out</a></p>"
                  f"<h2>Claims in the ID token</h2><table>{rows}</table>"
                  f"<h2>The ID token itself</h2><p class='jwt'><span class='h'>{h}</span>."
                  f"<span class='p'>{p}</span>.<span class='s'>{s}</span></p>")

    def admin(self, q):
        session = self.current_session()
        if not session:
            return self.redirect("/login")
        roles = session["claims"].get("roles", [])
        if "Admin" not in roles:
            log(f"/admin: {session['claims'].get('name')} has roles {roles} -> 403")
            return self.page(403, "Forbidden", "<p>You are signed in, but you do not have the "
                             "<b>Admin</b> role. <a href='/'>Back</a></p>")
        self.page(200, "Admin page", "<p>You have the <b>Admin</b> role. <a href='/'>Back</a></p>")

    def api_me(self, q):
        session = self.current_session()
        if not session:
            return self.json(401, {"error": "not signed in"})
        self.json(200, session["claims"])

    def health(self, q):
        self.json(200, {"status": "ok"})

    # ----- helpers -----
    def cookie(self, name):
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else None

    def redirect(self, location, cookies=()):
        self.send_response(302)
        self.send_header("Location", location)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def json(self, status, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def page(self, status, title, body):
        doc = (PAGE.replace("{{COLOR}}", COLOR).replace("{{APP}}", html.escape(APP_NAME))
               .replace("{{TITLE}}", title).replace("{{BODY}}", body)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(doc)))
        self.end_headers()
        self.wfile.write(doc)


def fmt(key, value):
    if key in ("iat", "nbf", "exp"):
        when = datetime.fromtimestamp(value, timezone.utc).strftime("%H:%M:%S UTC")
        return f"{value}  ({when})"
    return ", ".join(value) if isinstance(value, list) else str(value)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{APP}}</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f7;color:#1b2222}
header{background:{{COLOR}};color:#fff;padding:14px 20px;font-weight:600}
main{max-width:760px;margin:0 auto;padding:8px 20px 40px}
a{color:{{COLOR}}}.btn{display:inline-block;background:{{COLOR}};color:#fff;padding:8px 16px;
border-radius:4px;text-decoration:none;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;
padding:5px 8px;border-bottom:1px solid #dde2e2;vertical-align:top}th{width:28%;
font-family:ui-monospace,Menlo,monospace;font-weight:500}td{word-break:break-all}
.jwt{font:12px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;background:#fff;
border:1px solid #dde2e2;padding:10px}.h{color:#b23a48}.p{color:#6a3fa0}.s{color:#1f6fb2}
h2{font-size:17px;margin-top:28px}
</style></head><body><header>{{APP}}</header><main><h1>{{TITLE}}</h1>{{BODY}}</main></body></html>"""


if __name__ == "__main__":
    log(f"listening on {PUBLIC_URL}; trusts issuer {ISSUER}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
