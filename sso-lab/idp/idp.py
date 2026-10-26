"""mini-entra: a small OpenID Connect provider that stands in for Microsoft Entra ID.

It does the identity provider's part of a sign-in, in code you can read:
- keeps users and app registrations (directory.json),
- shows a sign-in page and checks the password,
- remembers who signed in with its own session cookie (this is what makes SSO work),
- hands out single-use authorization codes,
- signs ID tokens with an RSA private key and publishes the public key.

The URL paths copy Entra's, so what you see here is what you will see there.
Teaching code only: plain HTTP, test passwords in a file, the key lives in memory.
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
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

PUBLIC_URL = os.getenv("PUBLIC_URL", "http://idp.localhost:9000")
with open(os.path.join(os.path.dirname(__file__), "directory.json")) as f:
    DIRECTORY = json.load(f)
TID = DIRECTORY["tenant_id"]
ISSUER = f"{PUBLIC_URL}/{TID}/v2.0"
USERS = {u["username"]: u for u in DIRECTORY["users"]}
APPS = {a["client_id"]: a for a in DIRECTORY["app_registrations"]}

CODE_LIFETIME = 60      # seconds; Entra's authorization codes also last about a minute
TOKEN_LIFETIME = 3600   # seconds; Entra's ID tokens last one hour


def log(msg):
    print(f"[mini-entra] {msg}", flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# 1. The signing key pair (RSA, 2048 bits), made fresh at every start.
#    The private exponent d never leaves this process. n and e are public.
# ---------------------------------------------------------------------------
def _probably_prime(n, rounds=40):
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):  # Miller-Rabin test
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if _probably_prime(candidate):
            return candidate


def new_rsa_key(bits=2048):
    e = 65537
    while True:
        p, q = _random_prime(bits // 2), _random_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue
        if p != q:
            return p * q, e, d


N, E, D = new_rsa_key()
K = (N.bit_length() + 7) // 8
KID = b64url(hashlib.sha256(N.to_bytes(K, "big")).digest())[:27]
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
log(f"made a new RSA signing key, kid={KID}")


def rs256_sign(data: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 with SHA-256, the algorithm called RS256 in a JWT."""
    t = SHA256_DIGEST_INFO + hashlib.sha256(data).digest()
    encoded = b"\x00\x01" + b"\xff" * (K - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(encoded, "big"), D, N).to_bytes(K, "big")


def sign_jwt(claims: dict) -> str:
    header = {"typ": "JWT", "alg": "RS256", "kid": KID}
    part = lambda obj: b64url(json.dumps(obj, separators=(",", ":")).encode())
    signing_input = part(header) + "." + part(claims)
    return signing_input + "." + b64url(rs256_sign(signing_input.encode()))


def pairwise_sub(user, app):
    """sub is different for every app; oid is the same everywhere (as in Entra)."""
    seed = f"{TID}:{app['client_id']}:{user['oid']}".encode()
    return b64url(hashlib.sha256(seed).digest())[:43]


# ---------------------------------------------------------------------------
# 2. What the IdP remembers (in memory; a restart forgets everything)
# ---------------------------------------------------------------------------
sessions = {}  # IdP session cookie value -> {"user", "sid", "apps"}
pending = {}   # sign-in page id -> the /authorize parameters while the page is open
codes = {}     # authorization code -> what it was issued for
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # print our own lines instead of an access log
        pass

    # ----- routing -----
    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        route = {
            "/": self.home,
            f"/{TID}/v2.0/.well-known/openid-configuration": self.discovery,
            f"/{TID}/discovery/v2.0/keys": self.jwks,
            f"/{TID}/oauth2/v2.0/authorize": self.authorize,
            f"/{TID}/oauth2/v2.0/logout": self.logout,
        }.get(url.path)
        route(q) if route else self.send_text(404, "not found")

    def do_POST(self):
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        route = {
            f"/{TID}/login": self.login,
            f"/{TID}/oauth2/v2.0/token": self.token,
        }.get(url.path)
        route(form) if route else self.send_text(404, "not found")

    # ----- public metadata -----
    def discovery(self, q):
        self.send_json(200, {
            "issuer": ISSUER,
            "authorization_endpoint": f"{PUBLIC_URL}/{TID}/oauth2/v2.0/authorize",
            "token_endpoint": f"{PUBLIC_URL}/{TID}/oauth2/v2.0/token",
            "jwks_uri": f"{PUBLIC_URL}/{TID}/discovery/v2.0/keys",
            "end_session_endpoint": f"{PUBLIC_URL}/{TID}/oauth2/v2.0/logout",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "scopes_supported": ["openid", "profile"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "frontchannel_logout_supported": True,
            "claims_supported": ["aud", "exp", "iat", "iss", "name", "nbf", "nonce", "oid",
                                 "preferred_username", "roles", "sid", "sub", "tid", "ver"],
        })

    def jwks(self, q):
        self.send_json(200, {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
            "n": b64url(N.to_bytes(K, "big")), "e": b64url(E.to_bytes(3, "big")),
        }]})

    # ----- step 1 of a sign-in: the browser arrives from an app -----
    def authorize(self, q):
        app = APPS.get(q.get("client_id", ""))
        if not app:
            return self.error_page("AADSTS700016", f"Application with identifier "
                                   f"'{q.get('client_id', '')}' was not found in the directory "
                                   f"'{DIRECTORY['tenant_name']}'.")
        name, redirect_uri = app["display_name"], q.get("redirect_uri", "")
        if redirect_uri not in app["redirect_uris"]:
            log(f"/authorize from {name}: redirect_uri {redirect_uri} is not registered "
                "-> refuse, and do NOT send the browser there")
            return self.error_page("AADSTS50011", f"The redirect URI '{redirect_uri}' specified "
                                   "in the request does not match the redirect URIs configured "
                                   f"for the application '{app['client_id']}'.")
        # The redirect URI is trusted from here on, so errors can go back to the app.
        if q.get("response_type") != "code":
            return self.redirect_error(q, "unsupported_response_type", "Use response_type=code.")
        if "openid" not in q.get("scope", "").split():
            return self.redirect_error(q, "invalid_request", "The scope must include openid.")
        if q.get("code_challenge") and q.get("code_challenge_method") != "S256":
            return self.redirect_error(q, "invalid_request", "Use code_challenge_method=S256.")

        session = self.current_session()
        prompt = q.get("prompt")
        if session and prompt != "login":
            log(f"/authorize from {name}: this browser already has an IdP session for "
                f"{session['user']} -> no sign-in page. This is single sign-on.")
            return self.finish_sign_in(session, q, app)
        if prompt == "none":
            return self.redirect_error(q, "login_required", "prompt=none, but nobody is signed in.")
        page_id = secrets.token_urlsafe(16)
        with lock:
            pending[page_id] = q
        why = "prompt=login" if session else "no IdP session for this browser"
        log(f"/authorize from {name}: {why} -> show the sign-in page")
        self.login_page(page_id, app)

    # ----- step 2: the user submits the sign-in form -----
    def login(self, form):
        page_id = form.get("page_id", "")
        q = pending.get(page_id)
        if not q:
            return self.error_page(None, "This sign-in page has expired. Go back to the app and "
                                   "sign in again.")
        app = APPS[q["client_id"]]
        user = USERS.get(form.get("username", "").strip().lower())
        if not user or not hmac.compare_digest(user["password"], form.get("password", "")):
            log("sign-in failed: wrong username or password")
            return self.login_page(page_id, app, error="Wrong username or password.")
        with lock:
            pending.pop(page_id, None)
            cookie_value = secrets.token_urlsafe(32)
            session = {"user": user["username"], "sid": str(uuid.uuid4()), "apps": set()}
            sessions[cookie_value] = session
        log(f"{user['username']} signed in with a password -> IdP session cookie set "
            "for idp.localhost")
        cookie = f"idp_session={cookie_value}; Path=/; HttpOnly; SameSite=Lax"
        self.finish_sign_in(session, q, app, cookie)

    # ----- step 3: give the app a single-use code, through the browser -----
    def finish_sign_in(self, session, q, app, cookie=None):
        user = USERS[session["user"]]
        if app["assignment_required"] and user["username"] not in app["assignments"]:
            log(f"{user['username']} is not assigned to {app['display_name']} "
                "(assignment required) -> refuse")
            return self.error_page("AADSTS50105", f"The signed in user '{user['username']}' is "
                                   f"not assigned to the application {app['display_name']}. "
                                   "Your administrator set this application to block users "
                                   "who were not assigned to it.", cookie)
        code = secrets.token_urlsafe(32)
        with lock:
            codes[code] = {
                "client_id": app["client_id"], "redirect_uri": q["redirect_uri"],
                "user": user["username"], "sid": session["sid"], "nonce": q.get("nonce"),
                "scope": q.get("scope", ""), "challenge": q.get("code_challenge"),
                "expires": time.time() + CODE_LIFETIME, "used": False,
            }
            session["apps"].add(app["client_id"])
        sep = "&" if "?" in q["redirect_uri"] else "?"
        location = q["redirect_uri"] + sep + urlencode({"code": code, "state": q.get("state", "")})
        log(f"code {code[:6]}... issued to {app['display_name']} for {user['username']} "
            f"(single use, valid {CODE_LIFETIME} s) -> send the browser back to the app")
        self.redirect(location, cookie)

    # ----- step 4: the app's server swaps the code for tokens (back channel) -----
    def token(self, form):
        client_id, secret = form.get("client_id", ""), form.get("client_secret", "")
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):  # client_secret_basic: id and secret in a header
            client_id, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
        app = APPS.get(client_id)
        if not app:
            return self.token_error(400, "invalid_client", "AADSTS700016",
                                    f"Application '{client_id}' was not found in the directory.")
        if not hmac.compare_digest(secret, app["client_secret"]):
            log(f"/token: wrong client secret from {app['display_name']} -> refuse")
            return self.token_error(401, "invalid_client", "AADSTS7000215",
                                    "Invalid client secret provided.")
        if form.get("grant_type") != "authorization_code":
            return self.token_error(400, "unsupported_grant_type", None,
                                    "This lab supports grant_type=authorization_code only.")
        with lock:
            entry = codes.get(form.get("code", ""))
            if not entry:
                return self.token_error(400, "invalid_grant", None, "The code is not known.")
            if entry["used"]:
                log(f"/token: {app['display_name']} sent a code that was already used -> refuse")
                return self.token_error(400, "invalid_grant", "AADSTS54005",
                                        "OAuth2 Authorization code was already redeemed.")
            entry["used"] = True
        if time.time() > entry["expires"]:
            return self.token_error(400, "invalid_grant", "AADSTS70008",
                                    "The provided authorization code has expired.")
        if entry["client_id"] != client_id or entry["redirect_uri"] != form.get("redirect_uri"):
            return self.token_error(400, "invalid_grant", None,
                                    "The code was issued to another app or redirect URI.")
        if entry["challenge"]:
            verifier = form.get("code_verifier", "")
            if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                log(f"/token: PKCE code_verifier from {app['display_name']} does not match -> refuse")
                return self.token_error(400, "invalid_grant", "AADSTS501481", "The Code_Verifier "
                                        "does not match the code_challenge supplied in the "
                                        "authorization request.")
        user, now = USERS[entry["user"]], int(time.time())
        claims = {
            "aud": app["client_id"],
            "iss": ISSUER,
            "iat": now,
            "nbf": now,
            "exp": now + TOKEN_LIFETIME,
            "name": user["name"],
            "oid": user["oid"],
            "preferred_username": user["username"],
            "sid": entry["sid"],
            "sub": pairwise_sub(user, app),
            "tid": TID,
            "ver": "2.0",
        }
        if entry["nonce"]:
            claims["nonce"] = entry["nonce"]
        roles = app["assignments"].get(user["username"], [])
        if roles:
            claims["roles"] = roles
        log(f"/token: {app['display_name']} swapped the code for tokens: secret OK, "
            f"PKCE OK -> ID token for {user['username']} signed with key {KID}")
        self.send_json(200, {
            "token_type": "Bearer",
            "scope": entry["scope"],
            "expires_in": TOKEN_LIFETIME,
            "access_token": "lab-opaque-" + secrets.token_urlsafe(24),
            "id_token": sign_jwt(claims),
        }, extra=[("Cache-Control", "no-store")])

    # ----- sign-out -----
    def logout(self, q):
        cookie_value = self.cookie("idp_session")
        with lock:
            session = sessions.pop(cookie_value, None) if cookie_value else None
        target = q.get("post_logout_redirect_uri")
        app = APPS.get(q.get("client_id", ""))
        if target and not (app and target in app["redirect_uris"]):
            return self.error_page(None, f"post_logout_redirect_uri '{target}' is not a "
                                   "registered redirect URI of this app.")
        frames = []
        if session:
            for client_id in sorted(session["apps"]):
                url = APPS[client_id].get("frontchannel_logout_url")
                if url:
                    frames.append(url + "?" + urlencode({"iss": ISSUER, "sid": session["sid"]}))
            log(f"logout: ended the IdP session of {session['user']}; telling {len(frames)} "
                "app(s) through their front-channel logout URLs")
        else:
            log("logout: this browser had no IdP session")
        clear = "idp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        self.signed_out_page(frames, target, clear)

    # ----- helpers -----
    def cookie(self, name):
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else None

    def current_session(self):
        value = self.cookie("idp_session")
        return sessions.get(value) if value else None

    def redirect_error(self, q, error, description):
        sep = "&" if "?" in q["redirect_uri"] else "?"
        self.redirect(q["redirect_uri"] + sep + urlencode(
            {"error": error, "error_description": description, "state": q.get("state", "")}))

    def redirect(self, location, cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_json(self, status, obj, extra=()):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def token_error(self, status, error, entra_code, text):
        description = f"{entra_code}: {text}" if entra_code else text
        self.send_json(status, {"error": error, "error_description": description})

    def send_text(self, status, text):
        self.send_html(status, f"<p>{html.escape(text)}</p>")

    def send_html(self, status, body, cookie=None):
        page = PAGE.replace("{{BODY}}", body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def error_page(self, entra_code, text, cookie=None):
        code_line = (f"<p class='code'>The same error in Entra: <b>{entra_code}</b></p>"
                     if entra_code else "")
        self.send_html(400, f"<h1>Sign-in stopped</h1><p>{html.escape(text)}</p>{code_line}",
                       cookie)

    def login_page(self, page_id, app, error=""):
        err = f"<p class='err'>{html.escape(error)}</p>" if error else ""
        self.send_html(200, f"""
<h1>Sign in</h1>
<p>to continue to <b>{html.escape(app['display_name'])}</b></p>{err}
<form method="post" action="/{TID}/login">
  <input type="hidden" name="page_id" value="{page_id}">
  <label>Username <input name="username" value="alice@lab.test" autocomplete="off"></label>
  <label>Password <input name="password" type="password" value="lab-password"></label>
  <button>Sign in</button>
</form>
<p class="hint">Test users: <code>alice@lab.test</code> and <code>bob@lab.test</code>,
password <code>lab-password</code>. Only this page sees the password; the app never does.</p>""")

    def signed_out_page(self, frames, target, cookie):
        iframes = "".join(f'<iframe src="{html.escape(u)}" hidden></iframe>' for u in frames)
        go = (f"<p><a href='{html.escape(target)}'>Continue</a></p>"
              f"<script>setTimeout(() => location.href = {json.dumps(target)}, 1500)</script>"
              if target else "")
        self.send_html(200, f"<h1>You signed out</h1><p>Mini Entra ended your session and "
                       f"told {len(frames)} app(s) to end theirs.</p>{iframes}{go}", cookie)

    def home(self, q):
        rows = "".join(f"<li>{html.escape(a['display_name'])}: <code>{a['client_id']}</code></li>"
                       for a in APPS.values())
        self.send_html(200, f"""<h1>Mini Entra is running</h1>
<p>Tenant <b>{html.escape(DIRECTORY['tenant_name'])}</b> <code>{TID}</code></p>
<p><a href="/{TID}/v2.0/.well-known/openid-configuration">Discovery document</a> ·
<a href="/{TID}/discovery/v2.0/keys">Public signing keys</a></p>
<p>App registrations:</p><ul>{rows}</ul>""")


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Mini Entra</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;background:#eef0f7;color:#1c2133;margin:0;
padding:48px 16px}
main{max-width:420px;margin:0 auto;background:#fff;border:1px solid #d3d7e6;border-radius:6px;
padding:28px 28px 20px}
.brand{font:600 13px/1 system-ui;letter-spacing:.08em;text-transform:uppercase;color:#3d4a9e}
h1{font-size:24px;margin:10px 0 4px}
label{display:block;margin:14px 0 0;font-size:14px;color:#4b5270}
input{display:block;width:100%;box-sizing:border-box;font:inherit;padding:8px 10px;
border:1px solid #b9bfd6;border-radius:4px;margin-top:4px}
button{margin-top:20px;font:inherit;font-weight:600;background:#3d4a9e;color:#fff;border:0;
border-radius:4px;padding:9px 22px;cursor:pointer}
.hint{font-size:13px;color:#5b6283;border-top:1px solid #e3e6f0;margin-top:24px;padding-top:12px}
.err{color:#a3261b}.code{font-size:14px;color:#5b6283}
code{font-size:13px;background:#eef0f7;padding:1px 4px;border-radius:3px}
</style></head><body><main><div class="brand">Mini Entra · lab identity provider</div>
{{BODY}}</main></body></html>"""


if __name__ == "__main__":
    log(f"issuer {ISSUER}")
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
