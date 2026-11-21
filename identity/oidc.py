import re
import secrets
from hmac import compare_digest

from authlib.oauth2.rfc6749 import (
    AuthorizationCodeGrant, AuthorizationServer, InvalidRequestError, OAuth2Request,
)
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7636.challenge import CODE_VERIFIER_PATTERN
from authlib.oidc.core.grants import OpenIDCode
from sanic import response

from .storage import can_access, digest, now


SCOPES = ("openid", "profile", "email")
CLIENT_AUTH = ("client_secret_basic", "client_secret_post")
TOKEN_SECONDS = 300


def user_info(user, scope):
    claims = {"sub": user["id"]}
    if "profile" in scope.split():
        claims["name"] = user["name"]
    if "email" in scope.split():
        claims.update(email=user["email"], email_verified=bool(user["email_verified"]))
    return claims


class Client:
    def __init__(self, row):
        self.row = row

    def get_client_id(self):
        return self.row["id"]

    def get_default_redirect_uri(self):
        return None

    def check_redirect_uri(self, uri):
        return uri == self.row["callback"]

    def get_allowed_scope(self, scope):
        return scope if scope and "openid" in scope.split() else None

    def check_client_secret(self, value):
        return compare_digest(self.row["secret"], digest(value))

    def check_endpoint_auth_method(self, method, endpoint):
        return method in CLIENT_AUTH and endpoint == "token"

    def check_response_type(self, value):
        return value == "code"

    def check_grant_type(self, value):
        return value == "authorization_code"


class Code:
    def __init__(self, row):
        self.row = row
        self.code_challenge = row["challenge"]
        self.code_challenge_method = "S256"

    def get_redirect_uri(self):
        return self.row["callback"]

    def get_scope(self):
        return self.row["scope"]

    def get_nonce(self):
        return self.row["nonce"]

    def get_auth_time(self):
        return self.row["authenticated"]

    def get_acr(self):
        return None

    def get_amr(self):
        return None


class RequireS256(CodeChallenge):
    def validate_code_challenge(self, grant, redirect_uri):
        data = grant.request.payload.data
        if data.get("code_challenge_method") != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", data.get("code_challenge", ""),
        ):
            raise InvalidRequestError("A valid S256 code challenge is required.")
        super().validate_code_challenge(grant, redirect_uri)


class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = CLIENT_AUTH

    def save_authorization_code(self, code, request):
        data = request.payload.data
        self.server.db.execute(
            """INSERT INTO codes
            (token, person, site, callback, scope, nonce, challenge, authenticated, expires)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (digest(code), request.user["id"], request.client.get_client_id(),
             request.payload.redirect_uri, request.scope, data.get("nonce"), data["code_challenge"],
             request.user["authenticated"], now() + 120),
        )

    def query_authorization_code(self, code, client):
        row = self.server.db.execute(
            "SELECT * FROM codes WHERE token=? AND site=?",
            (digest(code), client.get_client_id()),
        ).fetchone()
        if row and row["used"]:
            verifier = self.request.form.get("code_verifier", "")
            if (self.request.form.get("redirect_uri") == row["callback"]
                    and CODE_VERIFIER_PATTERN.fullmatch(verifier)
                    and CodeChallenge.CODE_CHALLENGE_METHODS["S256"](verifier, row["challenge"])):
                self.server.db.execute("DELETE FROM tokens WHERE code=?", (row["token"],))
            return None
        return Code(row) if row and row["expires"] > now() else None

    def delete_authorization_code(self, code):
        self.server.db.execute("UPDATE codes SET used=1 WHERE token=?", (code.row["token"],))

    def authenticate_user(self, code):
        person, site = code.row["person"], code.row["site"]
        if can_access(self.server.db, person, site):
            return self.server.db.execute("SELECT * FROM people WHERE id=?", (person,)).fetchone()
        return None


class OIDCCode(OpenIDCode):
    DEFAULT_EXPIRES_IN = TOKEN_SECONDS

    def __init__(self, server):
        super().__init__()
        self.server = server

    def exists_nonce(self, nonce, request):
        return self.server.db.execute(
            "SELECT 1 FROM codes WHERE site=? AND nonce=? AND expires>?",
            (request.payload.client_id, nonce, now() - TOKEN_SECONDS),
        ).fetchone() is not None

    def resolve_client_private_key(self, client):
        return self.server.key

    def get_client_claims(self, client):
        return {"iss": self.server.origin, "aud": [client.get_client_id()]}

    def get_encode_header(self, client):
        return {"alg": "RS256", "kid": self.server.kid, "typ": "JWT"}

    def generate_user_info(self, user, scope):
        return user_info(user, scope)


class SanicOAuthRequest(OAuth2Request):
    def __init__(self, request, origin):
        super().__init__(request.method, origin + request.path, headers=request.headers)
        params = request.args if request.method == "GET" else request.form
        if any(len(params.getlist(key)) != 1 for key in params):
            raise InvalidRequestError("Duplicate request parameter.")
        self.payload = BasicOAuth2Payload({key: params.get(key) for key in params})

    @property
    def form(self):
        return self.payload.data if self.method == "POST" else {}


class Server(AuthorizationServer):
    def __init__(self, db, origin, key):
        super().__init__(scopes_supported=SCOPES)
        self.db, self.origin, self.key = db, origin, key
        self.kid = key.thumbprint()
        self.register_token_generator("default", BearerTokenGenerator(
            lambda **_: secrets.token_urlsafe(32), expires_generator=lambda *_: TOKEN_SECONDS,
        ))
        self.register_grant(CodeGrant, [RequireS256(), OIDCCode(self)])

    def query_client(self, client_id):
        row = self.db.execute("SELECT * FROM sites WHERE id=? AND enabled", (client_id,)).fetchone()
        return Client(row) if row else None

    def save_token(self, token, request):
        self.db.execute("INSERT INTO tokens (token, person, site, scope, expires, code) VALUES (?, ?, ?, ?, ?, ?)", (
            digest(token["access_token"]), request.user["id"], request.client.get_client_id(),
            token["scope"], now() + token["expires_in"], request.authorization_code.row["token"],
        ))

    def create_oauth2_request(self, request):
        return request if isinstance(request, OAuth2Request) else SanicOAuthRequest(request, self.origin)

    def send_signal(self, name, *args, **kwargs):
        pass

    def handle_response(self, status, body, headers):
        if isinstance(body, dict):
            return response.json(body, status=status, headers=dict(headers))
        return response.text(body or "", status=status, headers=dict(headers))
