import json
import logging
import os
import re
import secrets
import time
from hmac import compare_digest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID, uuid4

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oidc.core.errors import LoginRequiredError, RequestNotSupportedError, RequestURINotSupportedError
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sanic import Sanic, response
from webauthn import (
    generate_authentication_options, generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
    ResidentKeyRequirement, UserVerificationRequirement,
)

from .branding import Brand
from .oidc import CLIENT_AUTH, SCOPES, Server, user_info
from .passwords import register_passwords
from .storage import (
    ASCII_LOWER, StorageIntegrityError, can_access, digest, issue_invite, issue_signup_link, log, now, open_signup,
    person_by_email, reset_passkeys, store_from_environment,
)


FILES = Path(__file__).parent
LOGGER = logging.getLogger(__name__)
APP_ICONS = {
    "tasks.obscuretone.com": "nira",
    "docs.obscuretone.com": "nonfluence",
    "taste.obscuretone.com": "taste",
    "studio.obscuretone.com": "studio",
    "commerce.obscuretone.com": "commerce",
    "status.obscuretone.com": "status",
}
SESSION_COOKIE = "obscuretone_session"
FLOW_COOKIE = "obscuretone_flow"
SESSION_SECONDS = 3600
FLOW_SECONDS = 300
OKTA = "/oauth2/v1"
OIDC_POST = {"/token", "/authorize", "/userinfo", OKTA + "/token", OKTA + "/authorize", OKTA + "/userinfo"}
UV = UserVerificationRequirement.REQUIRED
AUTHORIZATION_PARAMS = frozenset({
    "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method", "prompt", "max_age", "request", "request_uri",
})
TEMPLATES = Environment(
    loader=FileSystemLoader(FILES / "templates"), autoescape=select_autoescape(),
)


def problem(message, status=400):
    return response.json({"error": message}, status=status)


def cookie_value(request, key):
    value = request.cookies.get("__Host-" + key, "")
    return value if re.fullmatch(r"[A-Za-z0-9_-]{43}", value) else ""


def set_cookie(result, key, value, seconds):
    result.add_cookie(key, value, max_age=seconds, httponly=True, host_prefix=True)


def local_target(value):
    if value == "/manage":
        return value
    if isinstance(value, str) and value.startswith(("/authorize?", OKTA + "/authorize?")) and len(value) <= 4096:
        if not re.search(r"[\\\x00-\x20\x7f]", value):
            return value
    return "/"


def valid_https(value):
    try:
        url = urlsplit(value)
        return (
            len(value) <= 500 and not re.search(r"[\\\s\x00-\x1f\x7f]", value)
            and url.scheme == "https" and url.hostname and not url.username
            and url.password is None and "#" not in value and "*" not in value
            and (url.port is None or 1 <= url.port <= 65535)
        )
    except ValueError:
        return False


def launcher_shortcuts(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        LOGGER.warning("Could not read launcher.json.")
        return []

    if not isinstance(config, list):
        LOGGER.warning("Expected a list in launcher.json.")
        return []
    shortcuts = {}
    for entry in config:
        if isinstance(entry, dict):
            name, launch = entry.get("name"), entry.get("launch")
            if (isinstance(name, str) and 1 <= len(name.strip()) <= 80
                    and isinstance(launch, str) and valid_https(launch)):
                shortcuts.setdefault(launch, {"name": name.strip(), "launch": launch})
                continue
        LOGGER.warning("Ignored an invalid launcher shortcut.")
    return list(shortcuts.values())


def valid_email(value):
    return len(value) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value)


def get_session(db, token):
    return db.execute(
        """SELECT p.*, s.token AS session_token, s.authenticated, s.fresh_for
        FROM sessions s JOIN people p ON p.id=s.person
        WHERE s.token=? AND s.expires>? AND p.enabled""",
        (token, now()),
    ).fetchone()


def top_level_credential(credential):
    client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
    return isinstance(client_data, dict) and client_data.get("crossOrigin", False) is False and "topOrigin" not in client_data


def invited_person(db, token):
    return db.execute(
        """SELECT p.* FROM invitations i JOIN people p ON p.id=i.person
        WHERE i.token=? AND i.expires>? AND p.enabled""", (token, now()),
    ).fetchone()


def new_session(db, result, person, previous, fresh_for):
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE token=? OR expires<=?", (digest(previous), now()))
    db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
               (digest(token), person, now(), now() + SESSION_SECONDS, fresh_for))
    set_cookie(result, SESSION_COOKIE, token, SESSION_SECONDS)


def is_form_encoded(request):
    return request.content_type.partition(";")[0].strip().lower() == "application/x-www-form-urlencoded"


def create_app(origin=None, directory=None):
    origin = origin or os.environ.get("IDENTITY_ORIGIN", "")
    if not valid_https(origin) or origin != "https://" + urlsplit(origin).netloc:
        raise ValueError("IDENTITY_ORIGIN must be an HTTPS origin with no path.")
    host = urlsplit(origin).netloc
    rp_id = urlsplit(origin).hostname
    okta_metadata = os.environ.get("IDENTITY_OKTA_ENDPOINTS") == "1"
    store = store_from_environment(directory)
    key = store.signing_key()
    shortcuts = launcher_shortcuts(store.directory / "launcher.json")
    brand = Brand.from_environment()
    app = Sanic("obscuretone_identity")
    app.config.REQUEST_MAX_SIZE = 64 * 1024
    app.config.ACCESS_LOG = False
    app.static("/assets", FILES / "assets", name="assets")
    def image_asset(data, content_type):
        return response.raw(data, content_type=content_type, headers={
            "Content-Security-Policy": "sandbox; default-src 'none'; "
                                       "style-src 'unsafe-inline'; frame-ancestors 'none'",
        })

    if brand.logo is not None:
        @app.get("/brand/logo", strict_slashes=True)
        async def custom_logo(request):
            return image_asset(brand.logo, brand.logo_type)

        @app.get("/favicon.ico")
        async def custom_favicon(request):
            return response.redirect(brand.logo_url)

    if brand.hero is not None:
        @app.get("/brand/hero")
        async def custom_hero(request):
            return image_asset(brand.hero, brand.hero_type)

    if brand.css is not None:
        @app.get("/brand/site.css")
        async def custom_css(request):
            return response.raw(brand.css, content_type="text/css")

    def site_css(client_id):
        if not brand.site_styles or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", client_id):
            return None
        file = brand.site_styles / (client_id + ".css")
        if not file.is_file() or file.is_symlink():
            return None
        return file

    if brand.site_styles:
        @app.get("/brand/sites/<stylesheet>")
        async def client_css(request, stylesheet):
            file = site_css(stylesheet.removesuffix(".css")) if stylesheet.endswith(".css") else None
            if file is None:
                return response.empty(status=404)
            with file.open("rb") as stylesheet:
                data = stylesheet.read(128 * 1024 + 1)
            return (response.raw(data, content_type="text/css") if len(data) <= 128 * 1024
                    else response.empty(status=404))

    def page(name, **context):
        target = context.get("target", "")
        query = parse_qs(urlsplit(target).query)
        client_id = query.get("client_id", [""])[0]
        style = f"/brand/sites/{client_id}.css" if site_css(client_id) else None
        return response.html(TEMPLATES.get_template(name + ".html").render(
            brand=brand, site_style=style, passwords_enabled=passwords_enabled, **context,
        ))

    def start_password_session(db, request, person, target):
        result = response.redirect(target, status=303)
        new_session(db, result, person, cookie_value(request, SESSION_COOKIE), digest(target))
        return result

    passwords_enabled = register_passwords(app, store, page, local_target, start_password_session)

    @app.on_request
    async def guard(request):
        if request.headers.get("host") != host:
            return problem("Invalid host.", 400)
        if request.method == "POST" and request.path not in OIDC_POST:
            if request.headers.get("origin") != origin:
                return problem("Invalid request origin.", 403)
        request.ctx.session = None
        token = cookie_value(request, SESSION_COOKIE)
        if token:
            with store.connect() as db:
                request.ctx.session = get_session(db, digest(token))

    @app.on_response
    async def headers(request, result):
        result.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self'",
        )
        result.headers.setdefault("Referrer-Policy", "no-referrer")
        result.headers.update({
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Robots-Tag": "noindex, nofollow",
            "Strict-Transport-Security": "max-age=31536000",
        })

    @app.get("/")
    async def dashboard(request):
        person = request.ctx.session
        if not person:
            return page("signin", target="/", mode="login", enrolled=request.args.get("enrolled") == "1")
        with store.connect() as db:
            sites = db.execute(
                """SELECT id, name, launch FROM sites s WHERE enabled AND
                (? OR EXISTS (SELECT 1 FROM grants g WHERE g.person=? AND g.site=s.id))""",
                (person["owner"], person["id"]),
            ).fetchall()
        apps = [dict(site) for site in sorted(sites, key=lambda site: site["name"].translate(ASCII_LOWER))]
        if person["owner"]:
            registered = {site["launch"] for site in sites}
            apps.extend(dict(shortcut) for shortcut in shortcuts if shortcut["launch"] not in registered)
        for entry in apps:
            entry["icon"] = APP_ICONS.get(urlsplit(entry["launch"]).hostname, "app")
        return page("dashboard", person=person, sites=sorted(
            apps, key=lambda entry: entry["name"].casefold()))

    @app.get("/enroll")
    async def enroll(request):
        return page("signin", mode="invite", target="/")

    @app.get("/join")
    async def join(request):
        return page("signin", mode="signup", target="/")

    @app.post("/passkeys/<purpose>/begin")
    async def begin(request, purpose):
        data = request.json
        if not isinstance(data, dict):
            return problem("Invalid passkey request.")
        session = request.ctx.session
        handle = secrets.token_urlsafe(32)
        with store.connect(write=True) as db:
            if purpose == "login":
                subject = local_target(data.get("target"))
                options = generate_authentication_options(rp_id=rp_id, user_verification=UV)
            elif purpose in {"invite", "backup", "signup"}:
                if purpose in {"invite", "signup"}:
                    invite = data.get("invite", "")
                    if not isinstance(invite, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", invite):
                        return problem("This invitation is invalid or expired.", 403)
                    subject = digest(invite)
                    if purpose == "invite":
                        person = invited_person(db, subject)
                    else:
                        name, email = data.get("name"), data.get("email")
                        if not isinstance(name, str) or not isinstance(email, str):
                            return problem("Enter a name and email address.")
                        name, email = name.strip(), email.strip()
                        if not 1 <= len(name) <= 80 or not valid_email(email):
                            return problem("Enter a name and valid email address.")
                        if not open_signup(db, subject):
                            return problem("This sign-up link is invalid, expired, or full.", 403)
                        if person_by_email(db, email):
                            return problem("Use your existing passkey or ask the site owner for access.", 409)
                        person = {"id": str(uuid4()), "email": email, "name": name}
                else:
                    if not session or session["authenticated"] <= now() - FLOW_SECONDS:
                        return problem("Sign out and verify your existing passkey before adding a backup.", 403)
                    subject, person = session["session_token"], session
                if not person:
                    return problem("This invitation is invalid or expired.", 403)
                keys = db.execute("SELECT id FROM passkeys WHERE person=?", (person["id"],)).fetchall()
                options = generate_registration_options(
                    rp_id=rp_id, rp_name=brand.name, user_id=UUID(person["id"]).bytes,
                    user_name=person["email"], user_display_name=person["name"],
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UV,
                    ),
                    exclude_credentials=[PublicKeyCredentialDescriptor(id=row["id"]) for row in keys],
                )
            else:
                return problem("Unknown passkey operation.", 404)
            db.execute("DELETE FROM ceremonies WHERE expires<=? OR token=?",
                       (now(), digest(cookie_value(request, FLOW_COOKIE))))
            db.execute("INSERT INTO ceremonies VALUES (?, ?, ?, ?, ?)",
                       (digest(handle), options.challenge, purpose, subject, now() + FLOW_SECONDS))
            if purpose == "signup":
                db.execute("INSERT INTO pending_signups VALUES (?, ?, ?, ?, ?)",
                           (digest(handle), subject, person["id"], person["name"], person["email"]))
        result = response.json({"options": json.loads(options_to_json(options))})
        set_cookie(result, FLOW_COOKIE, handle, FLOW_SECONDS)
        return result

    @app.post("/passkeys/<purpose>/finish")
    async def finish(request, purpose):
        handle = digest(cookie_value(request, FLOW_COOKIE))
        with store.connect(write=True) as db:
            pending = (db.execute("SELECT * FROM pending_signups WHERE ceremony=?", (handle,)).fetchone()
                       if purpose == "signup" else None)
            flow = db.execute("DELETE FROM ceremonies WHERE token=? RETURNING *",
                              (handle,)).fetchone()
        if not flow or flow["purpose"] != purpose or flow["expires"] <= now():
            return problem("The passkey request has expired. Try again.", 403)
        data = request.json
        if not isinstance(data, dict) or not isinstance(data.get("credential"), dict):
            return problem("Invalid passkey response.")
        credential = data["credential"]
        try:
            if not top_level_credential(credential):
                return problem("Open the portal directly to use your passkey.", 403)
            with store.connect(write=True) as db:
                args = dict(credential=credential, expected_challenge=flow["challenge"],
                            expected_rp_id=rp_id, expected_origin=origin, require_user_verification=True)
                previous = cookie_value(request, SESSION_COOKIE)
                if purpose == "login":
                    raw_id = credential.get("rawId", "")
                    if not isinstance(raw_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", raw_id):
                        return problem("Passkey verification failed.", 403)
                    key_row = db.execute(
                        """SELECT k.* FROM passkeys k JOIN people p ON p.id=k.person
                        WHERE k.id=? AND p.enabled""", (base64url_to_bytes(raw_id),),
                    ).fetchone()
                    if not key_row:
                        return problem("Passkey verification failed.", 403)
                    assertion = credential.get("response")
                    handle = assertion.get("userHandle") if isinstance(assertion, dict) else None
                    if not isinstance(handle, str) or not compare_digest(
                        base64url_to_bytes(handle), UUID(key_row["person"]).bytes,
                    ):
                        return problem("Passkey verification failed.", 403)
                    checked = verify_authentication_response(
                        **args, credential_public_key=key_row["public_key"],
                        credential_current_sign_count=key_row["sign_count"],
                    )
                    db.execute("UPDATE passkeys SET sign_count=? WHERE id=?",
                               (checked.new_sign_count, key_row["id"]))
                    result = response.json({"next": flow["subject"]})
                    new_session(db, result, key_row["person"], previous, digest(flow["subject"]))
                else:
                    if purpose == "invite":
                        person = invited_person(db, flow["subject"])
                    elif purpose == "signup":
                        if not pending or pending["signup"] != flow["subject"]:
                            return problem("This sign-up request has expired. Try again.", 403)
                        signup = open_signup(db, pending["signup"])
                        if not signup:
                            return problem("This sign-up link is invalid, expired, or full.", 403)
                        person = {"id": pending["person"], "name": pending["name"], "email": pending["email"]}
                    else:
                        session = get_session(db, digest(previous))
                        person = (session if session and session["session_token"] == flow["subject"]
                                  and session["authenticated"] > now() - FLOW_SECONDS else None)
                    if not person:
                        return problem("This enrollment is invalid or expired.", 403)
                    checked = verify_registration_response(**args)
                    if purpose == "signup":
                        db.execute("INSERT INTO people (id, name, email) VALUES (?, ?, ?)",
                                   (person["id"], person["name"], person["email"]))
                        db.execute("INSERT INTO grants VALUES (?, ?)", (person["id"], signup["site"]))
                        db.execute("UPDATE signup_links SET remaining=remaining-1 WHERE token=?", (signup["token"],))
                        log(db, "Site self-signup", signup["site"])
                    db.execute("INSERT INTO passkeys VALUES (?, ?, ?, ?, ?, ?)", (
                        checked.credential_id, person["id"], checked.credential_public_key,
                        checked.sign_count, "Passkey", now(),
                    ))
                    db.execute("UPDATE people SET enrolled=1 WHERE id=?", (person["id"],))
                    result = response.json({"next": "/?enrolled=1" if purpose in {"invite", "signup"} else "/account"})
                    if purpose in {"invite", "signup"}:
                        if purpose == "invite":
                            db.execute("DELETE FROM invitations WHERE token=?", (flow["subject"],))
                        db.execute("DELETE FROM sessions WHERE token=?", (digest(previous),))
                        result.delete_cookie(SESSION_COOKIE, host_prefix=True)
                    log(db, "Passkey enrolled", person["email"])
        except (WebAuthnException, ValueError, TypeError, KeyError, StorageIntegrityError):
            return problem("Passkey verification failed. Try again.", 403)
        result.delete_cookie(FLOW_COOKIE, host_prefix=True)
        return result

    @app.get("/account")
    async def account(request):
        person = request.ctx.session
        if not person:
            return response.redirect("/")
        with store.connect() as db:
            count = db.execute("SELECT COUNT(*) AS total FROM passkeys WHERE person=?",
                               (person["id"],)).fetchone()["total"]
        return page("account", person=person, count=count)

    @app.post("/sign-out")
    async def sign_out(request):
        with store.connect(write=True) as db:
            db.execute("DELETE FROM sessions WHERE token=?", (digest(cookie_value(request, SESSION_COOKIE)),))
        result = response.redirect("/", status=303)
        result.delete_cookie(SESSION_COOKIE, host_prefix=True)
        return result

    @app.get("/.well-known/openid-configuration")
    async def discovery(request):
        endpoint_root = origin + (OKTA if okta_metadata else "")
        return response.json({
            "issuer": origin, "authorization_endpoint": endpoint_root + "/authorize",
            "token_endpoint": endpoint_root + "/token", "userinfo_endpoint": endpoint_root + "/userinfo",
            "jwks_uri": endpoint_root + ("/keys" if okta_metadata else "/jwks.json"),
            "response_types_supported": ["code"], "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": list(CLIENT_AUTH),
            "code_challenge_methods_supported": ["S256"], "scopes_supported": list(SCOPES),
            "claims_parameter_supported": False, "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "claims_supported": ["iss", "sub", "aud", "iat", "exp", "auth_time", "nonce",
                                 "at_hash", "name", "email", "email_verified"],
        })

    @app.get(OKTA + "/keys", name="okta_jwks")
    @app.get("/jwks.json")
    async def jwks(request):
        return response.json({"keys": [key.as_dict(kid=key.thumbprint(), use="sig", alg="RS256")]})

    @app.post(OKTA + "/authorize", name="okta_authorize_form")
    @app.post("/authorize")
    async def authorize_form(request):
        if (not is_form_encoded(request) or request.query_string
                or any(len(request.form.getlist(field)) != 1 for field in request.form)):
            return problem("Expected a form-encoded authorization request.")
        params = {field: request.form.get(field) for field in request.form if field in AUTHORIZATION_PARAMS}
        target = local_target(request.path + "?" + urlencode(params))
        return response.redirect(target, status=303) if target != "/" else problem("Invalid authorization request.")

    @app.get(OKTA + "/authorize", name="okta_authorize")
    @app.get("/authorize")
    async def authorize(request):
        target = local_target(request.path + "?" + request.query_string)
        if target == "/":
            return problem("Invalid authorization request.")
        snapshot = request.ctx.session
        with store.connect(write=True) as db:
            person = get_session(db, snapshot["session_token"]) if snapshot else None
            issuer = Server(db, origin, key)
            try:
                grant = issuer.get_consent_grant(request, end_user=person)
                client_id = grant.request.client.get_client_id()
                prompt = request.args.get("prompt", "")
                max_age = request.args.get("max_age")
                if "request" in request.args:
                    raise RequestNotSupportedError(redirect_uri=grant.redirect_uri)
                if "request_uri" in request.args:
                    raise RequestURINotSupportedError(redirect_uri=grant.redirect_uri)
                if (prompt not in {"", "none", "login"}
                        or request.args.get("response_mode", "query") != "query"
                        or (max_age is not None and not re.fullmatch(r"\d{1,9}", max_age))):
                    raise InvalidRequestError("Unsupported authorization parameter.",
                                              redirect_uri=grant.redirect_uri)
                if person and not can_access(db, person["id"], client_id):
                    return issuer.create_authorization_response(grant.request, grant=grant, grant_user=None)
                age = now() - person["authenticated"] if person else None
                max_age = int(max_age) if max_age is not None else None
                repeated_login = prompt == "login" or max_age == 0
                age_expired = person and max_age is not None and max_age > 0 and age > max_age
                fresh = person and age < 60 and person["fresh_for"] == digest(target)
                if not person or age_expired or (repeated_login and not fresh):
                    if prompt == "none":
                        raise LoginRequiredError(redirect_uri=grant.redirect_uri)
                    return page("signin", target=target, mode="login")
                if fresh:
                    db.execute("UPDATE sessions SET fresh_for='' WHERE token=?", (person["session_token"],))
                db.execute("DELETE FROM codes WHERE expires<=?", (now() - 300,))
                return issuer.create_authorization_response(grant.request, grant=grant, grant_user=person)
            except OAuth2Error as error:
                error.state = request.args.get("state")
                return issuer.handle_error_response(request, error)

    @app.post(OKTA + "/token", name="okta_token")
    @app.post("/token")
    async def token(request):
        if not is_form_encoded(request) or request.query_string:
            return problem("Expected a form-encoded request.")
        if request.headers.get("authorization") and (
            "client_id" in request.form or "client_secret" in request.form
        ):
            return problem("Use a single client authentication method.")
        with store.connect(write=True) as db:
            issuer = Server(db, origin, key)
            try:
                result = issuer.create_token_response(request)
                db.execute("DELETE FROM tokens WHERE expires<=?", (now(),))
                return result
            except OAuth2Error as error:
                return issuer.handle_error_response(request, error)

    @app.route(OKTA + "/userinfo", methods=["GET", "POST"], name="okta_userinfo")
    @app.route("/userinfo", methods=["GET", "POST"])
    async def userinfo(request):
        bearer = re.fullmatch(r"Bearer ([A-Za-z0-9_-]{43})", request.headers.get("authorization", ""), re.I)
        if bearer:
            with store.connect() as db:
                person = db.execute(
                    """SELECT p.*, t.scope FROM tokens t JOIN people p ON p.id=t.person
                    JOIN sites s ON s.id=t.site
                    WHERE t.token=? AND t.expires>? AND p.enabled AND s.enabled
                    AND (p.owner OR EXISTS (
                        SELECT 1 FROM grants g WHERE g.person=p.id AND g.site=s.id
                    ))""",
                    (digest(bearer[1]), now()),
                ).fetchone()
                if person:
                    return response.json(user_info(person, person["scope"]))
        return response.json({"error": "invalid_token"}, status=401,
                             headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})

    @app.get("/manage")
    async def manage(request):
        person = request.ctx.session
        if not person:
            return page("signin", mode="login", target="/manage")
        if not person["owner"]:
            return response.text("Owner sign-in required.", status=403)
        if request.args.get("verify") == "1":
            return page("signin", mode="verify", target="/manage")
        return management_page(store, person, page)

    @app.post("/manage")
    async def manage_action(request):
        person = request.ctx.session
        if not person or not person["owner"]:
            return response.text("Owner sign-in required.", status=403)
        return update_management(store, person, request.form, origin, page)

    return app


def management_page(store, person, page, *, notice=None, error=None, setup=None):
    with store.connect() as db:
        guests = db.execute("SELECT * FROM people WHERE NOT owner ORDER BY name").fetchall()
        sites = db.execute("SELECT id, name, launch, enabled FROM sites ORDER BY name").fetchall()
        signup_links = {row["site"]: row["remaining"] for row in db.execute(
            "SELECT site, remaining FROM signup_links WHERE expires>?", (now(),),
        )}
        grants = {(row["person"], row["site"]) for row in db.execute("SELECT * FROM grants")}
        audit = [dict(entry) for entry in db.execute(
            "SELECT event, detail, at FROM audit ORDER BY id DESC LIMIT 20",
        )]
        for entry in audit:
            at = entry.pop("at")
            entry["date"] = (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(at))
                             if -62167219200 <= at <= 253402300799 else None)
    result = page("manage", person=person, guests=guests, sites=sites, grants=grants, audit=audit,
                  notice=notice, error=error, setup=setup, signup_links=signup_links)
    if error:
        result.status = 400
    return result


def update_management(store, owner, form, origin, page):
    action = form.get("action")
    person, site = form.get("person", ""), form.get("site", "")
    notice = setup = None
    try:
        with store.connect(write=True) as db:
            confirmed = get_session(db, owner["session_token"])
            if not confirmed or not confirmed["owner"]:
                return response.text("Owner sign-in required.", status=403)
            if confirmed["authenticated"] <= now() - FLOW_SECONDS:
                return response.redirect("/manage?verify=1", status=303)
            guest = db.execute("SELECT * FROM people WHERE id=? AND NOT owner", (person,)).fetchone()
            app = db.execute("SELECT * FROM sites WHERE id=?", (site,)).fetchone()
            if action == "invite":
                name, email = form.get("name", "").strip(), form.get("email", "").strip()
                if not 1 <= len(name) <= 80 or not valid_email(email):
                    raise ValueError("Enter a name and a valid email address.")
                person = str(uuid4())
                db.execute("INSERT INTO people (id, name, email) VALUES (?, ?, ?)", (person, name, email))
                setup = ("Enrollment link", origin + "/enroll#" + issue_invite(db, person, 86400))
                log(db, "Guest invited", email)
            elif action == "reinvite" and guest and guest["enabled"]:
                if guest["enrolled"]:
                    raise ValueError("This guest is already enrolled. Use Reset passkeys for recovery.")
                setup = ("Enrollment link", origin + "/enroll#" + issue_invite(db, person, 86400))
                log(db, "Guest enrollment link issued", guest["email"])
            elif action == "reset-passkeys" and guest and guest["enabled"] and guest["enrolled"]:
                if form.get("confirm") != "yes":
                    raise ValueError("Confirm that the guest's old passkeys and sessions should be revoked.")
                setup = ("Recovery link", origin + "/enroll#" + reset_passkeys(db, person, guest["email"]))
            elif action == "cancel-invite" and guest:
                db.execute("DELETE FROM invitations WHERE person=?", (person,))
                log(db, "Guest invitation revoked", guest["email"])
                notice = "Invitation revoked."
            elif action == "create-site":
                name, launch, callback = (form.get(field, "").strip() for field in ("name", "launch", "callback"))
                if not 1 <= len(name) <= 80 or not valid_https(launch) or not valid_https(callback):
                    raise ValueError("Enter a name and two exact HTTPS URLs.")
                site, secret = secrets.token_urlsafe(18), secrets.token_urlsafe(32)
                db.execute("INSERT INTO sites (id, name, launch, callback, secret) VALUES (?, ?, ?, ?, ?)",
                           (site, name, launch, callback, digest(secret)))
                setup = ("Client secret", secret)
                notice = "Site created. Client ID " + site
                log(db, "Site created", name)
            elif action == "create-signup" and app and app["enabled"]:
                uses, hours = int(form.get("uses", "20")), int(form.get("hours", "168"))
                if not 1 <= uses <= 100 or not 1 <= hours <= 168:
                    raise ValueError("Use 1 to 100 sign-ups and 1 to 168 hours.")
                setup = ("Site sign-up link", origin + "/join#" + issue_signup_link(db, site, uses, hours))
                notice = "Sign-up enabled for " + app["name"]
                log(db, "Site sign-up link issued", app["name"])
            elif action == "cancel-signup" and app:
                db.execute("DELETE FROM signup_links WHERE site=?", (site,))
                notice = "Site sign-up link revoked."
                log(db, notice, app["name"])
            elif action in {"grant", "revoke"} and guest and app:
                if action == "grant":
                    existing = db.execute("SELECT 1 FROM grants WHERE person=? AND site=?", (person, site))
                    if existing.fetchone() is None:
                        db.execute("INSERT INTO grants VALUES (?, ?)", (person, site))
                    notice = "Site access granted."
                else:
                    for table in ("grants", "codes", "tokens"):
                        db.execute(f"DELETE FROM {table} WHERE person=? AND site=?", (person, site))
                    notice = "Site access revoked."
                log(db, notice, guest["email"] + " · " + app["name"])
            elif action in {"disable-person", "enable-person"} and guest:
                enabled = action == "enable-person"
                db.execute("UPDATE people SET enabled=? WHERE id=?", (enabled, person))
                if not enabled:
                    for table in ("sessions", "invitations", "codes", "tokens"):
                        db.execute(f"DELETE FROM {table} WHERE person=?", (person,))
                notice = "Guest enabled." if enabled else "Guest disabled."
                log(db, notice, guest["email"])
            elif action in {"disable-site", "enable-site"} and app:
                enabled = action == "enable-site"
                db.execute("UPDATE sites SET enabled=? WHERE id=?", (enabled, site))
                if not enabled:
                    db.execute("DELETE FROM codes WHERE site=?", (site,))
                    db.execute("DELETE FROM tokens WHERE site=?", (site,))
                    db.execute("DELETE FROM signup_links WHERE site=?", (site,))
                notice = "Site enabled." if enabled else "Site disabled."
                log(db, notice, app["name"])
            else:
                raise ValueError("This action is unavailable.")
    except ValueError as error:
        return management_page(store, owner, page, error=str(error))
    except StorageIntegrityError:
        return management_page(store, owner, page, error="A guest with that email already exists.")
    if setup:
        return management_page(store, owner, page, setup=setup, notice=notice)
    return response.redirect("/manage", status=303)
