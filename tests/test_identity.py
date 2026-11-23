import base64
import hashlib
import json
import os
import re
import secrets
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from joserfc import jwt
from joserfc.jwk import KeySet
from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient

from identity.app import create_app
from identity.storage import Store, digest, now, person_by_email


ORIGIN = "https://admin.example.com"
RP = urlsplit(ORIGIN).hostname
USER_AGENT = {"Origin": ORIGIN}
SITE_A = "https://site-a.example.com"
SITE_B = "https://site-b.example.com"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def callback(response, key):
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return query[key][0]


class VirtualPasskey:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = secrets.token_bytes(32)
        self.sign_count = 0

    def credential(self, options, enrollment):
        challenge = options["challenge"]
        action = "webauthn.create" if enrollment else "webauthn.get"
        client_data = json.dumps({"type": action, "origin": ORIGIN, "challenge": challenge}).encode()
        auth = hashlib.sha256(RP.encode()).digest()
        if enrollment:
            self.handle = options["user"]["id"]
            numbers = self.key.public_key().public_numbers()
            cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
                                -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
            auth += b"\x45" + bytes(4 + 16) + struct.pack(">H", len(self.id)) + self.id + cose
            result = {"attestationObject": b64(cbor2.dumps(
                {"fmt": "none", "authData": auth, "attStmt": {}},
            ))}
        else:
            self.sign_count += 1
            auth += b"\x05" + struct.pack(">I", self.sign_count)
            signed = self.key.sign(auth + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
            result = {"authenticatorData": b64(auth), "signature": b64(signed), "userHandle": self.handle}
        result["clientDataJSON"] = b64(client_data)
        return {"id": b64(self.id), "rawId": b64(self.id), "type": "public-key", "response": result}


class IdentityTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.initialize()
        self.app = create_app(ORIGIN, self.directory.name)
        self.addCleanup(Sanic.unregister_app, self.app)
        self.client = SanicASGITestClient(self.app, base_url=ORIGIN)

    async def call_api(self, method, path, **kwargs):
        kwargs.setdefault("headers", USER_AGENT)
        location = ORIGIN + path
        _, result = await getattr(self.client, method)(location, follow_redirects=False, **kwargs)
        return result

    async def enroll(self, invite):
        key = VirtualPasskey()
        begin = await self.call_api("post", "/passkeys/invite/begin", json={"invite": invite})
        self.assertEqual(begin.status_code, 200, begin.text)
        credential = key.credential(begin.json["options"], enrollment=True)
        finish = await self.call_api("post", "/passkeys/invite/finish", json={"credential": credential})
        self.assertEqual(finish.status_code, 200, finish.text)
        self.assertNotIn("__Host-obscuretone_session", self.client.cookies)
        replay = await self.call_api("post", "/passkeys/invite/begin", json={"invite": invite})
        self.assertEqual(replay.status_code, 403)
        return key

    async def login(self, key):
        begin = await self.call_api("post", "/passkeys/login/begin", json={})
        self.assertEqual(begin.status_code, 200, begin.text)
        credential = key.credential(begin.json["options"], enrollment=False)
        finish = await self.call_api("post", "/passkeys/login/finish", json={"credential": credential})
        self.assertEqual(finish.status_code, 200, finish.text)
        self.assertIn("__Host-obscuretone_session", self.client.cookies)
        replay = await self.call_api("post", "/passkeys/login/finish", json={"credential": credential})
        self.assertEqual(replay.status_code, 403)

    async def test_branding_is_configurable_and_escaped(self):
        logo = Path(self.directory.name) / "logo.svg"
        contents = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
        logo.write_bytes(contents)
        styles = Path(self.directory.name) / "site-styles"
        styles.mkdir()
        (styles / "guest-site.css").write_text(".gate { color: green; }")
        theme = styles / "theme.css"
        theme.write_text(":root { --accent: blue; }")
        Sanic.unregister_app(self.app)
        with patch.dict(os.environ, {
            "IDENTITY_NAME": "Studio <Identity>",
            "IDENTITY_WORDMARK": "<studio>",
            "IDENTITY_LOGO_FILE": str(logo),
            "IDENTITY_CSS_FILE": str(theme),
            "IDENTITY_SITE_CSS_DIR": str(styles),
        }):
            app = create_app(ORIGIN, self.directory.name)
        self.addCleanup(Sanic.unregister_app, app)
        self.client = SanicASGITestClient(app, base_url=ORIGIN)
        home = await self.call_api("get", "/")
        self.assertIn("Studio &lt;Identity&gt;", home.text)
        self.assertIn("&lt;studio&gt;", home.text)
        self.assertIn('rel="icon" href="/brand/logo"', home.text)
        self.assertIn('href="/brand/site.css"', home.text)
        css = await self.call_api("get", "/brand/sites/guest-site.css")
        self.assertEqual(css.text, ".gate { color: green; }")
        self.assertTrue(css.headers["content-type"].startswith("text/css"))
        self.assertEqual((await self.call_api("get", "/brand/sites/unknown.css")).status_code, 404)
        image = await self.call_api("get", "/brand/logo")
        self.assertEqual(image.content, contents)
        self.assertEqual(image.headers["content-type"], "image/svg+xml")
        self.assertIn("sandbox", image.headers["content-security-policy"])
        self.assertEqual((await self.call_api("get", "/brand/logo/")).status_code, 404)
        self.assertEqual((await self.call_api("get", "/favicon.ico")).headers["location"], "/brand/logo")

    async def test_owner_guest_and_oidc(self):
        owner = await self.enroll(self.store.owner_invite("Owner", "owner@example.com"))
        await self.login(owner)
        self.assertEqual((await self.call_api("get", "/manage")).status_code, 200)
        reject_csrf = await self.call_api("post", "/manage", headers={"Origin": SITE_A},
                                          data={"action": "invite"})
        self.assertEqual(reject_csrf.status_code, 403)
        invite_page = await self.call_api("post", "/manage", data={
            "action": "invite", "name": "Guest", "email": "guest@example.com",
        })
        invite = re.search(r"/enroll#([A-Za-z0-9_-]{43})", invite_page.text)[1]
        clients = {}
        for name, url in [("Site A", SITE_A), ("Site B", SITE_B)]:
            created = await self.call_api("post", "/manage", data={
                "action": "create-site", "name": name, "launch": url, "callback": url + "/callback",
            })
            self.assertEqual(created.status_code, 200, created.text)
            client_id = re.search(r"Site created\. Client ID ([A-Za-z0-9_-]{24})", created.text)[1]
            secret = re.search(r'Client secret <input readonly value="([A-Za-z0-9_-]{43})"', created.text)[1]
            clients[name] = (client_id, secret)
        site_a, secret = clients["Site A"]
        site_b, _ = clients["Site B"]
        with self.store.connect() as db:
            person = db.execute("SELECT id FROM people WHERE NOT owner").fetchone()["id"]
        granted = await self.call_api("post", "/manage",
                                      data={"action": "grant", "person": person, "site": site_a})
        self.assertEqual(granted.status_code, 303)
        await self.call_api("post", "/sign-out")
        guest = await self.enroll(invite)
        await self.login(guest)
        dashboard = (await self.call_api("get", "/")).text
        self.assertIn(SITE_A, dashboard)
        self.assertNotIn(SITE_B, dashboard)
        self.assertEqual((await self.call_api("get", "/manage")).status_code, 403)
        self.assertEqual((await self.call_api("post", "/manage", data={
            "action": "grant", "person": person, "site": site_b,
        })).status_code, 403)

        verifier = secrets.token_urlsafe(48)
        query = {
            "client_id": site_a, "redirect_uri": SITE_A + "/callback", "response_type": "code",
            "scope": "openid profile email", "state": "browser-correlation",
            "nonce": "session-correlation", "code_challenge_method": "S256",
            "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
        }
        denied = await self.call_api("get", "/authorize?" + urlencode({
            **query, "client_id": site_b, "redirect_uri": SITE_B + "/callback",
        }))
        self.assertEqual(callback(denied, "error"), "access_denied")
        bad_url = await self.call_api("get", "/authorize?" + urlencode({
            **query, "redirect_uri": SITE_A + "/other",
        }))
        self.assertEqual(bad_url.status_code, 400)
        self.assertNotIn("location", bad_url.headers)
        bad_pkce = await self.call_api("get", "/authorize?" + urlencode({
            **query, "code_challenge_method": "plain",
        }))
        self.assertEqual(callback(bad_pkce, "error"), "invalid_request")
        submitted = await self.call_api("post", "/authorize", headers={"Origin": SITE_A}, data=query)
        self.assertEqual(submitted.status_code, 303)
        approved = await self.call_api("get", submitted.headers["location"])
        code = callback(approved, "code")
        self.assertEqual(callback(approved, "state"), query["state"])
        exchange = {
            "grant_type": "authorization_code", "redirect_uri": query["redirect_uri"],
            "code": code, "code_verifier": verifier,
        }
        invalid = await self.call_api("post", "/token", data={**exchange, "code_verifier": "x" * 43},
                                      auth=(site_a, secret))
        self.assertEqual(invalid.json["error"], "invalid_grant")
        good = await self.call_api("post", "/token", data=exchange, auth=(site_a, secret))
        self.assertEqual(good.status_code, 200, good.text)
        contents = good.json
        keys = (await self.call_api("get", "/jwks.json")).json
        self.assertNotIn("d", keys["keys"][0])
        claims = jwt.decode(contents["id_token"], KeySet.import_key_set(keys), ["RS256"]).claims
        self.assertEqual(claims["iss"], ORIGIN)
        self.assertEqual(claims["aud"], [site_a])
        self.assertEqual(claims["sub"], person)
        self.assertEqual(claims["nonce"], query["nonce"])
        self.assertEqual(claims["email_verified"], False)
        bearer = {"Authorization": "Bearer " + contents["access_token"]}
        self.assertEqual((await self.call_api("post", "/userinfo", headers=bearer)).json["sub"], person)
        with self.store.connect(write=True) as db:
            db.execute("UPDATE codes SET expires=expires-180")
        replay = await self.call_api("post", "/token", data=exchange, auth=(site_a, secret))
        self.assertEqual(replay.json["error"], "invalid_grant")
        self.assertEqual((await self.call_api("get", "/userinfo", headers=bearer)).status_code, 401)
        second_code = callback(await self.call_api("get", "/authorize?" + urlencode(
            {**query, "nonce": "second-exchange"},
        )), "code")
        exchanged = await self.call_api("post", "/token", data={
            **exchange, "code": second_code, "client_id": site_a, "client_secret": secret,
        })
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        bearer = {"Authorization": "Bearer " + exchanged.json["access_token"]}

        code_before_revoke = callback(await self.call_api("get", "/authorize?" + urlencode(
            {**query, "nonce": "new-correlation"},
        )), "code")
        await self.call_api("post", "/sign-out")
        await self.login(owner)
        revoked = await self.call_api("post", "/manage",
                                      data={"action": "revoke", "person": person, "site": site_a})
        self.assertEqual(revoked.status_code, 303)
        self.assertEqual((await self.call_api("get", "/userinfo", headers=bearer)).status_code, 401)
        wrong = await self.call_api("post", "/token", data={**exchange, "code": code_before_revoke},
                                    auth=(site_a, secret))
        self.assertEqual(wrong.json["error"], "invalid_grant")
        await self.call_api("post", "/sign-out")
        await self.login(guest)
        self.assertIn("No apps yet", (await self.call_api("get", "/")).text)

        await self.call_api("post", "/sign-out")
        owner_landing = await self.call_api("get", "/manage")
        self.assertIn('data-target="/manage"', owner_landing.text)
        await self.login(owner)
        with self.store.connect(write=True) as db:
            db.execute("UPDATE sessions SET authenticated=authenticated-301")
        reset = {"action": "reset-passkeys", "person": person, "confirm": "yes"}
        stale_owner = await self.call_api("post", "/manage", data=reset)
        self.assertEqual(stale_owner.headers["location"], "/manage?verify=1")
        await self.login(owner)
        recovered = await self.call_api("post", "/manage", data=reset)
        self.assertIn("Recovery link", recovered.text)
        replacement = re.search(r"/enroll#([A-Za-z0-9_-]{43})", recovered.text)[1]
        preempt = await self.call_api("post", "/manage", data={"action": "reinvite", "person": person})
        self.assertEqual(preempt.status_code, 400)
        await self.call_api("post", "/sign-out")
        challenge = await self.call_api("post", "/passkeys/login/begin", json={})
        old = await self.call_api("post", "/passkeys/login/finish", json={
            "credential": guest.credential(challenge.json["options"], enrollment=False),
        })
        self.assertEqual(old.status_code, 403)
        new_guest = await self.enroll(replacement)
        await self.login(new_guest)

    @unittest.skipUnless(os.environ.get("NTKA_TEST_MARIADB"), "requires an empty MariaDB fixture database")
    async def test_sqlite_migration_preserves_identity_and_session(self):
        from identity.mariadb_store import MariaDBStore
        from identity.migrate_mariadb import migrate_sqlite

        owner = await self.enroll(self.store.owner_invite("Owner", "OWNER@example.com"))
        await self.login(owner)
        cookie = self.client.cookies["__Host-obscuretone_session"]
        keys = (await self.call_api("get", "/jwks.json")).json
        with self.store.connect(write=True) as db:
            person = person_by_email(db, "owner@example.com")["id"]
            db.execute("INSERT INTO people (id, name, email) VALUES (?, ?, ?)",
                       ("guest-1", "Guest", "É@example.com"))
            db.execute("INSERT INTO people (id, name, email) VALUES (?, ?, ?)",
                       ("guest-2", "Guest", "é@example.com"))
            db.execute("INSERT INTO sites (id, name, launch, callback, secret) VALUES (?, ?, ?, ?, ?)",
                       ("x" * 256, "Import failure fixture", SITE_A, SITE_A + "/callback", "fixture"))
        target_directory = Path(self.directory.name) / "mariadb"
        wrong_key = Store(target_directory)
        wrong_key.initialize()
        target = MariaDBStore.from_environment(target_directory)
        with self.assertRaisesRegex(ValueError, "original signing key"):
            migrate_sqlite(self.directory.name, target)
        target.keyfile.write_bytes(self.store.keyfile.read_bytes())
        with self.assertRaisesRegex(ValueError, "could not import or verify sites"):
            migrate_sqlite(self.directory.name, target)
        with target.raw_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM people")
            self.assertEqual(cursor.fetchone()["total"], 0)
            cursor.execute("SELECT signing_fingerprint FROM identity_storage WHERE id=1")
            self.assertIsNone(cursor.fetchone()["signing_fingerprint"])

        with self.store.connect(write=True) as db:
            db.execute("UPDATE sites SET id=?", ("site-fixture",))
            db.execute("INSERT INTO grants VALUES (?, ?)", ("guest-1", "site-fixture"))
            db.execute("INSERT INTO ceremonies VALUES (?, ?, ?, ?, ?)",
                       ("ceremony-fixture", bytes(range(32)), "signup", "/", now() + 300))
            db.execute("INSERT INTO pending_signups VALUES (?, ?, ?, ?, ?)",
                       ("ceremony-fixture", "signup-fixture", "new-person", "Pending", "pending@example.com"))
        counts = migrate_sqlite(self.directory.name, target)
        self.assertEqual(counts["passkeys"], 1)
        self.assertEqual(counts["sessions"], 1)
        self.assertEqual(counts["pending_signups"], 1)
        with self.assertRaisesRegex(ValueError, "already been migrated"):
            migrate_sqlite(self.directory.name, target)
        with target.connect(write=True) as db:
            self.assertEqual(person_by_email(db, "owner@example.com")["id"], person)
            self.assertEqual(person_by_email(db, "É@EXAMPLE.COM")["id"], "guest-1")
            self.assertEqual(person_by_email(db, "é@EXAMPLE.COM")["id"], "guest-2")
            self.assertEqual(db.execute("SELECT person FROM sessions WHERE token=?", (digest(cookie),))
                             .fetchone()["person"], person)
            db.execute("DELETE FROM ceremonies WHERE token=? RETURNING *", ("ceremony-fixture",)).fetchone()
            self.assertIsNone(db.execute("SELECT * FROM pending_signups").fetchone())

        Sanic.unregister_app(self.app)
        with patch.dict(os.environ, {"IDENTITY_STORAGE": "mariadb"}):
            app = create_app(ORIGIN, target_directory)
        self.addCleanup(Sanic.unregister_app, app)
        self.client = SanicASGITestClient(app, base_url=ORIGIN)
        self.assertEqual((await self.call_api("get", "/jwks.json")).json, keys)
        headers = {**USER_AGENT, "Cookie": "__Host-obscuretone_session=" + cookie}
        self.assertEqual((await self.call_api("get", "/manage", headers=headers)).status_code, 200)
        await self.login(owner)
        with target.connect() as db:
            self.assertEqual(db.execute("SELECT sign_count FROM passkeys").fetchone()["sign_count"], 2)


if __name__ == "__main__":
    unittest.main()
