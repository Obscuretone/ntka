import hashlib
import os
import tempfile
import unittest
import re
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient

from identity.app import create_app
from identity.storage import Store
from test_identity import ORIGIN, USER_AGENT, SITE_A, b64


class PasswordSignupTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.initialize()
        mail = Path(self.directory.name) / "queued.eml"
        sender = Path(self.directory.name) / "sendmail"
        sender.write_text(f'#!/bin/sh\ncat > "{mail}"\n')
        sender.chmod(0o700)
        self.mail = mail
        with patch.dict(os.environ, {"IDENTITY_SENDMAIL": str(sender), "IDENTITY_MAIL_FROM": "accounts@example.test",
                                     "IDENTITY_OKTA_ENDPOINTS": "1"}):
            self.app = create_app(ORIGIN, self.directory.name)
        self.addCleanup(Sanic.unregister_app, self.app)
        self.client = SanicASGITestClient(self.app, base_url=ORIGIN)

    async def call_api(self, method, path, **kwargs):
        _, result = await getattr(self.client, method)(ORIGIN + path, follow_redirects=False, **kwargs)
        return result

    async def form(self, path, data, **kwargs):
        headers = {**USER_AGENT, "Content-Type": "application/x-www-form-urlencoded", **kwargs.pop("headers", {})}
        return await self.call_api("post", path, data=urlencode(data), headers=headers, **kwargs)

    async def test_registration_verifies_email_and_requires_explicit_site_grant(self):
        email = "guest@example.test"
        password = "An isolated fixture password"
        self.store.owner_invite("Owner", "owner@example.test")
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO sites (id, name, launch, callback, secret) VALUES (?, ?, ?, ?, ?)",
                       ("private", "Private app", SITE_A, SITE_A + "/callback", "fixture"))
        configuration = await self.call_api("get", "/.well-known/openid-configuration")
        assert configuration.json["issuer"] == ORIGIN
        assert configuration.json["token_endpoint"] == ORIGIN + "/oauth2/v1/token"
        assert (await self.call_api("get", "/oauth2/v1/keys")).json["keys"]
        target = "/oauth2/v1/authorize?" + urlencode({
            "client_id": "private", "redirect_uri": SITE_A + "/callback", "response_type": "code",
            "scope": "openid email", "state": "fixture", "code_challenge_method": "S256",
            "code_challenge": b64(hashlib.sha256(b"fixture").digest()),
        })
        start = await self.form("/password/signup", {"email": email, "next": target})
        assert start.status == 200 and "Verify your email" in start.text
        code = re.search(r"^[A-Za-z0-9_-]{43}$", self.mail.read_text(), re.MULTILINE)[0]
        data = {"email": email, "password": password, "code": code, "name": "Guest", "next": target}
        assert (await self.form("/password/verify", {**data, "email": "owner@example.test"})).status == 400
        completed = await self.form("/password/verify", data)
        assert completed.status == 303 and completed.headers["location"] == target
        assert (await self.form("/password/verify", data)).status == 400
        signed_in = await self.form("/password/sign-in", {"email": email, "password": password})
        cookie = signed_in.cookies["__Host-obscuretone_session"]
        headers = {"Cookie": "__Host-obscuretone_session=" + cookie}
        assert (await self.call_api("get", "/manage", headers=headers)).status == 403
        refused = await self.call_api("get", target, headers=headers)
        assert "error=access_denied" in refused.headers["location"]
        with self.store.connect(write=True) as db:
            guest = db.execute("SELECT * FROM people WHERE email=?", (email,)).fetchone()
            assert guest["email_verified"] == 1 and guest["owner"] == 0
            db.execute("INSERT INTO grants VALUES (?, ?)", (guest["id"], "private"))
        approved = await self.call_api("get", target, headers=headers)
        assert "code=" in approved.headers["location"]
        assert (await self.form("/password/sign-in", {"email": "owner@example.test", "password": password})).status == 401
