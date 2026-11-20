# ntka

A self-hosted Sanic identity provider for a single owner and invited guests. Passkeys belong to individual accounts. A guest sees and can sign in to only the sites the owner grants them. Obscuretone Identity is the first deployment.

## Run locally or behind an HTTPS proxy

Use Python 3.11 or newer, SQLite 3.35 or newer, and a trusted HTTPS origin. Set the reverse proxy to pass your configured host, forward to loopback, and leave authorization and token URLs out of access logs.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export IDENTITY_ORIGIN=https://login.example.com
export IDENTITY_DATA=/path/to/private/identity-state
.venv/bin/python -m identity init
.venv/bin/python -m identity serve --port 8799
```

Keep the origin stable. WebAuthn credentials are bound to its hostname, and relying parties use it as the OpenID Connect issuer. The process serves one Sanic worker and stores identity state on local disk. Run initialization and owner commands as the service user with the same environment and working directory.

The included Debian deployment uses systemd, nginx, Certbot, and two DNS names pointed at the server. The provided configuration targets Obscuretone. For another installation, substitute your hostnames, state paths, and TLS conventions before running the installer. The Certbot flow expects an existing ACME account and nginx TLS options under `/etc/letsencrypt`.

The included updater handles code-only changes when the installed dependencies and proxy configuration match the checkout. It preserves the database and keeps the previous code available for rollback. Back up state before upgrading dependencies or deployment settings.

## Branding

Set `IDENTITY_NAME` for page titles and the WebAuthn display name. Set `IDENTITY_WORDMARK` for the text in the header. Set `IDENTITY_LOGO_FILE` to the absolute path of a service-readable SVG, PNG, WebP, or ICO file up to 512 KiB. An uploaded logo file is used in the header and as the browser favicon. Restart the service after changing branding. The configured issuer hostname and passkey relying-party ID are independent of these display settings.

## Enroll the owner and invite guests

```sh
.venv/bin/python -m identity owner-invite --name 'Owner' --email owner@example.com
```

Open the 15-minute enrollment link on your own device, register a passkey, and sign in. Under **Account**, add a backup passkey after confirming the existing one. The owner can invite guests, register OIDC clients, and change access in **Administration** at `/manage`. Administrative mutations require a passkey sign-in from the last five minutes.

Guest enrollment links work once and expire after 24 hours. Share them privately. For a guest who loses their passkey, the owner can reset the guest's passkeys from Administration. This revokes all of the guest's passkeys, provider sessions, and tokens, and issues a 15-minute replacement enrollment link.

Owner recovery requires local server access. This command revokes the previous passkeys, provider sessions, and tokens and prints a one-time replacement link.

```sh
.venv/bin/python -m identity recover --email owner@example.com --revoke-all-passkeys
```

## Connect a site

1. Register the site in **Administration** with its HTTPS launch URL and the exact OIDC callback URL documented by the site or its authentication proxy.
2. Configure the site using the issuer, the ID and one-time client secret shown at creation, and scopes `openid profile email` as needed. Enable Authorization Code flow with S256 PKCE and `client_secret_basic` or `client_secret_post`.
3. Grant access individually and test both an allowed and an unassigned account against the direct site URL.

The supported discovery endpoint is `/.well-known/openid-configuration`. Set relying-party policy using the immutable `sub` claim. The owner enters account email addresses and the provider reports `email_verified: false`.

Revoking a grant invalidates provider-side codes and opaque access tokens immediately. Relying parties control their own issued browser sessions and can keep them until their configured expiry. Plan their session lifetime and termination behavior accordingly. The current profile uses confidential clients, RS256 ID tokens, five-minute access tokens, and no refresh grant or federated logout.

## Verification and operations

```sh
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
```

The integration tests simulate a WebAuthn authenticator and verify its signed assertions, validate an ID token against JWKS, and exercise admin access, per-site authorization and revocation, code replay, and guest recovery. Formal OpenID Foundation conformance testing is a separate step.

Back up the database using SQLite's backup API or while the service is stopped. Retain `signing.pem` and the database together in encrypted, access-controlled storage. Treat invitation links and client secrets as credentials. The repository contains source and sample configuration. Keep live signing material and identity state outside the checkout.
