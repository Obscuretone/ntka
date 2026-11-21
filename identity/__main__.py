import argparse
import os
from urllib.parse import urlsplit

from .app import create_app, valid_email, valid_https
from .storage import Store


def main():
    parser = argparse.ArgumentParser(description="ntka · OpenID Connect identity provider")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    owner = commands.add_parser("owner-invite")
    owner.add_argument("--name", required=True)
    owner.add_argument("--email", required=True)
    recover = commands.add_parser("recover")
    recover.add_argument("--email", required=True)
    recover.add_argument("--revoke-all-passkeys", action="store_true", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8799)
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(os.environ.get("IDENTITY_DATA", "instance"))
    if args.command == "init":
        store.initialize()
    elif args.command in {"owner-invite", "recover"}:
        origin = os.environ.get("IDENTITY_ORIGIN", "")
        if not valid_https(origin) or origin != "https://" + urlsplit(origin).netloc:
            parser.error("Set IDENTITY_ORIGIN to the exact HTTPS issuer origin.")
        if not valid_email(args.email):
            parser.error("Enter a valid account email.")
        try:
            if args.command == "recover":
                token = store.recover(args.email)
            else:
                if not 1 <= len(args.name.strip()) <= 80:
                    parser.error("Enter a valid name.")
                token = store.owner_invite(args.name.strip(), args.email)
        except ValueError as error:
            parser.error(str(error))
        print(origin + "/enroll#" + token)
    else:
        create_app().run(host="127.0.0.1", port=args.port, single_process=True, access_log=False)


if __name__ == "__main__":
    main()
