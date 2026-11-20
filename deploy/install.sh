#!/bin/bash
set -euo pipefail

base=/opt/obscuretone-identity
unit=/etc/systemd/system/obscuretone-identity.service
vhost=/etc/nginx/sites-available/obscuretone-identity
enabled=/etc/nginx/sites-enabled/obscuretone-identity
hook=/etc/letsencrypt/renewal-hooks/deploy/obscuretone-identity-nginx
host=login.obscuretone.com
admin=admin.obscuretone.com
webroot=/var/www/obscuretone-identity-acme

if [[ "$(id -u)" != 0 ]]; then
    echo "Run this installer as root." >&2
    exit 1
fi
exec 9>/run/lock/obscuretone-identity-install.lock
flock -n 9
for target in "$unit" "$vhost" "$enabled" "$hook" \
    /etc/nginx/sites-available/admin.obscuretone.com /etc/nginx/sites-available/login.obscuretone.com; do
    if [[ -e "$target" || -L "$target" ]]; then
        echo "Installation stopped because $target already exists." >&2
        exit 1
    fi
done
if [[ -e "$base" ]]; then
    if [[ "${1:-}" != "--resume" || -L "$base" || ! -f "$base/deploy/obscuretone-identity.service" ]]; then
        echo "Existing code directory detected. Use --resume for this installer's interrupted release." >&2
        exit 1
    fi
fi
if ss -H -ltn 'sport = :8799' | grep -q .; then
    echo "Port 8799 is occupied." >&2
    exit 1
fi

rollback() {
    status=$?
    if (( status != 0 )); then
        if [[ -L "$enabled" ]]; then
            rm -f -- "$enabled" "$vhost" "$hook"
            nginx -t && systemctl reload nginx
        fi
        if [[ -f "$unit" ]]; then
            systemctl disable --now obscuretone-identity.service || true
            rm -f -- "$unit"
            systemctl daemon-reload
        fi
        echo "Deployment stopped. The unpacked release is retained at $base." >&2
    fi
}
trap rollback EXIT

install -d -m 0755 "$base" "$webroot"
cp -r identity requirements.txt deploy "$base/"
cd "$base"
python3 -m venv .venv
.venv/bin/pip --disable-pip-version-check --no-cache-dir install -q -r requirements.txt
install -m 0644 deploy/obscuretone-identity.service "$unit"
systemctl daemon-reload
systemctl start obscuretone-identity.service
curl --retry 4 --retry-connrefused --max-time 5 -fsS -H "Host: $host" \
    http://127.0.0.1:8799/.well-known/openid-configuration >/dev/null

install -m 0644 deploy/admin.http "$vhost"
ln -s "$vhost" "$enabled"
nginx -t
systemctl reload nginx
certbot certonly --non-interactive --agree-tos --webroot --webroot-path "$webroot" \
    --cert-name "$host" --domains "$host,$admin" --keep-until-expiring
cat deploy/admin.http deploy/admin.https > "$vhost"
nginx -t
systemctl reload nginx
install -m 0755 deploy/renew-nginx "$hook"
curl --retry 5 --retry-all-errors --retry-delay 1 --max-time 5 -fsS --resolve "$host:443:127.0.0.1" \
    "https://$host/.well-known/openid-configuration" >/dev/null
redirect=$(curl --retry 3 --retry-all-errors --retry-delay 1 --max-time 5 -fsS \
    --resolve "$admin:443:127.0.0.1" -o /dev/null -w '%{http_code} %{redirect_url}' "https://$admin/")
[[ "$redirect" == "308 https://$host/manage" ]]
systemctl enable obscuretone-identity.service
printf 'Live at https://%s/\n' "$host"
