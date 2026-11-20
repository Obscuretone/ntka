#!/bin/bash
set -euo pipefail

base=/opt/obscuretone-identity
service=obscuretone-identity.service
host=login.obscuretone.com
if [[ "$(id -u)" != 0 ]]; then
    echo "Run this update as root." >&2
    exit 1
fi
exec 9>/run/lock/obscuretone-identity-install.lock
flock -n 9
systemctl is-active --quiet "$service"
cmp requirements.txt "$base/requirements.txt"
for config in admin.http admin.https proxy.conf obscuretone-identity.service; do
    cmp "deploy/$config" "$base/deploy/$config"
done

release=$(mktemp -d "$base/.update.XXXXXX")
cp -r identity "$release/new"
previous="$release/previous"
rollback() {
    status=$?
    if (( status != 0 )) && [[ -d "$previous" ]]; then
        if [[ -d "$base/identity" ]]; then
            mv "$base/identity" "$release/failed"
        fi
        mv "$previous" "$base/identity"
        systemctl restart "$service"
        echo "The previous release was restored." >&2
    fi
}
trap rollback EXIT
mv "$base/identity" "$previous"
mv "$release/new" "$base/identity"
systemctl restart "$service"
curl --retry 5 --retry-all-errors --retry-delay 1 --max-time 5 -fsS \
    --resolve "$host:443:127.0.0.1" "https://$host/.well-known/openid-configuration" >/dev/null
printf 'Updated https://%s/\n' "$host"
