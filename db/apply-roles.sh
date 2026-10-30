#!/bin/sh
# Runs db/roles.sql as the database administrator over the database's own socket,
# with the logins' passwords from the environment (OWNER_PASSWORD, APP_PASSWORD;
# ADMIN_PASSWORD for the administrator). docker-compose.yml's db-roles service
# runs it on every start. DB_NAME defaults to bastion.
set -eu

# A password as a MySQL string literal: backslashes and quotes doubled, so no
# password can end the string early.
quote() {
  escaped=$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/''/g")
  # A failed escape must stop here, not quietly become an empty password.
  [ -n "$escaped" ] || { echo "apply-roles: could not quote a password" >&2; exit 1; }
  printf "'%s'" "$escaped"
}

# An empty password would unlock the login with no password at all.
[ -n "${OWNER_PASSWORD:-}" ] || { echo "apply-roles: OWNER_PASSWORD is empty" >&2; exit 1; }
[ -n "${APP_PASSWORD:-}" ] || { echo "apply-roles: APP_PASSWORD is empty" >&2; exit 1; }

owner=$(quote "$OWNER_PASSWORD")
app=$(quote "$APP_PASSWORD")
init="SET @owner_password = $owner, @app_password = $app"
MYSQL_PWD="$ADMIN_PASSWORD" exec mysql --protocol=socket -uroot --init-command="$init" "${DB_NAME:-bastion}" < /bastion/roles.sql
