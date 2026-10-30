#!/bin/sh
# Checks that a running `docker compose --profile full` stack is as hardened as
# docker-compose.yml says: what the site serves, what it refuses, what each
# container can reach, how the app signs in to the database, and the runtime
# restrictions on every container. A restriction that is written down is not one
# that holds; this is what CI runs before an image could be published.
#
#   docker compose --profile full up -d --build --wait
#   scripts/verify-stack.sh                # exits non-zero on any failure
#
# Environment: COMPOSE (default "docker compose --profile full"; add -p/--env-file),
# SITE (default http://127.0.0.1:${WEB_PORT:-8081}), DB_PORT, DB_ADMIN_PASSWORD,
# DB_PASS — the same variables docker-compose.yml reads.
set -u

COMPOSE=${COMPOSE:-docker compose --profile full}
SITE=${SITE:-http://127.0.0.1:${WEB_PORT:-8081}}
DB_PORT=${DB_PORT:-3306}
ADMIN_PW=${DB_ADMIN_PASSWORD:-bastion}
APP_PW=${DB_PASS:-bastion-app-local}
failed=0

ok()   { echo "ok:   $1"; }
bad()  { echo "FAIL: $1"; failed=1; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
refuse() { if eval "$2" >/dev/null 2>&1; then bad "$1"; else ok "$1"; fi; }
in_c() { $COMPOSE exec -T "$1" sh -c "$2"; }

echo "== What the site serves ($SITE)"
check  "serves the SPA"                       "curl -fsS --max-time 10 $SITE/ | grep '<div id=\"root\"'"
check  "client-side routes fall back to the SPA" "curl -fsS --max-time 10 $SITE/login | grep '<div id=\"root\"'"
check  "the API answers through the web server"  "curl -fsS --max-time 10 $SITE/api/v1/auth/config | grep '{'"
check  "pages carry a strict CSP"             "curl -fsSI --max-time 10 $SITE/ | grep -i \"^content-security-policy: default-src 'self'\""
check  "pages carry HSTS"                     "curl -fsSI --max-time 10 $SITE/ | grep -i '^strict-transport-security: max-age='"
check  "pages forbid framing"                 "curl -fsSI --max-time 10 $SITE/ | grep -i '^x-frame-options: DENY'"
refuse "nginx hides its version"              "curl -fsSI --max-time 10 $SITE/ | grep -i '^server: nginx/'"
refuse "the actuator is not reachable through the web server" \
       "curl -fsS --max-time 10 $SITE/actuator/health | grep status"
marker="never-logged-$$"
curl -fsS --max-time 10 -o /dev/null "$SITE/reset-password?token=$marker" || true
refuse "query strings stay out of the access log" "$COMPOSE logs web 2>&1 | grep $marker"
refuse "a forged X-Forwarded-For is not believed" \
       "curl -fsS --max-time 10 -o /dev/null -H 'X-Forwarded-For: 203.0.113.77' $SITE/; $COMPOSE logs web 2>&1 | grep '203.0.113.77 ['"

echo "== What each container can reach"
check  "app reaches the internet"             "in_c app 'wget -q -T 10 -O /dev/null http://1.1.1.1/'"
refuse "web cannot reach the internet"        "in_c web 'wget -q -T 5 -O /dev/null http://1.1.1.1/'"
refuse "mailpit cannot reach the internet"    "in_c mailpit 'wget -q -T 5 -O /dev/null http://1.1.1.1/'"
refuse "db cannot reach the internet"         "in_c db 'curl -s -m 5 -o /dev/null http://1.1.1.1/'"
check  "web reaches the app"                  "in_c web 'wget -q -T 5 -O /dev/null http://app:8080/api/v1/auth/config'"
check  "app reaches the database"             "in_c app 'nc -z -w 5 db 3306'"
check  "app reaches mailpit"                  "in_c app 'nc -z -w 5 mailpit 1025'"
refuse "web cannot reach the database"        "in_c web 'nc -z -w 3 db 3306'"

echo "== How the app signs in to the database"
sessions=$(in_c db 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "
  select group_concat(distinct concat(t.processlist_user, \"/\", coalesce(nullif(s.variable_value, \"\"), \"plain\")))
  from performance_schema.threads t
  left join performance_schema.status_by_thread s
    on s.thread_id = t.thread_id and s.variable_name = \"Ssl_version\"
  where t.processlist_user is not null and t.processlist_user not in (\"root\", \"event_scheduler\")"' 2>/dev/null)
if [ -z "$sessions" ] || [ "$sessions" = "NULL" ]; then
  bad "the app has database sessions"
elif echo "$sessions" | tr ',' '\n' | grep -v '^bastion_app/TLS' >/dev/null; then
  bad "only bastion_app, over TLS, holds sessions (found: $sessions)"
else
  ok "only bastion_app, over TLS, holds sessions ($sessions)"
fi
grants=$(in_c db 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "show grants for bastion_app@\"%\""' 2>/dev/null)
if echo "$grants" | grep -q 'GRANT SELECT, INSERT, UPDATE, DELETE ON' && ! echo "$grants" | grep -qE 'ALL PRIVILEGES|CREATE|DROP|ALTER'; then
  ok "bastion_app can only read and write rows"
else
  bad "bastion_app has more than row access: $grants"
fi
mysql_image=$($COMPOSE config --images 2>/dev/null | grep '^mysql:' | head -1)
refuse "root cannot sign in over the network" \
       "docker run --rm --network host $mysql_image mysql -h 127.0.0.1 -P $DB_PORT -uroot -p'$ADMIN_PW' -e 'select 1'"
refuse "an unencrypted connection is refused" \
       "docker run --rm --network host $mysql_image mysql -h 127.0.0.1 -P $DB_PORT -ubastion_app -p'$APP_PW' --ssl-mode=DISABLED -e 'select 1'"
refuse "bastion_app cannot create a table" \
       "docker run --rm --network host $mysql_image mysql -h 127.0.0.1 -P $DB_PORT -ubastion_app -p'$APP_PW' ${DB_NAME:-bastion} -e 'create table pwned (id int)'"

echo "== Runtime restrictions on every container"
for c in $($COMPOSE ps -aq); do
  line=$(docker inspect -f '{{.Name}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} opts={{.HostConfig.SecurityOpt}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' "$c")
  if echo "$line" | grep -E 'user=[^ ]+ ro=true caps=\[ALL\] opts=\[no-new-privileges:true\] mem=[1-9][0-9]* pids=[1-9]' >/dev/null; then
    ok "$line"
  else
    bad "$line"
  fi
done

[ "$failed" -eq 0 ] && echo "== All checks passed" || echo "== Some checks FAILED"
exit $failed
