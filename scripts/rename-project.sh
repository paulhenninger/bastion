#!/bin/sh
# Turns a fresh copy of Bastion into your project: Java package, class names,
# cookie and header names, metric and logger names, database and login names,
# image names, the SPA's title — every place "bastion" appears, in one pass.
#
#   scripts/rename-project.sh <name> <java.package> "<Display Name>"
#   scripts/rename-project.sh acme com.example.acme "Acme"
#
#   <name>          lowercase identifier, [a-z][a-z0-9_]* — database, logins,
#                   cookies, images, metrics (acme_refresh, acme_app, acme.audit)
#   <java.package>  the base package, e.g. com.example.acme
#   <Display Name>  what users see: page title, emails, authenticator label
#
# Run it once, on a clean checkout, before the first migration reaches a real
# database: it is not an upgrade tool. It never edits the Flyway migrations
# (their checksums must not change), LICENSE, or the scaffolding docs, and it
# resets CHANGELOG.md. Afterwards: ./gradlew build, and grep for leftovers —
# see docs/scaffolding.md. Needs perl (present on macOS, Linux and Git Bash).
set -eu

if [ $# -ne 3 ]; then
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
name=$1 pkg=$2 display=$3

echo "$name" | grep -Eq '^[a-z][a-z0-9_]*$' || { echo "name must match [a-z][a-z0-9_]*" >&2; exit 2; }
echo "$pkg" | grep -Eq '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' || { echo "package must look like com.example.app" >&2; exit 2; }
[ -n "$display" ] || { echo "display name is empty" >&2; exit 2; }
[ -d src/main/java/dev/bastion ] || { echo "run from the root of an unrenamed Bastion checkout" >&2; exit 2; }
command -v perl >/dev/null || { echo "perl is required" >&2; exit 2; }
if command -v git >/dev/null && [ -d .git ] && [ -n "$(git status --porcelain)" ]; then
  echo "the working tree has uncommitted changes; commit or stash them first" >&2; exit 2
fi

# AcmeBooks from acme_books; ACME_BOOKS for environment variables.
pascal=$(echo "$name" | perl -pe 's/(^|_)([a-z0-9])/\U$2/g')
upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
group=${pkg%.*}
host=$(echo "$name" | tr _ -)   # hostnames can't contain underscores
pkg_path=$(echo "$pkg" | tr . /)

echo "Renaming: name=$name package=$pkg display=\"$display\" class=${pascal}Application"

# 1. Move the Java sources into the new package.
for root in src/main/java src/test/java; do
  mkdir -p "$root/$pkg_path"
  # Move the contents, then remove the now-empty dev/bastion (and dev/, if empty).
  ( cd "$root/dev/bastion" && tar cf - . ) | ( cd "$root/$pkg_path" && tar xf - )
  rm -rf "$root/dev/bastion"
  rmdir "$root/dev" 2>/dev/null || true
done
mv "src/main/java/$pkg_path/BastionApplication.java" "src/main/java/$pkg_path/${pascal}Application.java"

# 2. Rewrite every text file except the ones that must not change.
files=$(find . -type f \
  -not -path './.git/*' -not -path '*/node_modules/*' -not -path './build/*' -not -path './.gradle/*' \
  -not -path './frontend/dist/*' -not -path './.idea/*' \
  -not -path './src/main/resources/db/migration/*' \
  -not -name LICENSE -not -name CHANGELOG.md -not -name '*.jar' -not -name '*.png' -not -name '*.ico' \
  -not -name 'gradlew*' -not -name '.env' \
  -not -path './docs/scaffolding.md' -not -path './docs/ai-customization-prompt.md' \
  -not -path './scripts/rename-project.sh')

# Most specific first, so a general rule never rewrites part of a specific one.
export HOST="$host" NAME="$name" PKG="$pkg" DISPLAY="$display" PASCAL="$pascal" UPPER="$upper" GROUP="$group"
# shellcheck disable=SC2086
perl -pi -e '
  s/\bdev\.bastion\b/$ENV{PKG}/g;
  s/BastionApplication/$ENV{PASCAL}Application/g;
  s/bastion(\.local|-login\.example)/$ENV{HOST}$1/g;
  s/X-Bastion-/X-$ENV{PASCAL}-/g;
  s/BASTION/$ENV{UPPER}/g;
  s/Bastion/$ENV{DISPLAY}/g;
  s/bastion/$ENV{NAME}/g;
' $files

# The Gradle group: the package's parent (com.example for com.example.acme).
perl -pi -e "s/^group = '.*'/group = '$group'/; s/^version = '.*'/version = '0.1.0'/" build.gradle
perl -pi -e 's/"version": "[^"]*"/"version": "0.1.0"/ if $. < 6' frontend/package.json

# 3. A fresh changelog: Bastion's history is not yours.
cat > CHANGELOG.md <<EOF
# Changelog

## 0.1.0 — unreleased

- Started from [Bastion](https://github.com/paulhenninger/bastion) 2.1.0.
EOF

# This script only works on an unrenamed checkout; don't leave it lying around.
rm -f -- "$0"

echo
echo "Done. Next:"
echo "  ./gradlew build                     # every test must still pass"
echo "  (cd frontend && npm install && npm run build)"
echo "  git grep -in bastion                # review what is left (docs credit, migrations)"
echo "  see docs/scaffolding.md for what to change by hand"
