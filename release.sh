#!/bin/sh

set -e
set -x

cd "$(dirname "$(readlink -f "$0")")"

git pull origin master

CHANGELOG=./Changelog
VERSION=$(grep -m1 -o '\[v[0-9][^]]*\]' "$CHANGELOG" | sed 's/\[v//;s/\]//')
TAG="v${VERSION}"

CHANGESET=$(awk -v tag="$TAG" '
  $0 ~ tag { skip = 1; next }
  skip && NF == 0 { exit }
  skip { print }
' "$CHANGELOG" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' )

git add "$CHANGELOG"

if ! git diff-index --quiet HEAD --; then
  git commit -m"${TAG} landed"
  git push origin master
fi

echo "$CHANGESET" | git tag -f -a -F - "$TAG"
git push origin -f --tags