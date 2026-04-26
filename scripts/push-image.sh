#!/usr/bin/env bash
set -euo pipefail

REGISTRY="ghcr.io"
IMAGE="${REGISTRY}/nclaeys/s3sentinel"

usage() {
  echo "Usage: $0 <version>"
  echo "  version  Semantic version to tag, e.g. 1.2.3"
  exit 1
}

[[ $# -eq 1 ]] || usage
VERSION="$1"

run_or_hint() {
  local tmpfile
  tmpfile=$(mktemp)
  set +e
  "$@" 2>&1 | tee "$tmpfile"
  local exit_code=${PIPESTATUS[0]}
  set -e
  if [[ $exit_code -ne 0 ]]; then
    if grep -qi "unauthorized\|access denied" "$tmpfile"; then
      rm -f "$tmpfile"
      echo ""
      echo "Error: unauthorized. Login to ghcr.io first:"
      echo '  echo "<TOKEN>" | docker login ghcr.io -u nclaeys --password-stdin'
      exit 1
    fi
    rm -f "$tmpfile"
    exit "$exit_code"
  fi
  rm -f "$tmpfile"
}

run_or_hint docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" .
run_or_hint docker push "${IMAGE}:${VERSION}"
run_or_hint docker push "${IMAGE}:latest"

echo "Pushed ${IMAGE}:${VERSION} and ${IMAGE}:latest"
