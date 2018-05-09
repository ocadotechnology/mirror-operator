#!/usr/bin/env bash

if [ -n "${TRAVIS_TAG}" ]; then
  VERSION=$TRAVIS_COMMIT
fi

docker build --pull --cache-from "$TRAVIS_REPO_SLUG" --tag "$TRAVIS_REPO_SLUG" \
  --label="org.label-schema.build-date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --label="org.label-schema.vendor=Ocado Technology" \
  --label="org.label-schema.schema-version=1.0" \
  --label="org.label-schema.vcs-url=${VCS_SOURCE}" \
  --label="org.label-schema.version=${VERSION}" \
  --label="org.label-schema.vcs-ref=${TRAVIS_COMMIT}" \
  --label="org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --label="org.opencontainers.image.vendor=Ocado Technology" \
  --label="org.opencontainers.image.source=${VCS_SOURCE}" \
  --label="org.opencontainers.image.version=${VERSION}" \
  --label="org.opencontainers.image.revision=${TRAVIS_COMMIT}" \
  --label="org.opencontainers.image.authors=$(git log --format='%aE' Dockerfile | sort -u | tr '\n' ' ')" .


if [ "${TRAVIS_TAG}" ]; then
  docker tag "${TRAVIS_REPO_SLUG}" "${TRAVIS_REPO_SLUG}:${TRAVIS_TAG}"
fi
docker tag "${TRAVIS_REPO_SLUG}" "${TRAVIS_REPO_SLUG}:latest"
docker tag "${TRAVIS_REPO_SLUG}" "${TRAVIS_REPO_SLUG}:${TRAVIS_COMMIT}"
