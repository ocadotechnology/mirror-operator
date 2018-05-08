#!/usr/bin/env bash

docker login -u "$REGISTRY_USER" -p "$REGISTRY_PASS"

if [ "${TRAVIS_TAG}" ]; then
  docker push "${TRAVIS_REPO_SLUG}:${TRAVIS_TAG}"
fi
docker push "${TRAVIS_REPO_SLUG}:latest" && \
docker push "{TRAVIS_REPO_SLUG}:${TRAVIS_COMMIT}" 
