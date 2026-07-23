#!/usr/bin/env bash
#
# clean-dbs.sh — wipe MiniWSA's data stores for a clean slate.
#
#   * Elasticsearch: deletes the "security-events" index (recreated on next write).
#   * Redis:         FLUSHALL (nothing else uses this instance).
#
# Works whether or not the app is running; it talks to the stores directly. Redis is
# cleaned via a local `redis-cli` if present, otherwise via `docker exec` into the
# compose container.
#
# Overridable via environment variables (defaults match docker-compose.yml / application.yml):
#   ES_URL          Elasticsearch base URL           (default http://localhost:9200)
#   ES_INDEX        index to drop                     (default security-events)
#   REDIS_HOST      Redis host for local redis-cli    (default localhost)
#   REDIS_PORT      Redis port for local redis-cli    (default 6379)
#   REDIS_CONTAINER compose container for docker exec (default wsa-redis)
#
# Usage:
#   ./scripts/clean-dbs.sh          # clean both
#   ./scripts/clean-dbs.sh es       # only Elasticsearch
#   ./scripts/clean-dbs.sh redis    # only Redis

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
ES_INDEX="${ES_INDEX:-security-events}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_CONTAINER="${REDIS_CONTAINER:-wsa-redis}"

clean_es() {
    echo "[es] deleting index '${ES_INDEX}' at ${ES_URL} ..."
    # ignore_unavailable=true => deleting a missing index is a no-op, not an error.
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' \
        -X DELETE "${ES_URL}/${ES_INDEX}?ignore_unavailable=true")
    if [[ "${status}" == "200" || "${status}" == "404" ]]; then
        echo "[es] done (HTTP ${status})."
    else
        echo "[es] WARNING: unexpected HTTP ${status} — is Elasticsearch up at ${ES_URL}?" >&2
        return 1
    fi
}

clean_redis() {
    echo "[redis] FLUSHALL ..."
    if command -v redis-cli >/dev/null 2>&1; then
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" FLUSHALL
    elif command -v docker >/dev/null 2>&1; then
        echo "[redis] no local redis-cli; using 'docker exec ${REDIS_CONTAINER}'."
        docker exec "${REDIS_CONTAINER}" redis-cli FLUSHALL
    else
        echo "[redis] ERROR: need either redis-cli or docker on PATH." >&2
        return 1
    fi
    echo "[redis] done."
}

target="${1:-all}"
case "${target}" in
    es)    clean_es ;;
    redis) clean_redis ;;
    all)   clean_es; clean_redis ;;
    *)
        echo "Usage: $0 [all|es|redis]" >&2
        exit 2
        ;;
esac

echo "Clean complete."
