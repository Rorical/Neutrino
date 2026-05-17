#!/usr/bin/env bash
#
# M6 integration smoke test.
#
# Brings up a 3-node Neutrino stack via docker compose, waits for the
# gossipsub mesh to form, verifies block production/import, then starts a
# fourth node late and requires it to sync through the full FSM. Exits
# non-zero on any failure.
#
# Usage:
#     ./docker/integration/run-smoke-test.sh
#     ./docker/integration/run-smoke-test.sh --keep   # leave the stack running

set -euo pipefail

cd "$(dirname "$0")"

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

# Pick the right compose CLI — `docker compose` on modern Docker, fall
# back to `docker-compose` for older installs.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "docker compose not available" >&2
    exit 2
fi

cleanup() {
    if [[ ${KEEP} -eq 1 ]]; then
        echo
        echo "leaving stack running (--keep). Tear down with:"
        echo "    ${COMPOSE[*]} -f $(pwd)/docker-compose.yml down -v"
        return
    fi
    echo
    echo "--- tearing down stack ---"
    "${COMPOSE[@]}" -f docker-compose.yml down --remove-orphans -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- building neutrino-node image ---"
"${COMPOSE[@]}" -f docker-compose.yml build --quiet

echo "--- starting initial 3-node stack ---"
"${COMPOSE[@]}" -f docker-compose.yml up -d node1 node2 node3

NODES=(node1 node2 node3)
DEADLINE=$(( $(date +%s) + 60 ))

# Wait for each node to observe ≥ 2 successful "connection established"
# events. Each established connection emits exactly one log line, so
# counting them is enough.
EXPECTED_PEERS=2
echo "--- waiting for ${EXPECTED_PEERS} peer connections per node (timeout 60s) ---"
for node in "${NODES[@]}"; do
    container="neutrino-m6-${node}"
    while :; do
        if [[ $(date +%s) -ge ${DEADLINE} ]]; then
            echo "timeout: ${node} did not reach ${EXPECTED_PEERS} peers" >&2
            "${COMPOSE[@]}" -f docker-compose.yml logs --tail=80 "${node}" >&2 || true
            exit 1
        fi
        count=$(docker logs "${container}" 2>&1 | grep -c "connection established" || true)
        if [[ ${count} -ge ${EXPECTED_PEERS} ]]; then
            echo "  ${node}: ${count} peer connections observed"
            break
        fi
        sleep 1
    done
done

# Verify pubsub mesh formed — every node must have subscribed to every
# canonical topic before declaring success.
EXPECTED_SUBSCRIPTIONS=9
echo "--- verifying ${EXPECTED_SUBSCRIPTIONS} topic subscriptions per node ---"
for node in "${NODES[@]}"; do
    container="neutrino-m6-${node}"
    count=$(docker logs "${container}" 2>&1 | grep -c "subscribed to topic" || true)
    if [[ ${count} -lt ${EXPECTED_SUBSCRIPTIONS} ]]; then
        echo "  ${node}: only ${count} subscriptions (expected ≥ ${EXPECTED_SUBSCRIPTIONS})" >&2
        exit 1
    fi
    echo "  ${node}: ${count} topic subscriptions"
done

DEADLINE=$(( $(date +%s) + 60 ))
echo "--- waiting for validator block production ---"
while :; do
    if [[ $(date +%s) -ge ${DEADLINE} ]]; then
        echo "timeout: node1 did not produce a block" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=120 node1 >&2 || true
        exit 1
    fi
    count=$(docker logs neutrino-m6-node1 2>&1 | grep -c "produced and published block" || true)
    if [[ ${count} -ge 1 ]]; then
        echo "  node1: ${count} produced block(s)"
        break
    fi
    sleep 1
done

echo "--- verifying gossipped block import on followers ---"
for node in node2 node3; do
    container="neutrino-m6-${node}"
    while :; do
        if [[ $(date +%s) -ge ${DEADLINE} ]]; then
            echo "timeout: ${node} did not import a gossipped block" >&2
            "${COMPOSE[@]}" -f docker-compose.yml logs --tail=120 "${node}" >&2 || true
            exit 1
        fi
        count=$(docker logs "${container}" 2>&1 | grep -c "imported gossipped block" || true)
        if [[ ${count} -ge 1 ]]; then
            echo "  ${node}: ${count} imported block(s)"
            break
        fi
        sleep 1
    done
done

echo "--- starting late-joining node4 ---"
"${COMPOSE[@]}" -f docker-compose.yml up -d node4

DEADLINE=$(( $(date +%s) + 90 ))
echo "--- waiting for node4 to connect and sync from genesis ---"
while :; do
    if [[ $(date +%s) -ge ${DEADLINE} ]]; then
        echo "timeout: node4 did not complete full sync" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=160 node4 >&2 || true
        exit 1
    fi
    connections=$(docker logs neutrino-m6-node4 2>&1 | grep -c "connection established" || true)
    block_batches=$(docker logs neutrino-m6-node4 2>&1 | grep -c "imported block batch" || true)
    proof_batches=$(docker logs neutrino-m6-node4 2>&1 | grep -c "imported block proof batch" || true)
    following=$(docker logs neutrino-m6-node4 2>&1 | grep -c "sync FSM entered Following" || true)
    if [[ ${connections} -ge 1 && ${block_batches} -ge 1 && ${proof_batches} -ge 1 && ${following} -ge 1 ]]; then
        echo "  node4: ${connections} connection(s), ${block_batches} block batch(es), ${proof_batches} proof batch(es), Following reached"
        break
    fi
    sleep 1
done

echo
echo "--- M6 smoke test passed ---"
