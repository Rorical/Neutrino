#!/usr/bin/env bash
#
# M6 integration smoke test.
#
# Brings up a 3-node Neutrino stack via docker compose, waits for the
# gossipsub mesh to form, verifies block production / import / chunk
# close, exercises a late-joiner, and proves restart-resume on a
# follower node. Exits non-zero on any failure.
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

# Pick the right compose CLI - `docker compose` on modern Docker, fall
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

count_in_logs() {
    local container="$1"
    local needle="$2"
    docker logs "${container}" 2>&1 | grep -c "${needle}" || true
}

# Block counts: each produced or imported block emits exactly one log
# line, so counting them is an upper bound on the head height the node
# has observed. Used in lieu of an RPC head-query during the M6 smoke
# test.
produced_count() {
    count_in_logs "$1" "produced and published block"
}

imported_count() {
    count_in_logs "$1" "imported gossipped block"
}

echo "--- building neutrino-node image ---"
"${COMPOSE[@]}" -f docker-compose.yml build --quiet

echo "--- starting initial 3-node stack ---"
"${COMPOSE[@]}" -f docker-compose.yml up -d node1 node2 node3

NODES=(node1 node2 node3)
DEADLINE=$(( $(date +%s) + 60 ))

# Wait for each node to observe >= 2 successful "connection established"
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
        count=$(count_in_logs "${container}" "connection established")
        if [[ ${count} -ge ${EXPECTED_PEERS} ]]; then
            echo "  ${node}: ${count} peer connections observed"
            break
        fi
        sleep 1
    done
done

# Verify pubsub mesh formed - every node must have subscribed to every
# canonical topic before declaring success.
EXPECTED_SUBSCRIPTIONS=9
echo "--- verifying ${EXPECTED_SUBSCRIPTIONS} topic subscriptions per node ---"
for node in "${NODES[@]}"; do
    container="neutrino-m6-${node}"
    count=$(count_in_logs "${container}" "subscribed to topic")
    if [[ ${count} -lt ${EXPECTED_SUBSCRIPTIONS} ]]; then
        echo "  ${node}: only ${count} subscriptions (expected >= ${EXPECTED_SUBSCRIPTIONS})" >&2
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
    count=$(count_in_logs neutrino-m6-node1 "produced and published block")
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
        count=$(count_in_logs "${container}" "imported gossipped block")
        if [[ ${count} -ge 1 ]]; then
            echo "  ${node}: ${count} imported block(s)"
            break
        fi
        sleep 1
    done
done

# With slot_duration_secs=1 and chunk_size=8 we expect at least two
# chunks to close inside a 30 s window. The chunk close path advances
# `finalized_seed` and publishes the recursive checkpoint, so this is
# what verifies the M6 chunk-close + checkpoint loop end-to-end.
MIN_CHUNK_CLOSES=2
WAIT_FOR_CHUNKS_SECS=30
echo "--- waiting ${WAIT_FOR_CHUNKS_SECS}s for >= ${MIN_CHUNK_CLOSES} chunk closes on node1 ---"
DEADLINE=$(( $(date +%s) + WAIT_FOR_CHUNKS_SECS + 10 ))
sleep "${WAIT_FOR_CHUNKS_SECS}"
while :; do
    closes=$(count_in_logs neutrino-m6-node1 "closed chunk and published recursive checkpoint")
    if [[ ${closes} -ge ${MIN_CHUNK_CLOSES} ]]; then
        echo "  node1: ${closes} chunk close(s)"
        break
    fi
    if [[ $(date +%s) -ge ${DEADLINE} ]]; then
        echo "timeout: node1 closed only ${closes} chunk(s) (expected >= ${MIN_CHUNK_CLOSES})" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=200 node1 >&2 || true
        exit 1
    fi
    sleep 2
done

# Followers must observe at least one recursive checkpoint over the wire.
for node in node2 node3; do
    container="neutrino-m6-${node}"
    imported=$(count_in_logs "${container}" "imported gossipped recursive checkpoint")
    if [[ ${imported} -lt 1 ]]; then
        echo "  ${node}: only ${imported} recursive checkpoint(s) imported (expected >= 1)" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=200 "${node}" >&2 || true
        exit 1
    fi
    echo "  ${node}: ${imported} recursive checkpoint(s) imported"
done

# Chain agreement proxy: followers must have imported nearly as many
# blocks as the validator produced (slack window covers libp2p gossip
# propagation latency). Each "produced and published block" log line
# on node1 corresponds to one "imported gossipped block" on each
# follower under healthy gossip.
echo "--- verifying chain agreement (per-node block counts within slack) ---"
SLACK=3
PRODUCED=$(produced_count neutrino-m6-node1)
echo "  node1: ${PRODUCED} produced block(s)"
for node in node2 node3; do
    container="neutrino-m6-${node}"
    imported=$(imported_count "${container}")
    diff=$(( PRODUCED - imported ))
    if [[ ${diff} -gt ${SLACK} || ${diff} -lt 0 ]]; then
        echo "chain disagreement: produced=${PRODUCED}, ${node}=${imported} (slack ${SLACK})" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=120 "${node}" >&2 || true
        exit 1
    fi
    echo "  ${node}: ${imported} imported block(s)"
done

echo "--- starting late-joining node4 ---"
"${COMPOSE[@]}" -f docker-compose.yml up -d node4

DEADLINE=$(( $(date +%s) + 90 ))
echo "--- waiting for node4 to connect and sync from genesis ---"
while :; do
    if [[ $(date +%s) -ge ${DEADLINE} ]]; then
        echo "timeout: node4 did not complete full sync" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=200 node4 >&2 || true
        exit 1
    fi
    connections=$(count_in_logs neutrino-m6-node4 "connection established")
    block_batches=$(count_in_logs neutrino-m6-node4 "imported block batch")
    proof_batches=$(count_in_logs neutrino-m6-node4 "imported block proof batch")
    following=$(count_in_logs neutrino-m6-node4 "sync FSM entered Following")
    if [[ ${connections} -ge 1 && ${block_batches} -ge 1 && ${proof_batches} -ge 1 && ${following} -ge 1 ]]; then
        echo "  node4: ${connections} connection(s), ${block_batches} block batch(es), ${proof_batches} proof batch(es), Following reached"
        break
    fi
    sleep 1
done

# Restart resume: stop node2, wait long enough for node1 to keep
# producing past node2's last-seen view, then restart node2 and
# require it to catch up from on-disk state rather than fork off a
# fresh genesis chain. After restart, node2 will pull the missed
# range over RPC ("imported block batch") because gossip is
# fire-and-forget, so the resume check sums both batch and
# gossipped imports.
all_imports() {
    local container="$1"
    local gossip
    local batch
    gossip=$(imported_count "${container}")
    batch=$(count_in_logs "${container}" "imported block batch")
    echo $(( gossip + batch ))
}

echo "--- exercising node2 restart-resume ---"
IMPORTS_BEFORE_STOP=$(all_imports neutrino-m6-node2)
echo "  node2 imports before stop: ${IMPORTS_BEFORE_STOP}"
"${COMPOSE[@]}" -f docker-compose.yml stop node2 >/dev/null
sleep 8
"${COMPOSE[@]}" -f docker-compose.yml start node2 >/dev/null

DEADLINE=$(( $(date +%s) + 60 ))
echo "--- waiting for node2 to resume from on-disk state ---"
while :; do
    if [[ $(date +%s) -ge ${DEADLINE} ]]; then
        echo "timeout: node2 did not resume past its pre-restart imports" >&2
        "${COMPOSE[@]}" -f docker-compose.yml logs --tail=200 node2 >&2 || true
        exit 1
    fi
    resumed=$(count_in_logs neutrino-m6-node2 "engine resumed from persistent state")
    imports_after=$(all_imports neutrino-m6-node2)
    if [[ ${resumed} -ge 1 && ${imports_after} -gt ${IMPORTS_BEFORE_STOP} ]]; then
        echo "  node2 resumed (imports ${imports_after} > pre-restart ${IMPORTS_BEFORE_STOP})"
        break
    fi
    sleep 1
done

echo
echo "--- M6 smoke test passed ---"
