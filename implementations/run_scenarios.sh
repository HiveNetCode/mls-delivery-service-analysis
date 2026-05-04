#!/bin/bash
# Automated scenarios for MLS Delivery Service PoC
# Runs both scenarios from README.md

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/bin"

RTT=500
PKI_ADDR="127.0.0.1"
DS_ADDR="127.0.0.1"

PKI_PID=
DS_PID=
CLIENT1_PID=
CLIENT2_PID=
ATTACKER_PID=
PIPE1=
PIPE2=
PIPE3=

cleanup() {
    for pid in "$CLIENT1_PID" "$CLIENT2_PID" "$ATTACKER_PID" "$DS_PID" "$PKI_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    for pid in "$CLIENT1_PID" "$CLIENT2_PID" "$ATTACKER_PID" "$DS_PID" "$PKI_PID"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null
    done
    exec 3>&- 2>/dev/null
    exec 4>&- 2>/dev/null
    exec 5>&- 2>/dev/null
    [ -n "$PIPE1" ] && rm -f "$PIPE1"
    [ -n "$PIPE2" ] && rm -f "$PIPE2"
    [ -n "$PIPE3" ] && rm -f "$PIPE3"
}

trap cleanup EXIT
trap "" PIPE

make_pipe() {
    local p
    p=$(mktemp -u /tmp/mls_pipe_XXXXXX)
    mkfifo "$p"
    printf '%s' "$p"
}

# ============================================================
echo "=== Building ==="
(cd "$SCRIPT_DIR" && make)
echo ""

# ============================================================
echo "=== Scenario 1: Attack Case ==="
echo ""

"$BIN/pki" &
PKI_PID=$!
"$BIN/delivery_service" 10502 &
DS_PID=$!
sleep 1

PIPE1=$(make_pipe)
PIPE2=$(make_pipe)

# Start attacker first so it registers its key package with the PKI
# before client1 issues the 'add' command
"$BIN/attacker" client-attacker "$PKI_ADDR" "$DS_ADDR" "$RTT" < "$PIPE2" &
ATTACKER_PID=$!
exec 4>"$PIPE2"

"$BIN/centralized_client" client1 "$PKI_ADDR" "$DS_ADDR" "$RTT" < "$PIPE1" &
CLIENT1_PID=$!
exec 3>"$PIPE1"

sleep 1

echo "create" >&3
sleep 1

echo "add client-attacker" >&3
sleep 3   # Allow time for proposal broadcast, commit, and welcome delivery

# Attacker has joined the group; now send the invalid commit
echo "invalid-commit" >&4
sleep 2   # Allow time for client1 to receive and crash on the invalid commit

if kill -0 "$CLIENT1_PID" 2>/dev/null; then
    echo "(client1 still running - may not have crashed yet)"
else
    echo "(client1 terminated as expected due to attack)"
fi

echo "stop" >&4 2>/dev/null || true
sleep 0.5
wait "$ATTACKER_PID" 2>/dev/null; ATTACKER_PID=
wait "$CLIENT1_PID" 2>/dev/null; CLIENT1_PID=
exec 3>&-; exec 4>&-
rm -f "$PIPE1" "$PIPE2"; PIPE1=; PIPE2=

kill "$PKI_PID" "$DS_PID" 2>/dev/null
wait "$PKI_PID" "$DS_PID" 2>/dev/null; PKI_PID=; DS_PID=
sleep 1

echo ""

# ============================================================
echo "=== Scenario 2: Improved Clients ==="
echo ""

"$BIN/pki" &
PKI_PID=$!
"$BIN/delivery_service" 10502 &
DS_PID=$!
sleep 1

PIPE1=$(make_pipe)
PIPE2=$(make_pipe)
PIPE3=$(make_pipe)

# Start attacker first to register with PKI before any 'add' commands
"$BIN/attacker" client-attacker "$PKI_ADDR" "$DS_ADDR" "$RTT" < "$PIPE3" &
ATTACKER_PID=$!
exec 5>"$PIPE3"

"$BIN/ds_aware_client" client1 "$PKI_ADDR" "$DS_ADDR" "$RTT" < "$PIPE1" &
CLIENT1_PID=$!
exec 3>"$PIPE1"

"$BIN/ds_aware_client" client2 "$PKI_ADDR" "$DS_ADDR" "$RTT" < "$PIPE2" &
CLIENT2_PID=$!
exec 4>"$PIPE2"

sleep 1

echo "create" >&3
sleep 1

echo "add client2" >&3
sleep 3   # Wait for commit; client2 joins group

echo "add client-attacker" >&3
sleep 3   # Wait for commit; attacker joins group

# Attacker sends invalid commit; both improved clients should ignore it
echo "invalid-commit" >&5
sleep 2

# Verify both clients still function correctly
echo "update" >&3
sleep 3   # Wait for update proposal and commit

echo "message testOK" >&3
sleep 1   # Allow message delivery to client2

echo "stop" >&3
echo "stop" >&4
echo "stop" >&5 2>/dev/null || true
sleep 0.5

wait "$CLIENT1_PID" 2>/dev/null; CLIENT1_PID=
wait "$CLIENT2_PID" 2>/dev/null; CLIENT2_PID=
wait "$ATTACKER_PID" 2>/dev/null; ATTACKER_PID=
exec 3>&-; exec 4>&-; exec 5>&- 2>/dev/null
rm -f "$PIPE1" "$PIPE2" "$PIPE3"; PIPE1=; PIPE2=; PIPE3=

kill "$PKI_PID" "$DS_PID" 2>/dev/null
wait "$PKI_PID" "$DS_PID" 2>/dev/null; PKI_PID=; DS_PID=

echo ""
echo "=== All scenarios completed ==="
