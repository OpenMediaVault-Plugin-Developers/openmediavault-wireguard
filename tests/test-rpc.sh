#!/usr/bin/env bash
# test-rpc.sh — Integration tests for openmediavault-wireguard RPC methods.
#
# Usage: sudo ./tests/test-rpc.sh
#
# Exercises all Wireguard plugin RPC methods against the live OMV configuration
# database.  Creates test objects (tunnel, client, custom config) and removes
# them on exit.
#
# Requirements:
#   - Run as root
#   - OMV with the wireguard plugin installed
#   - wg command available (installed with the wireguard-tools package)
#
# WARNING: the "Apply" section enables the test objects and runs
#          'omv-salt deploy run wireguard'.  The salt state stops and restarts
#          EVERY wireguard tunnel on the host, not just the test ones.  Only
#          run this on a development machine.

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Colours / counters
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
declare -a FAILED_TESTS=()

section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}" >&2; }
info()    { echo -e "  ${YELLOW}»${NC} $*" >&2; }

_pass() { echo -e "  ${GREEN}PASS${NC}  $1" >&2; ((PASS++)) || true; }
_fail() {
    echo -e "  ${RED}FAIL${NC}  $1" >&2
    [ -n "${2:-}" ] && echo -e "         ${RED}→${NC} $2" >&2
    ((FAIL++)) || true
    FAILED_TESTS+=("$1")
}
_skip() { echo -e "  ${YELLOW}SKIP${NC}  $1${2:+  ($2)}" >&2; ((SKIP++)) || true; }

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

# Last successful RPC output — never call assert_rpc inside $() subshells as
# that prevents PASS/FAIL counter updates from propagating.
RPC_OUT=""
BG_OUT=""

assert_rpc() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local out ec=0
    RPC_OUT=""
    out=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "$(echo "$out" | tail -3)"
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$out" | grep -q "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in: ${out:0:300}"
        return 1
    fi
    _pass "$desc"
    RPC_OUT="$out"
    return 0
}

assert_rpc_fails() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'}
    local out ec=0
    out=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -eq 0 ] && ! echo "$out" | grep -qi "exception"; then
        _fail "$desc" "Expected failure but RPC succeeded: ${out:0:200}"
        return 1
    fi
    _pass "$desc"
    return 0
}

# Call a *BgProc method, poll for completion, report result.
# Optional 5th arg: grep pattern that must appear in the task output.
# Task output is available in $BG_OUT after the call.
assert_rpc_bg() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local filename ec=0
    BG_OUT=""
    filename=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "Failed to start bg task: ${filename:0:200}"
        return 1
    fi
    filename=$(echo "$filename" | tr -d '"')

    local timeout=120 elapsed=0 poll_ec=0 poll_out
    while [ $elapsed -lt $timeout ]; do
        poll_out=$(omv-rpc -u admin "Exec" "getOutput" \
            "{\"filename\":\"$filename\",\"pos\":0}" 2>&1)
        poll_ec=$?
        [ $poll_ec -ne 0 ] && break
        echo "$poll_out" | grep -q '"running":true\|"running": true' || break
        sleep 2; ((elapsed += 2)) || true
    done
    if [ $elapsed -ge $timeout ]; then
        _fail "$desc" "Bg task timed out after ${timeout}s"
        return 1
    fi
    if [ $poll_ec -ne 0 ]; then
        local err
        err=$(echo "$poll_out" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); e=d.get('error') or {}; print(e.get('message', str(d))[:300])" \
            2>/dev/null || echo "${poll_out:0:200}")
        _fail "$desc" "$err"
        return 1
    fi
    local content
    content=$(echo "$poll_out" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('output',''))" \
        2>/dev/null || echo "")
    BG_OUT="$content"
    if echo "$content" | grep -q "Exception"; then
        _fail "$desc" "$(echo "$content" | grep "Exception" | head -2)"
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$content" | grep -q "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in output"
        return 1
    fi
    _pass "$desc"
    return 0
}

json_get()  { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2',''))" 2>/dev/null; }
json_uuid() { json_get "$1" "uuid"; }

OMV_NEW_UUID=$(grep -oP 'OMV_CONFIGOBJECT_NEW_UUID="\K[^"]+' /etc/default/openmediavault 2>/dev/null \
    || echo "fa4b1c66-ef79-11e5-87a0-0002b3a176b4")

# ---------------------------------------------------------------------------
# Test object constants — high numbers to avoid colliding with production
# ---------------------------------------------------------------------------
TEST_TUNNELNUM=99
TEST_TUNNELNAME="omvtest_tunnel"
TEST_TUNNELPORT=51999

TEST_CLIENTNUM=99
TEST_CLIENTNAME="omvtest_client"

# Custom names must match ^\w{1,9}$ ("wgnet_" + name must fit IFNAMSIZ)
TEST_CUSTOMNAME="omvtestcc"

# ---------------------------------------------------------------------------
# Tracked UUIDs — cleared on successful deletion so cleanup skips them
# ---------------------------------------------------------------------------
TUNNEL_UUID=""
CLIENT_UUID=""
CUSTOM_UUID=""

# ---------------------------------------------------------------------------
# Helper: find a UUID in a paginated list by matching a field value
# ---------------------------------------------------------------------------
recover_uuid_from_list() {
    local svc=$1 method=$2 sortfield=$3 field=$4 value=$5
    omv-rpc -u admin "$svc" "$method" \
        "{\"start\":0,\"limit\":100,\"sortfield\":\"$sortfield\",\"sortdir\":\"ASC\"}" \
        2>/dev/null \
        | python3 -c "
import sys, json
d = json.load(sys.stdin)
rows = d.get('data', d) if isinstance(d, dict) else d
for r in rows:
    if r.get('$field') == '$value':
        print(r['uuid'])
        break
" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Apply helpers
# ---------------------------------------------------------------------------
TUNNEL_CONF="/etc/wireguard/wgnet${TEST_TUNNELNUM}.conf"
CLIENT_CONF="/etc/wireguard/wgnet_client${TEST_CLIENTNUM}.conf"
CUSTOM_CONF="/etc/wireguard/wgnet_${TEST_CUSTOMNAME}.conf"
TEST_CUSTOMPORT=51996

# Set when the test objects have been enabled and deployed; cleanup must then
# disable and redeploy before the objects can be deleted.
APPLIED=0

# set_enabled <Tunnel|Client|Custom> <uuid> <true|false> [customcfg]
# Round-trips the object through get/set with 'enable' changed.  Prints the
# set* RPC output.
set_enabled() {
    local kind=$1 uuid=$2 enable=$3 cfg=${4:-}
    local data params
    data=$(omv-rpc -u admin "Wireguard" "get$kind" "{\"uuid\":\"$uuid\"}" 2>&1) || {
        echo "$data"; return 1; }
    params=$(CFG="$cfg" python3 -c "
import sys, json, os
d = json.loads(sys.argv[1])
for k in ('numro', 'numclients', 'tunnelenable', 'allowedips'):
    d.pop(k, None)
d['enable'] = sys.argv[2] == 'true'
if os.environ.get('CFG'):
    d['customcfg'] = os.environ['CFG']
print(json.dumps(d))
" "$data" "$enable") || return 1
    omv-rpc -u admin "Wireguard" "set$kind" "$params" 2>&1
}

# Wait for any running salt deploy (e.g. one started by applyChanges) to end.
wait_for_deploys() {
    local t=0
    while pgrep -f 'omv-salt deploy|salt-call' >/dev/null && [ $t -lt 180 ]; do
        sleep 2; ((t += 2)) || true
    done
}

# deploy_wireguard — run the wireguard salt state; output in $DEPLOY_OUT.
DEPLOY_OUT=""
deploy_wireguard() {
    local ec=0
    wait_for_deploys
    DEPLOY_OUT=$(omv-salt deploy run wireguard 2>&1) || ec=$?
    return $ec
}

# Disable every given test object, then deploy so config files are removed.
disable_and_deploy() {
    local tunnel=$1 client=$2 custom=$3
    [ -n "$custom" ] && set_enabled Custom "$custom" false >/dev/null 2>&1
    [ -n "$client" ] && set_enabled Client "$client" false >/dev/null 2>&1
    [ -n "$tunnel" ] && set_enabled Tunnel "$tunnel" false >/dev/null 2>&1
    deploy_wireguard >/dev/null 2>&1
}

assert_file_contains() {
    local desc=$1 file=$2 text=$3
    if grep -qF -- "$text" "$file" 2>/dev/null; then
        _pass "$desc"
    else
        _fail "$desc" "'$text' not found in $file"
    fi
}

assert_file_lacks() {
    local desc=$1 file=$2 text=$3
    if [ -f "$file" ] && ! grep -qF -- "$text" "$file"; then
        _pass "$desc"
    else
        _fail "$desc" "'$text' found in $file (or file missing)"
    fi
}

# ---------------------------------------------------------------------------
# Pre-cleanup: remove leftover test objects from a previous failed run
# ---------------------------------------------------------------------------
pre_cleanup() {
    local tunnel client custom

    tunnel=$(recover_uuid_from_list "Wireguard" "getTunnelList" "tunnelnum" \
        "tunnelname" "$TEST_TUNNELNAME")
    client=$(recover_uuid_from_list "Wireguard" "getClientList" "clientnum" \
        "clientname" "$TEST_CLIENTNAME")
    custom=$(recover_uuid_from_list "Wireguard" "getCustomList" "name" \
        "name" "$TEST_CUSTOMNAME")

    # Leftovers from an interrupted apply cannot be deleted while their
    # config files exist.
    if [ -f "$TUNNEL_CONF" ] || [ -f "$CLIENT_CONF" ] || [ -f "$CUSTOM_CONF" ]; then
        info "Pre-cleanup: disabling leftover test objects and redeploying"
        disable_and_deploy "$tunnel" "$client" "$custom"
    fi

    if [ -n "$custom" ]; then
        info "Pre-cleanup: removing leftover custom config '$TEST_CUSTOMNAME' ($custom)"
        omv-rpc -u admin "Wireguard" "deleteCustom" "{\"uuid\":\"$custom\"}" >/dev/null 2>&1 || true
    fi
    if [ -n "$client" ]; then
        info "Pre-cleanup: removing leftover client '$TEST_CLIENTNAME' ($client)"
        omv-rpc -u admin "Wireguard" "deleteClient" "{\"uuid\":\"$client\"}" >/dev/null 2>&1 || true
    fi
    if [ -n "$tunnel" ]; then
        info "Pre-cleanup: removing leftover tunnel '$TEST_TUNNELNAME' ($tunnel)"
        omv-rpc -u admin "Wireguard" "deleteTunnel" "{\"uuid\":\"$tunnel\"}" >/dev/null 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# Cleanup trap — always runs on exit
# ---------------------------------------------------------------------------
cleanup() {
    section "Cleanup"
    if [ "$APPLIED" = "1" ]; then
        info "Disabling test objects and redeploying wireguard"
        disable_and_deploy "$TUNNEL_UUID" "$CLIENT_UUID" "$CUSTOM_UUID"
    fi
    if [ -n "$CLIENT_UUID" ]; then
        info "Deleting test client $CLIENT_UUID"
        omv-rpc -u admin "Wireguard" "deleteClient" "{\"uuid\":\"$CLIENT_UUID\"}" >/dev/null 2>&1 || true
    fi
    if [ -n "$TUNNEL_UUID" ]; then
        info "Deleting test tunnel $TUNNEL_UUID"
        omv-rpc -u admin "Wireguard" "deleteTunnel" "{\"uuid\":\"$TUNNEL_UUID\"}" >/dev/null 2>&1 || true
    fi
    if [ -n "$CUSTOM_UUID" ]; then
        info "Deleting test custom config $CUSTOM_UUID"
        omv-rpc -u admin "Wireguard" "deleteCustom" "{\"uuid\":\"$CUSTOM_UUID\"}" >/dev/null 2>&1 || true
    fi
    echo "" >&2

    # Deploy pending config changes so the OMV web UI "apply changes" banner
    # does not linger after this test run. Runs detached/async so the script
    # returns promptly; --append-dirty clears the dirty-module markers (the
    # banner) once the deploy completes.
    info "Deploying pending config changes asynchronously (clears web UI banner)"
    nohup omv-salt deploy run --quiet --append-dirty >/dev/null 2>&1 &
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
section "Pre-cleanup"
# ---------------------------------------------------------------------------
pre_cleanup

# ---------------------------------------------------------------------------
section "Pre-flight"
# ---------------------------------------------------------------------------

for cmd in omv-rpc omv-salt python3 wg; do
    if command -v "$cmd" &>/dev/null; then
        _pass "command available: $cmd"
    else
        _fail "command available: $cmd" "$cmd not found"
    fi
done

if ! omv-rpc -u admin "Config" "isDirty" '{}' &>/dev/null; then
    echo -e "\n${RED}omv-rpc not functional — aborting.${NC}" >&2
    exit 1
fi
_pass "omv-rpc functional"

# ===========================================================================
section "Tunnels — CRUD"
# ===========================================================================

assert_rpc "getTunnelList" "Wireguard" "getTunnelList" \
    '{"start":0,"limit":25,"sortfield":"tunnelnum","sortdir":"ASC"}' '"total"'

# Create
TUNNEL_CREATE=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'tunnelnum': $TEST_TUNNELNUM,
    'tunnelname': '$TEST_TUNNELNAME',
    'nic': '',
    'endpoint': '',
    'port': $TEST_TUNNELPORT,
    'iptables': False,
    'persistent': 0,
    'mtu': 0,
    'privatekeyserver': '',
    'publickeyserver': ''
}))
")
assert_rpc "setTunnel (create)" "Wireguard" "setTunnel" "$TUNNEL_CREATE"
TUNNEL_UUID=$(json_uuid "$RPC_OUT")

if [ -z "$TUNNEL_UUID" ]; then
    TUNNEL_UUID=$(recover_uuid_from_list "Wireguard" "getTunnelList" "tunnelnum" \
        "tunnelname" "$TEST_TUNNELNAME")
    [ -n "$TUNNEL_UUID" ] && info "Recovered tunnel uuid from DB: $TUNNEL_UUID"
fi
info "Created tunnel uuid=$TUNNEL_UUID"

if [ -n "$TUNNEL_UUID" ]; then
    assert_rpc "getTunnel" "Wireguard" "getTunnel" \
        "{\"uuid\":\"$TUNNEL_UUID\"}" "\"tunnelname\":\"$TEST_TUNNELNAME\""
    TUNNEL_DATA="$RPC_OUT"

    # Verify stored fields
    saved_num=$(json_get "$TUNNEL_DATA" "tunnelnum")
    if [ "$saved_num" = "$TEST_TUNNELNUM" ]; then
        _pass "getTunnel — tunnelnum correct"
    else
        _fail "getTunnel — tunnelnum" "expected $TEST_TUNNELNUM, got '$saved_num'"
    fi

    saved_port=$(json_get "$TUNNEL_DATA" "port")
    if [ "$saved_port" = "$TEST_TUNNELPORT" ]; then
        _pass "getTunnel — port correct"
    else
        _fail "getTunnel — port" "expected $TEST_TUNNELPORT, got '$saved_port'"
    fi

    # Keys should have been auto-generated (44-char base64 strings)
    saved_priv=$(json_get "$TUNNEL_DATA" "privatekeyserver")
    saved_pub=$(json_get  "$TUNNEL_DATA" "publickeyserver")
    if [ ${#saved_priv} -eq 44 ] && [ ${#saved_pub} -eq 44 ]; then
        _pass "getTunnel — keys auto-generated (44 chars each)"
    else
        _fail "getTunnel — keys auto-generated" \
            "priv=${#saved_priv} chars, pub=${#saved_pub} chars (expected 44)"
    fi

    # numro: true when keys are already set (44 chars)
    saved_numro=$(json_get "$TUNNEL_DATA" "numro")
    if [ "$saved_numro" = "True" ] || [ "$saved_numro" = "true" ] || [ "$saved_numro" = "1" ]; then
        _pass "getTunnel — numro=true (keys present)"
    else
        _fail "getTunnel — numro" "expected true, got '$saved_numro'"
    fi

    # Update — round-trip with endpoint changed; strip dynamically-added fields
    TUNNEL_UPDATE=$(echo "$TUNNEL_DATA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in ('numro', 'numclients'):
    d.pop(k, None)
d['endpoint'] = 'vpn.example.com'
print(json.dumps(d))
" 2>/dev/null)
    if [ -n "$TUNNEL_UPDATE" ]; then
        assert_rpc "setTunnel (update endpoint)" "Wireguard" "setTunnel" \
            "$TUNNEL_UPDATE" '"tunnelname"'
        saved_ep=$(json_get "$RPC_OUT" "endpoint")
        if [ "$saved_ep" = "vpn.example.com" ]; then
            _pass "setTunnel (update) — endpoint saved correctly"
        else
            _fail "setTunnel (update) — endpoint round-trip" \
                "expected 'vpn.example.com', got '$saved_ep'"
        fi
    else
        _skip "setTunnel (update endpoint)" "could not build update params"
    fi
else
    _skip "getTunnel"            "no tunnel uuid"
    _skip "setTunnel (update)"   "no tunnel uuid"
fi

# ===========================================================================
section "Tunnels — enumerate / config methods"
# ===========================================================================

assert_rpc "enumerateTunnels" "Wireguard" "enumerateTunnels" '{}'

if [ -n "$TUNNEL_UUID" ]; then
    # Verify our tunnel appears in the enumeration
    if echo "$RPC_OUT" | grep -q "\"tunnelnum\":$TEST_TUNNELNUM"; then
        _pass "enumerateTunnels — test tunnel present"
    else
        _fail "enumerateTunnels — test tunnel present" \
            "tunnelnum $TEST_TUNNELNUM not found in output"
    fi

    # Tunnel is disabled and not deployed yet; the config file is tested in
    # the Apply section.
    assert_rpc_fails "downloadTunnelConfig (no config file)" \
        "Wireguard" "downloadTunnelConfig" "{\"uuid\":\"$TUNNEL_UUID\"}"
fi

assert_rpc "downloadAllTunnelConfigs" "Wireguard" "downloadAllTunnelConfigs" '{}' '"filename"'

# ===========================================================================
section "Clients — CRUD"
# ===========================================================================

assert_rpc "getClientList" "Wireguard" "getClientList" \
    '{"start":0,"limit":25,"sortfield":"clientnum","sortdir":"ASC"}' '"total"'

# Create client associated with the test tunnel
CLIENT_CREATE=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'clientnum': $TEST_CLIENTNUM,
    'tunnelnum': $TEST_TUNNELNUM,
    'clientname': '$TEST_CLIENTNAME',
    'restrict': False,
    'vpn': False,
    'localip': False,
    'persistent': 0,
    'privatekeyclient': '',
    'publickeyclient': '',
    'presharedkeyclient': '',
    'dns': '',
    'dns2': 'disable',
    'subnets': ''
}))
")
assert_rpc "setClient (create)" "Wireguard" "setClient" "$CLIENT_CREATE"
CLIENT_UUID=$(json_uuid "$RPC_OUT")

if [ -z "$CLIENT_UUID" ]; then
    CLIENT_UUID=$(recover_uuid_from_list "Wireguard" "getClientList" "clientnum" \
        "clientname" "$TEST_CLIENTNAME")
    [ -n "$CLIENT_UUID" ] && info "Recovered client uuid from DB: $CLIENT_UUID"
fi
info "Created client uuid=$CLIENT_UUID"

if [ -n "$CLIENT_UUID" ]; then
    assert_rpc "getClient" "Wireguard" "getClient" \
        "{\"uuid\":\"$CLIENT_UUID\"}" "\"clientname\":\"$TEST_CLIENTNAME\""
    CLIENT_DATA="$RPC_OUT"

    # Verify stored fields
    saved_cnum=$(json_get "$CLIENT_DATA" "clientnum")
    if [ "$saved_cnum" = "$TEST_CLIENTNUM" ]; then
        _pass "getClient — clientnum correct"
    else
        _fail "getClient — clientnum" "expected $TEST_CLIENTNUM, got '$saved_cnum'"
    fi

    saved_tnum=$(json_get "$CLIENT_DATA" "tunnelnum")
    if [ "$saved_tnum" = "$TEST_TUNNELNUM" ]; then
        _pass "getClient — tunnelnum correct"
    else
        _fail "getClient — tunnelnum" "expected $TEST_TUNNELNUM, got '$saved_tnum'"
    fi

    # All three keys should have been auto-generated
    saved_priv=$(json_get "$CLIENT_DATA" "privatekeyclient")
    saved_pub=$(json_get  "$CLIENT_DATA" "publickeyclient")
    saved_psk=$(json_get  "$CLIENT_DATA" "presharedkeyclient")
    if [ ${#saved_priv} -eq 44 ] && [ ${#saved_pub} -eq 44 ] && [ ${#saved_psk} -eq 44 ]; then
        _pass "getClient — priv/pub/psk keys auto-generated (44 chars each)"
    else
        _fail "getClient — keys auto-generated" \
            "priv=${#saved_priv}, pub=${#saved_pub}, psk=${#saved_psk} (expected 44)"
    fi

    # getClient adds dns2 dynamically; disabled DNS → "disable"
    saved_dns2=$(json_get "$CLIENT_DATA" "dns2")
    if [ "$saved_dns2" = "disable" ]; then
        _pass "getClient — dns2 defaults to 'disable'"
    else
        _fail "getClient — dns2 default" "expected 'disable', got '$saved_dns2'"
    fi

    # Update — round-trip with persistent changed; strip dynamically-added fields
    CLIENT_UPDATE=$(echo "$CLIENT_DATA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in ('numro', 'tunnelenable', 'allowedips'):
    d.pop(k, None)
d['persistent'] = 25
print(json.dumps(d))
" 2>/dev/null)
    if [ -n "$CLIENT_UPDATE" ]; then
        assert_rpc "setClient (update persistent)" "Wireguard" "setClient" \
            "$CLIENT_UPDATE" '"clientname"'
        saved_per=$(json_get "$RPC_OUT" "persistent")
        if [ "$saved_per" = "25" ]; then
            _pass "setClient (update) — persistent=25 saved correctly"
        else
            _fail "setClient (update) — persistent round-trip" \
                "expected 25, got '$saved_per'"
        fi
    else
        _skip "setClient (update persistent)" "could not build update params"
    fi
else
    _skip "getClient"           "no client uuid"
    _skip "setClient (update)"  "no client uuid"
fi

# ===========================================================================
section "Clients — enumerate / DNS / config methods"
# ===========================================================================

assert_rpc "enumerateDns" "Wireguard" "enumerateDns" '{}'

if [ -n "$CLIENT_UUID" ]; then
    # Verify our client appears in the list with tunnelenable field
    assert_rpc "getClientList (test client present)" "Wireguard" "getClientList" \
        '{"start":0,"limit":100,"sortfield":"clientnum","sortdir":"ASC"}' \
        "\"uuid\":\"$CLIENT_UUID\""

    # Client is disabled and not deployed yet; the config file is tested in
    # the Apply section.
    assert_rpc_fails "downloadClientConfig (no config file)" \
        "Wireguard" "downloadClientConfig" "{\"uuid\":\"$CLIENT_UUID\"}"
    assert_rpc_fails "downloadQrCode (no config file)" \
        "Wireguard" "downloadQrCode" "{\"uuid\":\"$CLIENT_UUID\"}"
fi

assert_rpc "downloadAllClientConfigs" "Wireguard" "downloadAllClientConfigs" '{}' '"filename"'
assert_rpc "downloadAllQrCodes"       "Wireguard" "downloadAllQrCodes"       '{}' '"filename"'

# ===========================================================================
section "Custom configs — CRUD"
# ===========================================================================

assert_rpc "getCustomList" "Wireguard" "getCustomList" \
    '{"start":0,"limit":25,"sortfield":"name","sortdir":"ASC"}' '"total"'

CUSTOM_CREATE=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'name': '$TEST_CUSTOMNAME',
    'customcfg': '# omvtest custom wireguard config\n[Interface]\n# placeholder'
}))
")
assert_rpc "setCustom (create)" "Wireguard" "setCustom" "$CUSTOM_CREATE"
CUSTOM_UUID=$(json_uuid "$RPC_OUT")

if [ -z "$CUSTOM_UUID" ]; then
    CUSTOM_UUID=$(recover_uuid_from_list "Wireguard" "getCustomList" "name" \
        "name" "$TEST_CUSTOMNAME")
    [ -n "$CUSTOM_UUID" ] && info "Recovered custom uuid from DB: $CUSTOM_UUID"
fi
info "Created custom config uuid=$CUSTOM_UUID"

if [ -n "$CUSTOM_UUID" ]; then
    assert_rpc "getCustom" "Wireguard" "getCustom" \
        "{\"uuid\":\"$CUSTOM_UUID\"}" "\"name\":\"$TEST_CUSTOMNAME\""
    CUSTOM_DATA="$RPC_OUT"

    # Update — change customcfg content
    CUSTOM_UPDATE=$(echo "$CUSTOM_DATA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['customcfg'] = '# updated custom config'
print(json.dumps(d))
" 2>/dev/null)
    if [ -n "$CUSTOM_UPDATE" ]; then
        assert_rpc "setCustom (update customcfg)" "Wireguard" "setCustom" \
            "$CUSTOM_UPDATE" '"name"'
        saved_cfg=$(json_get "$RPC_OUT" "customcfg")
        if echo "$saved_cfg" | grep -q "updated"; then
            _pass "setCustom (update) — customcfg saved correctly"
        else
            _fail "setCustom (update) — customcfg round-trip" \
                "expected 'updated' in customcfg, got: '${saved_cfg:0:100}'"
        fi
    else
        _skip "setCustom (update customcfg)" "could not build update params"
    fi
else
    _skip "getCustom"           "no custom uuid"
    _skip "setCustom (update)"  "no custom uuid"
fi

assert_rpc "enumerateCustom" "Wireguard" "enumerateCustom" '{}'

if [ -n "$CUSTOM_UUID" ]; then
    if echo "$RPC_OUT" | grep -q "\"name\":\"$TEST_CUSTOMNAME\""; then
        _pass "enumerateCustom — test custom config present"
    else
        _fail "enumerateCustom — test custom config present" \
            "'$TEST_CUSTOMNAME' not found in enumeration"
    fi
fi

# ===========================================================================
section "Negative tests"
# ===========================================================================

BAD='{"uuid":"00000000-0000-0000-0000-000000000000"}'

# Unknown UUID → exception for every get/delete/config method
assert_rpc_fails "getTunnel — unknown uuid"           "Wireguard" "getTunnel"           "$BAD"
assert_rpc_fails "deleteTunnel — unknown uuid"        "Wireguard" "deleteTunnel"        "$BAD"
assert_rpc_fails "getTunnelConfig — unknown uuid"     "Wireguard" "getTunnelConfig"     "$BAD"
assert_rpc_fails "downloadTunnelConfig — unknown uuid" "Wireguard" "downloadTunnelConfig" "$BAD"

assert_rpc_fails "getClient — unknown uuid"           "Wireguard" "getClient"           "$BAD"
assert_rpc_fails "deleteClient — unknown uuid"        "Wireguard" "deleteClient"        "$BAD"
assert_rpc_fails "getClientConfig — unknown uuid"     "Wireguard" "getClientConfig"     "$BAD"
assert_rpc_fails "downloadClientConfig — unknown uuid" "Wireguard" "downloadClientConfig" "$BAD"
assert_rpc_fails "downloadQrCode — unknown uuid"      "Wireguard" "downloadQrCode"      "$BAD"

assert_rpc_fails "getCustom — unknown uuid"           "Wireguard" "getCustom"           "$BAD"
assert_rpc_fails "deleteCustom — unknown uuid"        "Wireguard" "deleteCustom"        "$BAD"

# Uniqueness constraints on new objects
if [ -n "$TUNNEL_UUID" ]; then
    DUP_NAME=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'tunnelnum': 98,
    'tunnelname': '$TEST_TUNNELNAME',
    'nic': '',
    'endpoint': '',
    'port': 51998,
    'iptables': False,
    'persistent': 0,
    'mtu': 0,
    'privatekeyserver': '',
    'publickeyserver': ''
}))
")
    assert_rpc_fails "setTunnel — duplicate tunnelname" "Wireguard" "setTunnel" "$DUP_NAME"

    DUP_TNUM=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'tunnelnum': $TEST_TUNNELNUM,
    'tunnelname': 'omvtest_dup_tunnelnum',
    'nic': '',
    'endpoint': '',
    'port': 51998,
    'iptables': False,
    'persistent': 0,
    'mtu': 0,
    'privatekeyserver': '',
    'publickeyserver': ''
}))
")
    assert_rpc_fails "setTunnel — duplicate tunnelnum" "Wireguard" "setTunnel" "$DUP_TNUM"

    DUP_PORT=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'tunnelnum': 98,
    'tunnelname': 'omvtest_dup_port',
    'nic': '',
    'endpoint': '',
    'port': $TEST_TUNNELPORT,
    'iptables': False,
    'persistent': 0,
    'mtu': 0,
    'privatekeyserver': '',
    'publickeyserver': ''
}))
")
    assert_rpc_fails "setTunnel — duplicate port" "Wireguard" "setTunnel" "$DUP_PORT"
else
    _skip "setTunnel — duplicate tunnelname" "no test tunnel created"
    _skip "setTunnel — duplicate tunnelnum"  "no test tunnel created"
    _skip "setTunnel — duplicate port"       "no test tunnel created"
fi

if [ -n "$CLIENT_UUID" ]; then
    DUP_CLIENT=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'clientnum': $TEST_CLIENTNUM,
    'tunnelnum': $TEST_TUNNELNUM,
    'clientname': '$TEST_CLIENTNAME',
    'restrict': False,
    'vpn': False,
    'localip': False,
    'persistent': 0,
    'privatekeyclient': '',
    'publickeyclient': '',
    'presharedkeyclient': '',
    'dns': '',
    'dns2': 'disable',
    'subnets': ''
}))
")
    assert_rpc_fails "setClient — duplicate clientname" "Wireguard" "setClient" "$DUP_CLIENT"
else
    _skip "setClient — duplicate clientname" "no test client created"
fi

if [ -n "$CUSTOM_UUID" ]; then
    DUP_CUSTOM=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'name': '$TEST_CUSTOMNAME',
    'customcfg': '# duplicate'
}))
")
    assert_rpc_fails "setCustom — duplicate name" "Wireguard" "setCustom" "$DUP_CUSTOM"
else
    _skip "setCustom — duplicate name" "no test custom config created"
fi

BAD_CUSTOM_NAME=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'name': '../omvtest',
    'customcfg': '# invalid name'
}))
")
assert_rpc_fails "setCustom — invalid name" "Wireguard" "setCustom" "$BAD_CUSTOM_NAME"

BAD_KEY=$(python3 -c "
import json
print(json.dumps({
    'uuid': '$OMV_NEW_UUID',
    'enable': False,
    'tunnelnum': 97,
    'tunnelname': 'omvtest_badkey',
    'nic': '',
    'endpoint': '',
    'port': 51997,
    'iptables': False,
    'persistent': 0,
    'mtu': 0,
    'privatekeyserver': \"'\" + 'A' * 42 + '=',
    'publickeyserver': ''
}))
")
assert_rpc_fails "setTunnel — invalid private key" "Wireguard" "setTunnel" "$BAD_KEY"

# deleteTunnel must be blocked while clients still reference the tunnel
if [ -n "$TUNNEL_UUID" ] && [ -n "$CLIENT_UUID" ]; then
    assert_rpc_fails "deleteTunnel — blocked by existing clients" \
        "Wireguard" "deleteTunnel" "{\"uuid\":\"$TUNNEL_UUID\"}"
else
    _skip "deleteTunnel — blocked by existing clients" "no test tunnel/client created"
fi

# ===========================================================================
section "Apply — enable and deploy (restarts all wireguard tunnels)"
# ===========================================================================

if [ -n "$TUNNEL_UUID" ] && [ -n "$CLIENT_UUID" ] && [ -n "$CUSTOM_UUID" ]; then
    out=$(set_enabled Tunnel "$TUNNEL_UUID" true) \
        && _pass "setTunnel (enable)" || _fail "setTunnel (enable)" "${out:0:300}"
    out=$(set_enabled Client "$CLIENT_UUID" true) \
        && _pass "setClient (enable)" || _fail "setClient (enable)" "${out:0:300}"
    CUSTOM_CFG=$(printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' \
        "$(wg genkey)" "$TEST_CUSTOMPORT")
    out=$(set_enabled Custom "$CUSTOM_UUID" true "$CUSTOM_CFG") \
        && _pass "setCustom (enable)" || _fail "setCustom (enable)" "${out:0:300}"

    APPLIED=1
    if deploy_wireguard; then
        _pass "omv-salt deploy run wireguard (enable)"
    else
        _fail "omv-salt deploy run wireguard (enable)" \
            "$(echo "$DEPLOY_OUT" | tail -n 20)"
    fi

    T_DATA=$(omv-rpc -u admin "Wireguard" "getTunnel" "{\"uuid\":\"$TUNNEL_UUID\"}" 2>/dev/null)
    C_DATA=$(omv-rpc -u admin "Wireguard" "getClient" "{\"uuid\":\"$CLIENT_UUID\"}" 2>/dev/null)
    T_PRIV=$(json_get "$T_DATA" "privatekeyserver")
    T_PUB=$(json_get "$T_DATA" "publickeyserver")
    C_PRIV=$(json_get "$C_DATA" "privatekeyclient")
    C_PUB=$(json_get "$C_DATA" "publickeyclient")
    C_PSK=$(json_get "$C_DATA" "presharedkeyclient")

    # Generated tunnel config
    if [ -f "$TUNNEL_CONF" ]; then
        _pass "tunnel config file created"
        assert_file_contains "tunnel conf — Address"    "$TUNNEL_CONF" "Address = 10.192.${TEST_TUNNELNUM}.254/24"
        assert_file_contains "tunnel conf — ListenPort" "$TUNNEL_CONF" "ListenPort = $TEST_TUNNELPORT"
        assert_file_contains "tunnel conf — PrivateKey" "$TUNNEL_CONF" "PrivateKey = $T_PRIV"
        assert_file_contains "tunnel conf — client peer" "$TUNNEL_CONF" "PublicKey = $C_PUB"
        assert_file_contains "tunnel conf — peer AllowedIPs" "$TUNNEL_CONF" \
            "AllowedIPs = 10.192.${TEST_TUNNELNUM}.${TEST_CLIENTNUM}/32"
        assert_file_contains "tunnel conf — PresharedKey" "$TUNNEL_CONF" "PresharedKey = $C_PSK"
        assert_file_lacks    "tunnel conf — no SaveConfig" "$TUNNEL_CONF" "SaveConfig"
        assert_file_lacks    "tunnel conf — no iptables rules" "$TUNNEL_CONF" "PostUp"
    else
        _fail "tunnel config file created" "$TUNNEL_CONF missing"
    fi

    # Generated client config
    if [ -f "$CLIENT_CONF" ]; then
        _pass "client config file created"
        assert_file_contains "client conf — Address"    "$CLIENT_CONF" \
            "Address = 10.192.${TEST_TUNNELNUM}.${TEST_CLIENTNUM}/24"
        assert_file_contains "client conf — PrivateKey" "$CLIENT_CONF" "PrivateKey = $C_PRIV"
        assert_file_contains "client conf — server peer" "$CLIENT_CONF" "PublicKey = $T_PUB"
        assert_file_contains "client conf — Endpoint"   "$CLIENT_CONF" \
            "Endpoint = vpn.example.com:$TEST_TUNNELPORT"
        assert_file_contains "client conf — AllowedIPs (unrestricted)" "$CLIENT_CONF" \
            "AllowedIPs = 0.0.0.0/0"
        assert_file_contains "client conf — PersistentKeepalive" "$CLIENT_CONF" \
            "PersistentKeepalive = 25"
        assert_file_lacks    "client conf — no DNS line" "$CLIENT_CONF" "DNS ="
    else
        _fail "client config file created" "$CLIENT_CONF missing"
    fi

    # Custom config
    if [ -f "$CUSTOM_CONF" ]; then
        _pass "custom config file created"
        assert_file_contains "custom conf — content" "$CUSTOM_CONF" "ListenPort = $TEST_CUSTOMPORT"
    else
        _fail "custom config file created" "$CUSTOM_CONF missing"
    fi

    # Services and live interfaces
    for svc in "wgnet${TEST_TUNNELNUM}" "wgnet_${TEST_CUSTOMNAME}"; do
        if systemctl is-active --quiet "wg-quick@$svc"; then
            _pass "wg-quick@$svc active"
        else
            _fail "wg-quick@$svc active" "$(systemctl is-active "wg-quick@$svc" 2>&1)"
        fi
    done
    port=$(wg show "wgnet${TEST_TUNNELNUM}" listen-port 2>/dev/null)
    if [ "$port" = "$TEST_TUNNELPORT" ]; then
        _pass "wg show — tunnel listen port"
    else
        _fail "wg show — tunnel listen port" "expected $TEST_TUNNELPORT, got '$port'"
    fi
    if wg show "wgnet${TEST_TUNNELNUM}" peers 2>/dev/null | grep -qF -- "$C_PUB"; then
        _pass "wg show — client peer present"
    else
        _fail "wg show — client peer present" "client public key not in peer list"
    fi
    port=$(wg show "wgnet_${TEST_CUSTOMNAME}" listen-port 2>/dev/null)
    if [ "$port" = "$TEST_CUSTOMPORT" ]; then
        _pass "wg show — custom listen port"
    else
        _fail "wg show — custom listen port" "expected $TEST_CUSTOMPORT, got '$port'"
    fi

    assert_rpc "enumerateTunnels — test tunnel running" "Wireguard" "enumerateTunnels" '{}'
    if echo "$RPC_OUT" | python3 -c "
import sys, json
rows = json.load(sys.stdin)
sys.exit(0 if any(r['tunnelnum'] == $TEST_TUNNELNUM and r['running'] for r in rows) else 1)
" 2>/dev/null; then
        _pass "enumerateTunnels — running=true"
    else
        _fail "enumerateTunnels — running=true" "test tunnel not reported running"
    fi

    # RPC methods that need the config files
    assert_rpc_bg "getTunnelConfig (bg)" "Wireguard" "getTunnelConfig" \
        "{\"uuid\":\"$TUNNEL_UUID\"}" "[Interface]"
    assert_rpc "downloadTunnelConfig" "Wireguard" "downloadTunnelConfig" \
        "{\"uuid\":\"$TUNNEL_UUID\"}" '"filename"'
    assert_rpc_bg "getClientConfig (bg)" "Wireguard" "getClientConfig" \
        "{\"uuid\":\"$CLIENT_UUID\"}" "[Interface]"
    assert_rpc "downloadClientConfig" "Wireguard" "downloadClientConfig" \
        "{\"uuid\":\"$CLIENT_UUID\"}" '"filename"'
    assert_rpc "downloadQrCode" "Wireguard" "downloadQrCode" \
        "{\"uuid\":\"$CLIENT_UUID\"}" '"filename"'

    # generateQrCodes stores a base64 PNG per client and triggers applyChanges
    assert_rpc "generateQrCodes" "Wireguard" "generateQrCodes" '{}'
    wait_for_deploys
    QR=$(json_get "$(omv-rpc -u admin "Wireguard" "getClient" \
        "{\"uuid\":\"$CLIENT_UUID\"}" 2>/dev/null)" "qr")
    if [[ "$QR" == data:image/png\;base64,* ]] && [ ${#QR} -gt 500 ]; then
        _pass "generateQrCodes — client QR stored"
    else
        _fail "generateQrCodes — client QR stored" "qr='${QR:0:80}…' (${#QR} chars)"
    fi
    if [[ "$QR" != *$'\n'* ]]; then
        _pass "generateQrCodes — QR base64 has no line breaks"
    else
        _fail "generateQrCodes — QR base64 has no line breaks" "newline found in qr"
    fi
    if echo "${QR#data:image/png;base64,}" | base64 -d 2>/dev/null | head -c 8 \
        | grep -q "PNG"; then
        _pass "generateQrCodes — QR decodes to PNG"
    else
        _fail "generateQrCodes — QR decodes to PNG" "decoded data is not a PNG"
    fi
    assert_rpc "downloadAllQrCodes (after generate)" "Wireguard" "downloadAllQrCodes" \
        '{}' '"filename"'

    # Deletes are refused while config files exist
    assert_rpc_fails "deleteTunnel — blocked by existing config file" \
        "Wireguard" "deleteTunnel" "{\"uuid\":\"$TUNNEL_UUID\"}"
    assert_rpc_fails "deleteClient — blocked by existing config file" \
        "Wireguard" "deleteClient" "{\"uuid\":\"$CLIENT_UUID\"}"
    assert_rpc_fails "deleteCustom — blocked by existing config file" \
        "Wireguard" "deleteCustom" "{\"uuid\":\"$CUSTOM_UUID\"}"

    # -----------------------------------------------------------------------
    # Teardown: disable and redeploy, files and services must be gone
    # -----------------------------------------------------------------------
    out=$(set_enabled Custom "$CUSTOM_UUID" false) \
        && _pass "setCustom (disable)" || _fail "setCustom (disable)" "${out:0:300}"
    out=$(set_enabled Client "$CLIENT_UUID" false) \
        && _pass "setClient (disable)" || _fail "setClient (disable)" "${out:0:300}"
    out=$(set_enabled Tunnel "$TUNNEL_UUID" false) \
        && _pass "setTunnel (disable)" || _fail "setTunnel (disable)" "${out:0:300}"
    if deploy_wireguard; then
        _pass "omv-salt deploy run wireguard (disable)"
        APPLIED=0
    else
        _fail "omv-salt deploy run wireguard (disable)" \
            "$(echo "$DEPLOY_OUT" | tail -n 20)"
    fi

    for f in "$TUNNEL_CONF" "$CLIENT_CONF" "$CUSTOM_CONF"; do
        if [ ! -e "$f" ]; then
            _pass "removed after disable: $(basename "$f")"
        else
            _fail "removed after disable: $(basename "$f")" "$f still exists"
        fi
    done
    for svc in "wgnet${TEST_TUNNELNUM}" "wgnet_${TEST_CUSTOMNAME}"; do
        if ! systemctl is-active --quiet "wg-quick@$svc"; then
            _pass "wg-quick@$svc stopped"
        else
            _fail "wg-quick@$svc stopped" "service still active"
        fi
    done
else
    _skip "Apply section" "test tunnel/client/custom config not all created"
fi

# ===========================================================================
section "Delete test objects"
# ===========================================================================

if [ -n "$CUSTOM_UUID" ]; then
    if [ -f "$CUSTOM_CONF" ]; then
        _skip "deleteCustom" "$CUSTOM_CONF exists — disable and apply changes first"
    else
        assert_rpc "deleteCustom" "Wireguard" "deleteCustom" \
            "{\"uuid\":\"$CUSTOM_UUID\"}" && CUSTOM_UUID=""
    fi
fi

if [ -n "$CLIENT_UUID" ]; then
    if [ -f "$CLIENT_CONF" ]; then
        _skip "deleteClient" "$CLIENT_CONF exists — disable and apply changes first"
    else
        assert_rpc "deleteClient" "Wireguard" "deleteClient" \
            "{\"uuid\":\"$CLIENT_UUID\"}" && CLIENT_UUID=""
    fi
fi

if [ -n "$TUNNEL_UUID" ]; then
    if [ -f "$TUNNEL_CONF" ]; then
        _skip "deleteTunnel" "$TUNNEL_CONF exists — disable and apply changes first"
    else
        assert_rpc "deleteTunnel" "Wireguard" "deleteTunnel" \
            "{\"uuid\":\"$TUNNEL_UUID\"}" && TUNNEL_UUID=""
    fi
fi

# Verify deleted objects are gone from list
assert_rpc "getTunnelList (after delete)" "Wireguard" "getTunnelList" \
    '{"start":0,"limit":100,"sortfield":"tunnelnum","sortdir":"ASC"}' '"total"'
if echo "$RPC_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
rows = d.get('data', d) if isinstance(d, dict) else d
found = any(r.get('tunnelname') == '$TEST_TUNNELNAME' for r in rows)
sys.exit(0 if not found else 1)
" 2>/dev/null; then
    _pass "getTunnelList — test tunnel absent after delete"
else
    _fail "getTunnelList — test tunnel absent after delete" \
        "'$TEST_TUNNELNAME' still present in list"
fi

assert_rpc "getClientList (after delete)" "Wireguard" "getClientList" \
    '{"start":0,"limit":100,"sortfield":"clientnum","sortdir":"ASC"}' '"total"'
if echo "$RPC_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
rows = d.get('data', d) if isinstance(d, dict) else d
found = any(r.get('clientname') == '$TEST_CLIENTNAME' for r in rows)
sys.exit(0 if not found else 1)
" 2>/dev/null; then
    _pass "getClientList — test client absent after delete"
else
    _fail "getClientList — test client absent after delete" \
        "'$TEST_CLIENTNAME' still present in list"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "" >&2
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}" >&2
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo -e "${RED}Failed tests:${NC}" >&2
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  - $t" >&2
    done
    exit 1
fi
exit 0
