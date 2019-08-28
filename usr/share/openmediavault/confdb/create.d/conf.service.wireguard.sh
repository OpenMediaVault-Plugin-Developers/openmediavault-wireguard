#!/bin/sh

set -e

. /usr/share/openmediavault/scripts/helper-functions

SERVICE_XPATH_NAME="wireguard"
SERVICE_XPATH="/config/services/${SERVICE_XPATH_NAME}"

keyPath="/etc/wireguard"

privateKeyServer="${keyPath}/privatekey_server"
publicKeyServer="${keyPath}/publickey_server"

privateKeyClient="${keyPath}/privatekey_client"
publicKeyClient="${keyPath}/publickey_client"

mkdir -p ${keyPath}

if ! omv_config_exists "${SERVICE_XPATH}"; then
    privkeyserver="$(wg genkey | tee ${privateKeyServer})"
    pubkeyserver="$(wg pubkey < ${privateKeyServer} | tee ${publicKeyServer})"

    privkeyclient="$(wg genkey | tee ${privateKeyClient})"
    pubkeyclient="$(wg pubkey < ${privateKeyClient} | tee ${publicKeyClient})"

    omv_config_add_node "/config/services" "${SERVICE_XPATH_NAME}"
    omv_config_add_key "${SERVICE_XPATH}" "enable" "0"
    omv_config_add_key "${SERVICE_XPATH}" "nic" ""
    omv_config_add_key "${SERVICE_XPATH}" "port" "51820"
    omv_config_add_key "${SERVICE_XPATH}" "privatekeyserver" "${privkeyserver}"
    omv_config_add_key "${SERVICE_XPATH}" "privatekeyclient" "${pubkeyserver}"
    omv_config_add_key "${SERVICE_XPATH}" "publickeyserver" "${privkeyclient}"
    omv_config_add_key "${SERVICE_XPATH}" "publickeyclient" "${pubkeyclient}"
fi

exit 0
