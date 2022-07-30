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
presharedKeyClient="${keyPath}/presharedkey_client"

mkdir -p ${keyPath}

if ! omv_config_exists "${SERVICE_XPATH}"; then
    privkeyserver="$(wg genkey | tee ${privateKeyServer})"
    pubkeyserver="$(wg pubkey < ${privateKeyServer} | tee ${publicKeyServer})"

    privkeyclient="$(wg genkey | tee ${privateKeyClient})"
    pubkeyclient="$(wg pubkey < ${privateKeyClient} | tee ${publicKeyClient})"
    prekeyclient="$(wg genpsk > ${presharedKeyClient})"

    omv_config_add_node "/config/services" "${SERVICE_XPATH_NAME}"
    omv_config_add_key "${SERVICE_XPATH}" "enable" "0"
    omv_config_add_key "${SERVICE_XPATH}" "nic" ""
    omv_config_add_key "${SERVICE_XPATH}" "endpoint" ""
    omv_config_add_key "${SERVICE_XPATH}" "port" "51820"
    omv_config_add_key "${SERVICE_XPATH}" "privatekeyserver" "${privkeyserver}"
    omv_config_add_key "${SERVICE_XPATH}" "publickeyserver" "${pubkeyserver}"
    omv_config_add_key "${SERVICE_XPATH}" "privatekeyclient" "${privkeyclient}"
    omv_config_add_key "${SERVICE_XPATH}" "publickeyclient" "${pubkeyclient}"
    omv_config_add_key "${SERVICE_XPATH}" "presharedkeyclient" "${prekeyclient}"
fi

if [ -z "$(omv_config_get "${SERVICE_XPATH}/privatekeyserver")" ]; then
    omv_config_update "${SERVICE_XPATH}/privatekeyserver" "$(cat ${privateKeyServer})"
fi
if [ -z "$(omv_config_get "${SERVICE_XPATH}/publickeyserver")" ]; then
    omv_config_update "${SERVICE_XPATH}/publickeyserver" "$(cat ${publicKeyServer})"
fi
if [ -z "$(omv_config_get "${SERVICE_XPATH}/privatekeyclient")" ]; then
    omv_config_update "${SERVICE_XPATH}/privatekeyclient" "$(cat ${privateKeyClient})"
fi
if [ -z "$(omv_config_get "${SERVICE_XPATH}/publickeyclient")" ]; then
    omv_config_update "${SERVICE_XPATH}/publickeyclient" "$(cat ${publicKeyClient})"
fi
if [ -z "$(omv_config_get "${SERVICE_XPATH}/presharedkeyclient")" ]; then
    omv_config_update "${SERVICE_XPATH}/presharedkeyclient" "$(cat ${presharedKeyClient})"
fi

exit 0