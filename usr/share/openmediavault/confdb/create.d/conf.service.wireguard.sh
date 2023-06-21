#!/bin/sh

set -e

. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/wireguard"; then
    omv_config_add_node "/config/services" "wireguard"
    omv_config_add_node "/config/services/wireguard" "tunnels"
    omv_config_add_node "/config/services/wireguard" "clients"
    omv_config_add_node "/config/services/wireguard" "custom"
fi

exit 0
