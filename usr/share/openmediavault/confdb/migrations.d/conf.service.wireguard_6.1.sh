#!/bin/sh
#
# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    Volker Theile <volker.theile@openmediavault.org>
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2009-2013 Volker Theile
# @copyright Copyright (c) 2013-2025 openmediavault plugin developers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

set -e

. /usr/share/openmediavault/scripts/helper-functions

xpath="/config/services/wireguard/clients/client"

xmlstarlet sel -t -m "${xpath}" -v "uuid" -n ${OMV_CONFIG_FILE} |
    xmlstarlet unesc |
    while read uuid; do
        if ! omv_config_exists "${xpath}[uuid='${uuid}']/restrict"; then
            omv_config_add_key "${xpath}[uuid='${uuid}']" "restrict" "0"
        fi
        if ! omv_config_exists "${xpath}[uuid='${uuid}']/persistent"; then
            omv_config_add_key "${xpath}[uuid='${uuid}']" "persistent" "0"
        fi
    done;

exit 0
