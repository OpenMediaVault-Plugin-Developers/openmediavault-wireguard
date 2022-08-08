# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2019-2022 OpenMediaVault Plugin Developers
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

{% set config = salt['omv_conf.get']('conf.service.wireguard') %}

{% for tunnel in config.tunnels.tunnel %}
{% set scfg = '/etc/wireguard/wgnet' ~ tunnel.tunnelnum ~ '.conf' %}
{% if tunnel.enable | to_bool %}

configure_wireguard_wgnet{{ tunnel.tunnelnum }}:
  file.managed:
    - name: "{{ scfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_conf.j2
    - template: jinja
    - context:
        tunnel: {{ tunnel | json }}
    - user: root
    - group: root
    - mode: 644

{% else %}

stop_wireguard_service_wgnet{{ tunnel.tunnelnum }}:
  service.dead:
    - name: wg-quick@wgnet{{ tunnel.tunnelnum }}
    - enable: False

remove_wireguard_conf_file{{ tunnel.tunnelnum }}:
  file.absent:
    - names:
      - "{{ scfg }}"

{% endif %}

{% for client in config.clients.client | selectattr("tunnelnum", "equalto", tunnel.tunnelnum) %}
{% set qr = '/var/www/openmediavault/clientqrcode' ~ client.clientnum ~ '.png' %}
{% set ccfg = '/etc/wireguard/wgnet_client' ~ client.clientnum ~ '.conf' %}
{% if client.enable | to_bool %}

configure_wireguard_client_wgnet{{ client.clientnum }}:
  file.managed:
    - name: "{{ ccfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_client_conf.j2
    - template: jinja
    - context:
        client: {{ client | json }}
    - user: root
    - group: root
    - mode: 644

configure_wireguard_wgnet{{ tunnel.tunnelnum }}_peer:
  file.append:
    - name: "{{ scfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_conf_peer.j2
    - template: jinja
    - context:
        tunnel: {{ tunnel | json }}
        client: {{ client | json }}

configure_wireguard_client_wgnet{{ client.clientnum }}_peer:
  file.append:
    - name: "{{ ccfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_client_conf_peer.j2
    - template: jinja
    - context:
        tunnel: {{ tunnel | json }}
        client: {{ client | json }}

start_wireguard_service_wgnet{{ tunnel.tunnelnum }}:
  service.running:
    - name: wg-quick@wgnet{{ tunnel.tunnelnum }}
    - enable: True
    - reload: true
    - watch:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"

create_wireguard_qa_code_wgnet{{ client.clientnum }}:
  cmd.run:
    - name: "qrencode --type=png --output={{ qr }} --read-from={{ ccfg }}"
    - onchanges:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"
{% else %}

remove_wireguard_conf_files{{ client.clientnum }}:
  file.absent:
    - names:
      - "{{ qr }}"
      - "{{ ccfg }}"

{% endif %}
{% endfor %}
{% endfor %}
