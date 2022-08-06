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

{% for client in config.clients.client %}

{% set qr = '/var/www/openmediavault/clientqrcode' ~ client.netnum ~ '.png' %}
{% set scfg = '/etc/wireguard/wgnet' ~ client.netnum ~ '.conf' %}
{% set ccfg = '/etc/wireguard/wgnet_client' ~ client.netnum ~ '.conf' %}

{% if client.enable | to_bool %}

configure_wireguard_wgnet{{ client.netnum }}:
  file.managed:
    - name: "{{ scfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_conf.j2
    - template: jinja
    - context:
        config: {{ client | json }}
    - user: root
    - group: root
    - mode: 644

configure_wireguard_client_wgnet{{ client.netnum }}:
  file.managed:
    - name: "{{ ccfg }}"
    - source:
      - salt://{{ tpldir }}/files/etc-wireguard-wgnet_client_conf.j2
    - template: jinja
    - context:
        config: {{ client | json }}
    - user: root
    - group: root
    - mode: 644

start_wireguard_service_wgnet{{ client.netnum }}:
  service.running:
    - name: wg-quick@wgnet{{ client.netnum }}
    - enable: True
    - reload: true
    - watch:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"

create_wireguard_qa_code_wgnet{{ client.netnum }}:
  cmd.run:
    - name: "qrencode --type=png --output={{ qr }} --read-from={{ ccfg }}"
    - watch:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"

{% else %}

stop_wireguard_service_wgnet{{ client.netnum }}:
  service.dead:
    - name: wg-quick@wgnet{{ client.netnum }}
    - enable: False

remove_wireguard_conf_files{{ client.netnum }}:
  file.absent:
    - names:
      - "{{ qr }}"
      - "{{ ccfg }}"
      - "{{ scfg }}"

{% endif %}
{% endfor %}
