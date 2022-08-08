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

{% for tl in config.tunnels.tunnel %}
{% set tnum = tl.tunnelnum %}
{% set tname = tl.tunnelname %}
{% set scfg = '/etc/wireguard/wgnet' ~ tnum ~ '.conf' %}
{% if tl.enable | to_bool %}

configure_wireguard_wgnet{{ tnum }}_{{ tname }}:
  file.managed:
    - name: "{{ scfg }}"
    - content: |
        [Interface]
        Address = 10.192.{{ tnum }}.1/24
        SaveConfig = true
        ListenPort = {{ tl.port }}
        PostUp = iptables -A FORWARD -i wgnet{{ tnum }} -j ACCEPT; iptables -A FORWARD -o wgnet{{ tnum }} -j ACCEPT; iptables -t nat -A POSTROUTING -o {{ tl.nic }} -j MASQUERADE
        PostDown = iptables -D FORWARD -i wgnet{{ tnum }} -j ACCEPT; iptables -D FORWARD -o wgnet{{ tnum }} -j ACCEPT; iptables -t nat -D POSTROUTING -o {{ tl.nic }} -j MASQUERADE
        PrivateKey = {{ tl.privatekeyserver }}
    - user: root
    - group: root
    - mode: 644

{% else %}

stop_wireguard_service_wgnet{{ tnum }}:
  service.dead:
    - name: wg-quick@wgnet{{ tnum }}
    - enable: False

remove_wireguard_conf_file{{ tnum }}:
  file.absent:
    - names:
      - "{{ scfg }}"

{% endif %}

{% for ct in config.clients.client | selectattr("tunnelnum", "equalto", tnum) %}
{% set cnum = ct.clientnum %}
{% set cname = ct.clientname %}
{% set qr = '/var/www/openmediavault/clientqrcode' ~ cnum ~ '.png' %}
{% set ccfg = '/etc/wireguard/wgnet_client' ~ cnum ~ '.conf' %}
{% if ct.enable | to_bool and tl.enable | to_bool %}

configure_wireguard_client_wgnet{{ cnum }}:
  file.managed:
    - name: "{{ ccfg }}"
    - content: |
        [Interface]
        Address = 10.192.{{ tnum }}.{{ cnum }}/32
        PrivateKey = {{ ct.privatekeyclient }}
    - user: root
    - group: root
    - mode: 644

configure_wireguard_wgnet{{ tnum }}_{{ cname }}_peer:
  file.append:
    - name: "{{ scfg }}"
    - text: |
        [Peer]
        PublicKey = {{ ct.publickeyclient }}
        AllowedIPs = 10.192.{{ tnum }}.{{ cnum }}/32
        PresharedKey = {{ ct.presharedkeyclient }}

configure_wireguard_client_wgnet{{ cnum }}_{{ cname }}_peer:
  file.append:
    - name: "{{ ccfg }}"
    - text: |
        [Peer]
        PublicKey = {{ tl.publickeyserver }}
        PresharedKey = {{ ct.presharedkeyclient }}
        Endpoint = {{ tl.endpoint }}:{{ tl.port }}
        AllowedIPs = 0.0.0.0/0

start_wireguard_service_wgnet{{ tnum }}_{{ cname }}:
  service.running:
    - name: wg-quick@wgnet{{ tnum }}
    - enable: True
    - reload: true
    - watch:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"

create_wireguard_qr_code_wgnet{{ cnum }}:
  cmd.run:
    - name: "qrencode --type=png --output={{ qr }} --read-from={{ ccfg }}"
    - onchanges:
      - file: "{{ ccfg }}"
      - file: "{{ scfg }}"

{% else %}

remove_wireguard_conf_files{{ cnum }}:
  file.absent:
    - names:
      - "{{ qr }}"
      - "{{ ccfg }}"

{% endif %}
{% endfor %}
{% endfor %}
