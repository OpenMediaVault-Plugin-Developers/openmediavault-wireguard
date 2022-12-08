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
{% set iptab = tl.iptables %}

stop_wireguard_service_wgnet{{ tnum }}:
  service.dead:
    - name: wg-quick@wgnet{{ tnum }}
    - enable: False

remove_wireguard_conf_file{{ tnum }}:
  file.absent:
    - name: "{{ scfg }}"

{% if tl.enable | to_bool %}

configure_wireguard_wgnet{{ tnum }}_{{ tname }}_perms:
  file.managed:
    - name: "{{ scfg }}"
    - user: root
    - group: root
    - mode: 644

configure_wireguard_wgnet{{ tnum }}_{{ tname }}:
  file.append:
    - name: "{{ scfg }}"
    - text: |
        [Interface]
        Address = 10.192.{{ tnum }}.254/24
        SaveConfig = true
        ListenPort = {{ tl.port }}
        PrivateKey = {{ tl.privatekeyserver }}

{% if iptab | to_bool %}

configure_wireguard_wgnet{{ tnum }}_{{ tname }}_iptables:
  file.append:
    - name: "{{ scfg }}"
    - text: |
        PostUp = iptables -A FORWARD -i wgnet{{ tnum }} -j ACCEPT; iptables -A FORWARD -o wgnet{{ tnum }} -j ACCEPT; iptables -t nat -A POSTROUTING -o {{ tl.nic }} -j MASQUERADE
        PostDown = iptables -D FORWARD -i wgnet{{ tnum }} -j ACCEPT; iptables -D FORWARD -o wgnet{{ tnum }} -j ACCEPT; iptables -t nat -D POSTROUTING -o {{ tl.nic }} -j MASQUERADE

{% endif %}
{% endif %}

{% for ct in config.clients.client | selectattr("tunnelnum", "equalto", tnum) %}
{% set cnum = ct.clientnum %}
{% set cname = ct.clientname %}
{% set cuuid = ct.uuid %}
{% set qr = '/var/www/openmediavault/clientqrcode_' ~ cuuid ~ '.png' %}
{% set ccfg = '/etc/wireguard/wgnet_client' ~ cnum ~ '.conf' %}

remove_wireguard_conf_files{{ cnum }}:
  file.absent:
    - names:
      - "{{ qr }}"
      - "{{ ccfg }}"

{% if ct.enable | to_bool and tl.enable | to_bool %}

configure_wireguard_client_wgnet{{ cnum }}_perms:
  file.managed:
    - name: "{{ ccfg }}"
    - user: root
    - group: root
    - mode: 644

configure_wireguard_client_wgnet{{ cnum }}:
  file.append:
    - name: "{{ ccfg }}"
    - text: |
        [Interface]
        Address = 10.192.{{ tnum }}.{{ cnum }}/24
        PrivateKey = {{ ct.privatekeyclient }}
        {% if ct.dns | length > 0 and not ct.dns == "disable" %}DNS = {{ ct.dns }}{% endif %}

configure_wireguard_client_wgnet{{ cnum }}_{{ cname }}_peer:
  file.append:
    - name: "{{ ccfg }}"
    - text: |
        
        [Peer]
        PublicKey = {{ tl.publickeyserver }}
        PresharedKey = {{ ct.presharedkeyclient }}
        Endpoint = {{ tl.endpoint }}:{{ tl.port }}
        AllowedIPs = {{ "10.192." ~ tnum ~ ".0/24" if ct.restrict | to_bool else "0.0.0.0/0" }}
        {% if ct.persistent > 0 %}PersistentKeepAlive = {{ ct.persistent }}{% endif %}


create_wireguard_qr_code_wgnet{{ cnum }}:
  cmd.run:
    - name: "qrencode --type=png --output={{ qr }} --read-from={{ ccfg }}"
    - onchanges:
      - file: "{{ ccfg }}"

configure_wireguard_wgnet{{ tnum }}_{{ cname }}_peer:
  file.append:
    - name: "{{ scfg }}"
    - text: |
        
        [Peer]
        PublicKey = {{ ct.publickeyclient }}
        AllowedIPs = 10.192.{{ tnum }}.{{ cnum }}/32
        PresharedKey = {{ ct.presharedkeyclient }}
        PersistentKeepAlive = 25;

{% endif %}
{% endfor %}

{% if tl.enable | to_bool %}

start_wireguard_service_wgnet{{ tnum }}:
  service.running:
    - name: wg-quick@wgnet{{ tnum }}
    - enable: True
    - reload: true
    - watch:
      - file: "{{ scfg }}"

{% endif %}
{% endfor %}
