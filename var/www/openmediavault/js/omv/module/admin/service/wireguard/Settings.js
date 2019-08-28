/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2019 OpenMediaVault Plugin Developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
// require("js/omv/WorkspaceManager.js")
// require("js/omv/workspace/form/Panel.js")

Ext.define("OMV.module.admin.service.wireguard.Settings", {
    extend: "OMV.workspace.form.Panel",

    rpcService: "WireGuard",
    rpcGetMethod: "getSettings",
    rpcSetMethod: "setSettings",

    getFormItems: function () {
        return [{
            xtype: "fieldset",
            title: _("General settings"),
            fieldDefaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "checkbox",
                name: "enable",
                fieldLabel: _("Enable"),
                checked: false
            },{
                xtype: "combo",
                name: "nic",
                fieldLabel: _("Interface"),
                emptyText: _("Select an interface ..."),
                allowBlank: false,
                allowNone: false,
                editable: false,
                triggerAction: "all",
                displayField: "devicename",
                valueField: "devicename",
                store: Ext.create("OMV.data.Store", {
                    autoLoad: true,
                    model: OMV.data.Model.createImplicit({
                        idProperty: "devicename",
                        fields: [
                            { name: "devicename", type: "string" },
                            { name: "address", type: "string" },
                            { name: "netmask", type: "string" },
                            { name: "gateway", type: "string" },
                            { name: "method6", type: "string" },
                            { name: "address6", type: "string" },
                            { name: "netmask6", type: "int" },
                            { name: "gateway6", type: "string" },
                            { name: "ether", type: "string" },
                            { name: "mtu", type: "string" },
                            { name: "link", type: "boolean" },
                            { name: "speed", type: "int" }
                        ]
                    }),
                    proxy: {
                        type: "rpc",
                        rpcData: {
                            service: "Network",
                            method: "enumerateDevicesList",
                            options: {
                                updatelastaccess: false
                            }
                        }
                    },
                    sorters: [{
                        direction: "ASC",
                        property: "devicename"
                    }]
                })
            },{
                xtype: "textfield",
                name: "endpoint",
                value: "",
                fieldLabel: _("Endpoint address")
            },{
                xtype: "numberfield",
                name: "port",
                fieldLabel: _("Port"),
                vtype: "port",
                minValue: 1,
                maxValue: 65535,
                allowDecimals: false,
                allowBlank: false,
                value: 51820
            },{
                xtype: "textfield",
                name: "privatekeyserver",
                value: "",
                readOnly: true,
                fieldLabel: _("Private key - server")
            },{
                xtype: "textfield",
                name: "privatekeyclient",
                value: "",
                readOnly: true,
                fieldLabel: _("Private key - client")
            },{
                xtype: "textfield",
                name: "publickeyserver",
                value: "",
                readOnly: true,
                fieldLabel: _("Public key - server")
            },{
                xtype: "textfield",
                name: "publickeyclient",
                value: "",
                readOnly: true,
                fieldLabel: _("Public key - client")
            }]
        }];
    }
});

OMV.WorkspaceManager.registerPanel({
    id: "settings",
    path: "/service/wireguard",
    text: _("Settings"),
    position: 10,
    className: "OMV.module.admin.service.wireguard.Settings"
});
