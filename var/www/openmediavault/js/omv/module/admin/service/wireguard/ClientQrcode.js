/**
 * @license     http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author      OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright   Copyright (c) 2019 OpenMediaVault Plugin Developers
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

Ext.define("OMV.module.admin.service.wireguard.ClientQrcode", {
    extend: "OMV.workspace.form.Panel",

    rpcService: "WireGuard",
    rpcGetMethod: "getClientQrcode",

    hideOkButton: true,
    hideResetButton: true,

    getButtonItems: function() {
        var me = this;
        var items = me.callParent(arguments);
        items.push({
            id: me.getId() + "-refresh",
            xtype: "button",
            text: _("Refresh"),
            icon: "images/refresh.png",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            scope: me,
            handler: function() {
                me.doReload();
            }
        });
        return items;
    },

    getFormItems: function() {
        return [{
            xtype: "fieldset",
            title: _("Scan this QR code in your client."),
            fieldDefaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "image",
                name: "clientQrcode",
                src: "images/clientqrcode.png",
                height: 171,
                width: 171
            }]
        }];
    }
});

OMV.WorkspaceManager.registerPanel({
    id: "clientqrcode",
    path: "/service/wireguard",
    text: _("Client QR Code"),
    position: 20,
    className: "OMV.module.admin.service.wireguard.ClientQrcode"
});
