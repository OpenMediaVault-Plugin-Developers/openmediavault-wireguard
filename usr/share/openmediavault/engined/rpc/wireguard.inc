<?php
/**
 * Copyright (C) 2019-2025 openmediavault plugin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

class OMVRpcServiceWireGuard extends \OMV\Rpc\ServiceAbstract
{
    public function getName()
    {
        return "Wireguard";
    }

    public function initialize()
    {
        $this->registerMethod("getTunnelList");
        $this->registerMethod("getTunnel");
        $this->registerMethod("setTunnel");
        $this->registerMethod("deleteTunnel");
        $this->registerMethod("getTunnelConfig");
        $this->registerMethod("downloadTunnelConfig");
        $this->registerMethod("downloadAllTunnelConfigs");
        $this->registerMethod("enumerateTunnels");

        $this->registerMethod("getClientList");
        $this->registerMethod("getClient");
        $this->registerMethod("setClient");
        $this->registerMethod("deleteClient");
        $this->registerMethod("getClientConfig");
        $this->registerMethod("downloadClientConfig");
        $this->registerMethod("downloadQrCode");
        $this->registerMethod("downloadAllClientConfigs");
        $this->registerMethod("downloadAllQrCodes");
        $this->registerMethod("generateQrCodes");
        $this->registerMethod("enumerateDns");

        $this->registerMethod("getCustomList");
        $this->registerMethod("getCustom");
        $this->registerMethod("setCustom");
        $this->registerMethod("deleteCustom");
    }

    public function getTunnelList($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.getlist");
        // Get configuration data.
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get("conf.service.wireguard.tunnel");
        // Add additional share informations.
        $objectsAssoc = [];
        foreach ($objects as $objectk => &$objectv) {
            $tunnelnum = $objectv->get("tunnelnum");
            $clients = $db->getByFilter("conf.service.wireguard.client", [
                "operator" => "stringEquals",
                "arg0" => "tunnelnum",
                "arg1" => $tunnelnum
            ]);
            // Add the new property 'sharedfoldername'.
            $objectv->add("numclients", "integer", count($clients));
            $objectsAssoc[] = $objectv->getAssoc();
        }
        // Filter the result.
        return $this->applyFilter($objectsAssoc, $params['start'], $params['limit'],
            $params['sortfield'], $params['sortdir'], $params['search']);
    }

    public function getTunnel($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Get the configuration object.
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.tunnel", $params["uuid"]);
        $ro = false;
        if (strlen($object->get("privatekeyserver")) == 44) {
            $ro = true;
        }
        $object->add("numro", "boolean", $ro);
        return ($object->getAssoc());
    }

    public function setTunnel($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.wireguard.settunnel");
        // Create keys if empty
        // privatekeyserver
        if (strlen($params["privatekeyserver"]) != 44) {
            $output = [];
            $cmdArgs = [];
            $cmdArgs[] = "genkey";
            $cmd = new \OMV\System\Process("wg", $cmdArgs);
            $cmd->execute($output);
            $params["privatekeyserver"] = $output[0];
        }
        // publickeyserver
        if (strlen($params["publickeyserver"]) != 44) {
            $output = [];
            $cmdArgs = [];
            $cmdArgs[] = sprintf("echo '%s'", $params["privatekeyserver"]);
            $cmdArgs[] = "| wg pubkey";
            $cmd = new \OMV\System\Process($cmdArgs);
            $cmd->execute($output);
            $params["publickeyserver"] = $output[0];
        }
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Prepare the configuration object.
        $object = new \OMV\Config\ConfigObject("conf.service.wireguard.tunnel");
        $object->setAssoc($params);
        // Set the configuration object.
        $isNew = $object->isNew();
        if (TRUE === $isNew) {
            // Check uniqueness - name
            $db->assertIsUnique($object, "tunnelname");
            $db->assertIsUnique($object, "tunnelnum");
            $db->assertIsUnique($object, "port");
        }
        $db->set($object);
        // Return the configuration object.
        return $object->getAssoc();
    }

    public function deleteTunnel($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Delete the configuration object.
        $object = $db->get("conf.service.wireguard.tunnel", $params["uuid"]);
        $tunnelnum = $object->get("tunnelnum");
        $conf = sprintf("/etc/wireguard/wgnet%d.conf", $tunnelnum);
        if (file_exists($conf)) {
            $msg1 = gettext("Please disable tunnel and apply changes before deleting!");
            $msg2 = sprintf("Tunnel '%s' - %s", $object->get("tunnelname"), $msg1);
            throw new \OMV\Exception($msg2);
        }
        $db->delete($object);
        // Return the deleted configuration object.
        return $object->getAssoc();
    }

    public function getTunnelConfig($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.tunnel", $params["uuid"]);
        // Create the background process.
        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename)
            use ($object) {
                $clientnum = $object->get("tunnelnum");
                $conf = sprintf("/etc/wireguard/wgnet%d.conf", $clientnum);
                if (file_exists($conf)) {
                    $cmd = new \OMV\System\Process("cat", $conf);
                    $cmdLine = $cmd->getCommandLine();
                    if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename))
                        throw new \OMV\ExecException($cmdLine, $output);
                } else {
                    $msg = gettext("Tunnel config file does not exist.  Please apply changes.");
                    throw new \OMV\Exception($msg);
                }
                return $output;
            }
        );
    }

    public function downloadTunnelConfig($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // get client info
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.tunnel", $params["uuid"]);
        $tunnelnum = $object->get("tunnelnum");
        $conf = sprintf("/etc/wireguard/wgnet%d.conf", $tunnelnum);
        if (!file_exists($conf)) {
            $msg = gettext("Tunnel config file does not exist.  Please apply changes.");
            throw new \OMV\Exception($msg);
        }
        // create temp config file
        $ts = date('Ymd_His');
        $tc = sprintf('%s/wireguard_tunnel%d_%s.conf', sys_get_temp_dir(), $tunnelnum, $ts);
        copy($conf, $tc);
        // adjust permissions on temp file
        chown($tc, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($tc, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($tc, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($tc),
            'filepath' => $tc,
            'contenttype' => 'text/plain',
            'unlink' => true
        ];
    }

    public function downloadAllTunnelConfigs($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Create a new zip archive
        $zip = new ZipArchive();
        $ts = date('Ymd_His');
        $zipfn = sprintf('%s/allTunnelConfigs_%s.zip', sys_get_temp_dir(), $ts);
        if ($zip->open($zipfn, ZipArchive::CREATE) !== true) {
            $msg = gettext("Cannot open zip file.");
            throw new \OMV\Exception($msg);
        }
        // Get configuration data
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get('conf.service.wireguard.tunnel');
        foreach ($objects as $objectk => &$objectv) {
            $tunnelnum = $objectv->get("tunnelnum");
            $conf = sprintf("/etc/wireguard/wgnet%d.conf", $tunnelnum);
            if (file_exists($conf)) {
                $zip->addFromString(basename($conf), file_get_contents($conf));
            }
        }
        $zip->close();
        // adjust permissions on temp file
        chown($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($zipfn, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($zipfn),
            'filepath' => $zipfn,
            'contenttype' => 'application/zip',
            'unlink' => true
        ];
    }

    public function enumerateTunnels($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ['role' => OMV_ROLE_ADMINISTRATOR]);
        // Get configuration data.
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get("conf.service.wireguard.tunnel");
        $tunnels = [];
        foreach ($objects as $objectk => &$objectv) {
            $tunnelnum = $objectv->get("tunnelnum");
            $tunnelname = $objectv->get("tunnelname");
            $running = false;
            if ($objectv->get("enable")) {
                $svcname = sprintf("wg-quick@wgnet%d", $tunnelnum);
                $systemCtl = new \OMV\System\SystemCtl($svcname);
                $running = $systemCtl->isActive();
            }
            $tunnels[] = [
                'tunnelnum' => $tunnelnum,
                'description' => sprintf('%s - %s', $tunnelnum, $tunnelname),
                'enabled' => $objectv->get("enable"),
                'running' => $running,
            ];
        }
        // Filter the result.
        return ($tunnels);
    }

    public function getClientList($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.getlist");
        // Get configuration data.
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get("conf.service.wireguard.client");
        // Add additional share informations.
        $objectsAssoc = [];
        foreach ($objects as $objectk => &$objectv) {
            $tunnelnum = $objectv->get("tunnelnum");
            $tunnel = $db->getByFilter("conf.service.wireguard.tunnel", [
                "operator" => "stringEquals",
                "arg0" => "tunnelnum",
                "arg1" => $tunnelnum
            ], 1);
            $restricts = [];
            if ($objectv->get("restrict")) {
                if ($objectv->get("vpn")) {
                    $restricts[] = sprintf('10.192.%d.0/24', $objectv->get("tunnelnum"));
                }
                if ($objectv->get("localip") && strlen($tunnel->get("localserver")) >= 7) {
                    $restricts[] = $tunnel->get("localserver");
                }
                if (strlen($objectv->get("subnets")) >= 7) {
                    $restricts[] = $objectv->get("subnets");
                }
                if (count($restricts) == 0) {
                    $restricts[] = "0.0.0.0/0";
                }
            } else {
                $restricts[] = "0.0.0.0/0";
            }
            $restricts = array_filter($restricts);
            $objectv->add("tunnelenable", "boolean", $tunnel->get("enable"));
            $objectv->add("allowedips", "string", implode('<br />', $restricts));
            $objectsAssoc[] = $objectv->getAssoc();
        }
        // Filter the result.
        return $this->applyFilter($objectsAssoc, $params['start'], $params['limit'],
            $params['sortfield'], $params['sortdir'], $params['search']);
    }

    public function getClient($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Get the configuration object.
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        $ro = false;
        if (strlen($object->get("privatekeyclient")) == 44) {
            $ro = true;
        }
        $object->add("numro", "boolean", $ro);
        $object->add("dns2", "string", "disable");
        if (strlen($object->get("dns")) >= 7) {
            $object->set("dns2", "custom");
        } else {
            $object->set("dns", "");
            $object->set("dns2", "disable");
        }
        return ($object->getAssoc());
    }

    public function setClient($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.wireguard.setclient");
        // Create keys if empty
        // privatekeyclient
        if (strlen($params["privatekeyclient"]) != 44) {
            $output = [];
            $cmdArgs = [];
            $cmdArgs[] = "genkey";
            $cmd = new \OMV\System\Process("wg", $cmdArgs);
            $cmd->execute($output);
            $params["privatekeyclient"] = $output[0];
        }
        // publickeyclient
        if (strlen($params["publickeyclient"]) != 44) {
            $output = [];
            $cmdArgs = [];
            $cmdArgs[] = sprintf("echo '%s'", $params["privatekeyclient"]);
            $cmdArgs[] = "| wg pubkey";
            $cmd = new \OMV\System\Process($cmdArgs);
            $cmd->execute($output);
            $params["publickeyclient"] = $output[0];
        }
        // presharedkeyclient
        if (strlen($params["presharedkeyclient"]) != 44) {
            $output = [];
            $cmdArgs = [];
            $cmdArgs[] = "genpsk";
            $cmd = new \OMV\System\Process("wg", $cmdArgs);
            $cmd->execute($output);
            $params["presharedkeyclient"] = $output[0];
        }
        // sort and deduplicate dns servers
        if ($params['dns2'] == 'disable') {
            $params['dns'] = '';
        } else {
            $dns = str_replace([':',' '], ',', $params['dns']);
            if ($params['dns2'] !== 'custom') {
                $dns .= ',' . $params['dns2'];
            }
            $dnsa = explode(',', $dns);
            // remove bad lines in paths
            foreach ($dnsa as $dnsk => &$dnsv) {
                $oct = explode('.', $dnsv);
                if ((strlen($dnsv) < 7) || ($oct[0] == 127 && $oct[3] != 53)) {
                    unset($dnsa[$dnsk]);
                }
            }
            $dnsu = array_unique($dnsa);
            asort($dnsu);
            $params['dns'] = implode(',', $dnsu);
        }
        unset($params['dns2']);
        // set localip to false if restrict is false
        if ($params['restrict'] == false) {
            $params['vpn'] = false;
            $params['localip'] = false;
            $params['subnets'] = '';
        }
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Prepare the configuration object.
        $object = new \OMV\Config\ConfigObject("conf.service.wireguard.client");
        $object->setAssoc($params);
        // Set the configuration object.
        $isNew = $object->isNew();
        if (TRUE === $isNew) {
            // Check uniqueness - name
            $db->assertIsUnique($object, "clientname");
            $db->assertIsUnique($object, "clientnum");
        }
        $db->set($object);
        // Return the configuration object.
        return $object->getAssoc();
    }

    public function deleteClient($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Delete the configuration object.
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        $clientnum = $object->get("clientnum");
        $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $clientnum);
        if (file_exists($conf)) {
            $msg1 = gettext("Please disable client and apply changes before deleting!");
            $msg2 = sprintf("Client '%s' - %s", $object->get("clientname"), $msg1);
            throw new \OMV\Exception($msg2);
        }
        $db->delete($object);
        // Return the deleted configuration object.
        return $object->getAssoc();
    }

    public function getClientConfig($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        // Create the background process.
        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename)
            use ($object) {
                $clientnum = $object->get("clientnum");
                $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $clientnum);
                if (file_exists($conf)) {
                    $cmd = new \OMV\System\Process("cat", $conf);
                    $cmdLine = $cmd->getCommandLine();
                    if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename))
                        throw new \OMV\ExecException($cmdLine, $output);
                } else {
                    $msg = gettext("Client config file does not exist.  Please apply changes.");
                    throw new \OMV\Exception($msg);
                }
                return $output;
            }
        );
    }

    public function downloadClientConfig($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // get client info
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        $clientnum = $object->get("clientnum");
        $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $clientnum);
        if (!file_exists($conf)) {
            $msg = gettext("Client config file does not exist.  Please apply changes.");
            throw new \OMV\Exception($msg);
        }
        // create temp config file
        $cc = sprintf('%s/wgnet_client%d.conf', sys_get_temp_dir(), $clientnum);
        copy($conf, $cc);
        // adjust permissions on temp file
        chown($cc, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($cc, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($cc, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($cc),
            'filepath' => $cc,
            'contenttype' => 'text/plain',
            'unlink' => true
        ];
    }

    public function downloadQrCode($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // get client info
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        $clientnum = $object->get("clientnum");
        $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $clientnum);
        // create QR code image
        $ts = date('Ymd_His');
        $qr = sprintf('%s/wireguard_client%d_qr_%s.png', sys_get_temp_dir(), $clientnum, $ts);
        if (file_exists($conf)) {
            $cmdArgs = [];
            $cmdArgs[] = 'qrencode';
            $cmdArgs[] = '--type=png';
            $cmdArgs[] = sprintf('--output=%s', $qr);
            $cmdArgs[] = sprintf('--read-from=%s', $conf);
            $cmd = new \OMV\System\Process($cmdArgs);
            $cmdLine = $cmd->getCommandLine();
            if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename)) {
                throw new \OMV\ExecException($cmdLine, $output);
            }
        } else {
            $msg = gettext("Client config file does not exist.  Please apply changes.");
            throw new \OMV\Exception($msg);
        }
        // adjust permissions on temp file
        chown($qr, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($qr, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($qr, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($qr),
            'filepath' => $qr,
            'contenttype' => 'image/png',
            'unlink' => true
        ];
    }

    public function downloadAllClientConfigs($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Create a new zip archive
        $zip = new ZipArchive();
        $ts = date('Ymd_His');
        $zipfn = sprintf('%s/allClientConfigs_%s.zip', sys_get_temp_dir(), $ts);
        if ($zip->open($zipfn, ZipArchive::CREATE) !== true) {
            $msg = gettext("Cannot open zip file.");
            throw new \OMV\Exception($msg);
        }
        $files = glob('/etc/wireguard/wgnet_client*.conf');
        foreach ($files as $file) {
            if (file_exists($file)) {
                $zip->addFromString(basename($file), file_get_contents($file));
            }
        }
        $zip->close();
        // adjust permissions on temp file
        chown($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($zipfn, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($zipfn),
            'filepath' => $zipfn,
            'contenttype' => 'application/zip',
            'unlink' => true
        ];
    }

    public function downloadAllQrCodes($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Create a new zip archive
        $zip = new ZipArchive();
        $ts = date('Ymd_His');
        $zipfn = sprintf('%s/allQRcodes_%s.zip', sys_get_temp_dir(), $ts);
        if ($zip->open($zipfn, ZipArchive::CREATE) !== true) {
            $msg = gettext("Cannot open zip file.");
            throw new \OMV\Exception($msg);
        }
        // Get configuration data
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get('conf.service.wireguard.client');
        // add each image to zip
        foreach ($objects as $objectk => &$objectv) {
            $clientnum = $objectv->get('clientnum');
            $filename = sprintf('wireguard_client%d_qr.png', $clientnum);
            $img64 = $objectv->get('qr');
            $img = base64_decode(explode(',', $img64)[1]);
            $zip->addFromString($filename, $img);
        }
        $zip->close();
        // adjust permissions on temp file
        chown($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chgrp($zipfn, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chmod($zipfn, 0600);
        // Return values required by generic download RPC implementation.
        return [
            'filename' => basename($zipfn),
            'filepath' => $zipfn,
            'contenttype' => 'application/zip',
            'unlink' => true
        ];
    }

    public function generateQrCodes($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ['role' => OMV_ROLE_ADMINISTRATOR]);
        // Get configuration data.
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->get('conf.service.wireguard.client');
        $qr = 'data:image/png;base64,';
        // 1x1 transparent base64 png
        $tiny = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/wcAAgEBAYXMlpUAAAAASUVORK5CYII=';
        // Add additional share informations.
        $objectsAssoc = [];
        foreach ($objects as $objectk => &$objectv) {
            $clientnum = $objectv->get('clientnum');
            $conf = sprintf('/etc/wireguard/wgnet_client%d.conf', $clientnum);
            if (file_exists($conf)) {
                $output = [];
                // generate qr code png and base64 encode
                $cmdArgs = [];
                $cmdArgs[] = 'qrencode';
                $cmdArgs[] = '--type=png';
                $cmdArgs[] = '--output=-';
                $cmdArgs[] = sprintf('--read-from=%s', $conf);
                $cmdArgs[] = ' | base64';
                $cmd = new \OMV\System\Process($cmdArgs);
                $cmd->execute($output);
                $img = trim(implode(PHP_EOL, $output));
            } else {
                $img = $tiny;
            }
            // put base64 string in database
            $client = $db->get('conf.service.wireguard.client', $objectv->get('uuid'));
            $client->set('qr', $qr . $img);
            $db->set($client);
        }
        // Apply changes immmediately
        \OMV\Rpc\Rpc::call('Config', 'applyChanges', [
            'modules' => [ 'wireguard' ],
            'force' => TRUE
        ], $context);
    }

    public function enumerateDns($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ['role' => OMV_ROLE_ADMINISTRATOR]);
        // Get configuration data.
        $dns = [];
        $dns[] = [ 'dns' => 'disable' ];
        $dns[] = [ 'dns' => 'custom' ];
        $ips = [];
        $resolvConf = '/etc/resolv.conf';
        if (file_exists($resolvConf)) {
            $resolv = file($resolvConf);
            foreach ($resolv as $line) {
                if (substr(trim($line), 0,10) == "nameserver") {
                    $ip = trim(str_replace("nameserver", "", $line));
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $ips[] = $ip;
                    }
                }
            }
        }
        $output = [];
        $cmdArgs = [];
        $cmdArgs[] = "resolvectl";
        $cmdArgs[] = "status";
        $cmd = new \OMV\System\Process($cmdArgs);
        $cmd->setQuiet(true);
        $cmdLine = $cmd->getCommandLine();
        if (0 === $this->exec($cmdLine, $output)) {
            $ipPattern = '/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/';
            foreach ($output as $record) {
                if (preg_match_all($ipPattern, $record, $matches)) {
                    foreach ($matches[0] as $ip) {
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $ips[] = $ip;
                        }
                    }
                }
            }
        }
        $ipsu = array_unique($ips);
        if (count($ipsu) > 1) {
            asort($ipsu);
            foreach ($ipsu as $ip) {
                $dns[] = [ 'dns' => $ip ];
            }
            $dns[] = [ 'dns' => implode(",", $ipsu) ];
        }
        return ($dns);
    }

    public function getCustomList($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.getlist");
        // Get configuration data.
        $db = \OMV\Config\Database::getInstance();
        $objects = $db->getAssoc("conf.service.wireguard.custom");
        // Filter the result.
        return $this->applyFilter($objects, $params['start'], $params['limit'],
            $params['sortfield'], $params['sortdir'], $params['search']);
    }

    public function getCustom($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Get the configuration object.
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.custom", $params["uuid"]);
        return ($object->getAssoc());
    }

    public function setCustom($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.wireguard.setcustom");
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Prepare the configuration object.
        $object = new \OMV\Config\ConfigObject("conf.service.wireguard.custom");
        $object->setAssoc($params);
        // Set the configuration object.
        $isNew = $object->isNew();
        if (TRUE === $isNew) {
            // Check uniqueness - name
            $db->assertIsUnique($object, "name");
        }
        $db->set($object);
        // Return the configuration object.
        return $object->getAssoc();
    }

    public function deleteCustom($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.objectuuid");
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Delete the configuration object.
        $object = $db->get("conf.service.wireguard.custom", $params["uuid"]);
        $customname = $object->get("name");
        $conf = sprintf("/etc/wireguard/wgnet_%s.conf", $customname);
        if (file_exists($conf)) {
            $msg1 = gettext("Please disable custom config and apply changes before deleting!");
            $msg2 = sprintf("Custom config '%s' - %s", $customname, $msg1);
            throw new \OMV\Exception($msg2);
        }
        $db->delete($object);
        // Return the deleted configuration object.
        return $object->getAssoc();
    }
}
