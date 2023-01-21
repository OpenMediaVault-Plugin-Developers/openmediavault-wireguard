<?php
/**
 * Copyright (C) 2019-2023 OpenMediaVault Plugin Developers
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
        $this->registerMethod("enumerateTunnels");

        $this->registerMethod("getClientList");
        $this->registerMethod("getClient");
        $this->registerMethod("setClient");
        $this->registerMethod("deleteClient");
        $this->registerMethod("getClientConfig");
        $this->registerMethod("enumerateDns");
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
            $params['sortfield'], $params['sortdir']);
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
            $tunnels[] = [
                'tunnelnum' => $tunnelnum,
                'description' => sprintf('%s - %s', $tunnelnum, $tunnelname)
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
            // Add the new property 'sharedfoldername'.
            $objectv->add("qrcode", "string", gettext("n/a"));
            if ($objectv->get("enable")) {
                $clientuuid = $objectv->get("uuid");
                $image = sprintf("/var/www/openmediavault/clientqrcode_%s.png", $clientuuid);
                if (file_exists($image)) {
                    $url = sprintf("<img src='/clientqrcode_%s.png?%d'>", $clientuuid, time());
                    $objectv->set("qrcode", $url);
                }
            }
            $objectsAssoc[] = $objectv->getAssoc();
        }
        // Filter the result.
        return $this->applyFilter($objectsAssoc, $params['start'], $params['limit'],
            $params['sortfield'], $params['sortdir']);
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
        if (strlen($object->get("dns")) > 7) {
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
                if ((strlen($dnsv) < 7) || (substr(0, 3, $dnsv) == 127)) {
                    unset($dnsa[$dnsk]);
                }
            }
            $dnsu = array_unique($dnsa);
            asort($dnsu);
            $params['dns'] = implode(',', $dnsu);
        }
        unset($params['dns2']);
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
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.wireguard.client", $params["uuid"]);
        // Create the background process.
        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename)
            use ($object) {
                $clientnum = $object->get("clientnum");
                $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $clientnum);
                $cmd = new \OMV\System\Process("cat", $conf);
                $cmdLine = $cmd->getCommandLine();
                if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename))
                    throw new \OMV\ExecException($cmdLine, $output);
                return $output;
            }
        );
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
        $resolv = file("/etc/resolv.conf");
        foreach ($resolv as $line) {
            if (substr(trim($line), 0,10) == "nameserver") {
                $ip = trim(str_replace("nameserver", "", $line));
                $dns[] = [ 'dns' => $ip ];
                $ips[] = $ip;
            }
        }
        $ipsu = array_unique($ips);
        if (count($ipsu) > 1) {
            asort($ipsu);
            $dns[] = [ 'dns' => implode(",", $ipsu) ];
        }
        return ($dns);
    }
}
