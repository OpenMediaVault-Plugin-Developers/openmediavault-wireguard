<?php
/**
 * Copyright (C) 2019-2022 OpenMediaVault Plugin Developers
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
        $this->registerMethod("getClientList");
        $this->registerMethod("getClient");
        $this->registerMethod("setClient");
        $this->registerMethod("deleteClient");
        $this->registerMethod("getClientConfig");
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
                $netnum = $objectv->get("netnum");
                $image = sprintf("/var/www/openmediavault/clientqrcode%d.png", $netnum);
                if (file_exists($image)) {
                    $url = sprintf("<img src='/clientqrcode%d.png'>", $netnum);
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
        return $db->getAssoc("conf.service.wireguard.client", $params["uuid"]);
    }

    public function setClient($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.wireguard.setclient");
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
        // Verify that shared folder is set
        $db = \OMV\Config\Database::getInstance();
        // Prepare the configuration object.
        $object = new \OMV\Config\ConfigObject("conf.service.wireguard.client");
        $object->setAssoc($params);
        // Set the configuration object.
        $isNew = $object->isNew();
        if (TRUE === $isNew) {
            // Check uniqueness - name
            $db->assertIsUnique($object, "name");
            $db->assertIsUnique($object, "netnum");
            $db->assertIsUnique($object, "port");
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
        $netnum = $object->get("netnum");
        $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $netnum);
        if (file_exists($conf)) {
            $msg1 = gettext("Please disable client and apply changes before deleting!");
            $msg2 = sprintf("Client '%s' - %s", $object->get("name"), $msg1);
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
                $netnum = $object->get("netnum");
                $conf = sprintf("/etc/wireguard/wgnet_client%d.conf", $netnum);
                $cmd = new \OMV\System\Process("cat", $conf);
                $cmdLine = $cmd->getCommandLine();
                if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename))
                    throw new \OMV\ExecException($cmdLine, $output);
                return $output;
            }
        );
	}
}
