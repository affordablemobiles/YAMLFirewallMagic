<?php

require __DIR__ . '/class/firewallParser.class.php';

$data = new FirewallParser( 'Daventry Firewall Rules.fwcfg' );

file_put_contents('iptables.rules', $data->getOutput());