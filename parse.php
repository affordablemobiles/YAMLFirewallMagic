<?php

require __DIR__ . '/class/firewallParser.class.php';

//$data = new FirewallParser( 'Daventry Firewall Rules.fwcfg' );

//file_put_contents('iptables.rules', $data->getOutput());

$cmdopts = getopt('hwso', array('help', 'overwrite', 'quiet', 'stdout'));
		
//-----------------------------
// Check if we need to display
// the help.
//-----------------------------
if ( (@$cmdopts['h'] === false) || (@$cmdopts['help'] === false) ){
	echo 'YAMLFirewallMagic - Infitialis Web Services v0.1 ALPHA';
	echo "\n" . 'fwcompile [<options>] <INPUT FILE> [<OUTPUT FILE>] - Compile YAML firewall config down to iptables-save format.';
	echo "\n\n" . 'Options:';
	echo "\n" . '    -h  ' . str_pad('--help', 14, ' ') . ' - Display this help message.';
	echo "\n" . '    -w  ' . str_pad('--overwrite', 14, ' ') . ' - Overwrite output file if it already exists.';
	echo "\n" . '    -s  ' . str_pad('--quiet', 14, ' ') . ' - Supress warning messages.';
	echo "\n" . '    -o  ' . str_pad('--stdout', 14, ' ') . ' - Print output to stdout.';
	echo "\n";
	exit();
}

if ( (@$cmdopts['o'] === false) || (@$cmdopts['stdout'] === false) ){
	if (count($_SERVER['argv']) > 1){
		$file = array_pop($_SERVER['argv']);
		
		if (is_file(getcwd() . '/' . $file)){
			$data = new FirewallParser( realpath(getcwd() . '/' . $file) );
			
			echo $data->getOutput();
		} else {
			die('Error');
		}
	} else {
		die('Error');
	}
} else {
	
}