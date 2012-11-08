<?php

abstract class Step2 extends logableBase {
	protected $dataArray;
	
	public function __construct(&$dataArray){
		$this->dataArray =& $dataArray;
		
		$this->_parse();
	}
	
	abstract protected function _parse();
	
	abstract protected function parseGoTo(&$rule, &$result);
	
	protected function transformToIPTables(&$rulesArray, &$IPTablesArray){
		// Loop through the rules...
		foreach ($rulesArray as &$initrule){
			// Create a copy of the rule incase we have to error out...
			$rule = $initrule;
			
			// Blank IPTables Text...
			$iptables = '';
			
			// First check for source...
			if (!empty($rule['source'])){
				if ($this->checkIP($rule['source']) == 2){
					// We've already got CIDR notation, leave as is...
					$this->appendToRule("-s " . $rule['source'], $iptables);
				} else {
					// We've got a single IP address, so put /32 at the end.
					$this->appendToRule("-s " . $rule['source'] . '/32', $iptables);
				}
				// Now remove source from the initial array since it matched...
				$this->array_remove_key($rule, "source");
			}
			
			// Check for destination...
			if (!empty($rule['destination'])){
				if ($this->checkIP($rule['destination']) == 2){
					// We've already got CIDR notation, leave as is...
					$this->appendToRule("-d " . $rule['destination'], $iptables);
				} else {
					// We've got a single IP address, so put /32 at the end.
					$this->appendToRule("-d " . $rule['destination'] . '/32', $iptables);
				}
				// Now remove source from the initial array since it matched...
				$this->array_remove_key($rule, "destination");
			}
			
			// Check for a protocol definition...
			if (!empty($rule['proto'])){
				$valid = array('tcp', 'udp', 'icmp');
				$sdport = array('tcp', 'udp');
				if (in_array($rule['proto'], $valid)){
					$this->appendToRule("-p " . $rule['proto'], $iptables);
					if (in_array($rule['proto'], $sdport)){
						if ( (!empty($rule['dport'])) || (!empty($rule['sport'])) ){
							$this->appendToRule("-m " . $rule['proto'], $iptables);
							if ( !empty($rule['dport']) ){
								$this->appendToRule("--dport " . $rule['dport'], $iptables);
								$this->array_remove_key($rule, "dport");
							}
							if ( !empty($rule['sport']) ){
								$this->appendToRule("--sport " . $rule['sport'], $iptables);
								$this->array_remove_key($rule, "sport");
							}
						}
					}
					$this->array_remove_key($rule, "proto");
				} else {
					$this->logError('Error: Invalid Protocol Specified - ' . var_export($initrule, true), true);
				}
			} else {
				if ( (!empty($rule['dport'])) || (!empty($rule['sport'])) ){
					$this->logError('Error: dport or sport specified without proto - ' . var_export($initrule, true), true);
				}
			}
			
			// Now check for the in-iface
			if(!empty($rule['in-iface'])){
				if(in_array($rule['in-iface'], array_keys($this->dataArray['interfaces']))){
					$this->appendToRule("-i " . $this->dataArray['interfaces'][$rule['in-iface']], $iptables);
					$this->array_remove_key($rule, "in-iface");
				} else {
					$this->logError('Error: Invalid in-iface - ' . var_export($initrule, true), true);
				}
			}
			
			// And check for the out-iface
			if(!empty($rule['out-iface'])){
				if(in_array($rule['out-iface'], array_keys($this->dataArray['interfaces']))){
					$this->appendToRule("-o " . $this->dataArray['interfaces'][$rule['out-iface']], $iptables);
					$this->array_remove_key($rule, "out-iface");
				} else {
					$this->logError('Error: Invalid out-iface - ' . var_export($initrule, true), true);
				}
			}
			
			// And the custom IPTables input.
			$ipt = false;
			if (!empty($rule['iptables'])){
				$ipt = true;
				$this->appendToRule($rule['iptables'], $iptables);
				$this->array_remove_key($rule, "iptables");
			}
			
			// Then parse the goto...
			if ( $ipt || $this->parseGoTo($rule, $iptables) ){
				// Ok we're done, add the iptables text to the array...
				$IPTablesArray[] = $iptables;
			} else {
				$this->logError('Error: No valid go-to or iptables code specified - ' . var_export($initrule, true), true);
			}
		}
	}
	
	protected function appendToRule($append, &$rule){
		if (@substr($rule, -1, 1) == ' '){
			$rule = $rule . $append;
		} else {
			$rule = $rule . ' ' . $append;
		}
	}
	
	protected function checkIP($ip){
		// First check if it is just a valid IP address...
		if ( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ){
			return 1;
		} else {
			// Check if we have CIDR notation...
			$a = explode('/', $ip);
			if (count($a) == 2){
				// Looks like we do have CIDR - Validate the IP and then the CIDR.
				if ( filter_var($a[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ){
					if ( (int)$a[1] > 0 && (int)$a[1] < 33 ){
						return 2;
					} else {
						$this->logError('Invalid CIDR Notation - ' . $ip, true);
					}
				} else {
					$this->logError('Invalid IP Address (CIDR) - ' . $ip, true);
				}
			} else {
				$this->logError('Invalid IP Address (CIDR) - ' . $ip, true);
			}
		}
	}
	
	// Usage: $this->array_remove_key($array, $key1, $key2, etc);
	protected function array_remove_key(){
		$args  = func_get_args();
		return array_diff_key($args[0],array_flip(array_slice($args,1)));
	}

	// Usage: $this->array_remove_value($array, $value1, $value2, etc);
	protected function array_remove_value(){
		$args = func_get_args();
		return array_diff($args[0],array_slice($args,1));
	}
	
}