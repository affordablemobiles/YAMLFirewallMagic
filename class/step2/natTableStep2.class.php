<?php

class natTableStep2 extends Step2 {
	
	protected function _parse(){
		// First, process the default chains...
		foreach ($this->dataArray['tables']['nat']['default-chains'] as $a => &$b){
			$b['iptables-rules'] = array();
			$this->transformToIPTables($b['rules'], $b['iptables-rules']);
		}
		
		// Now the IP chains...
		foreach ($this->dataArray['tables']['nat']['ip-chains'] as &$e){
			$e['iptables-rules'] = array();
			$this->transformToIPTables($e['rules'], $e['iptables-rules']);
		}
		
		// And finally, the others...
		foreach ($this->dataArray['tables']['nat']['other-chains'] as $h => &$i){
			$i['iptables-rules'] = array();
			$this->transformToIPTables($i['rules'], $i['iptables-rules']);
		}
	}
	
	protected function parseGoTo(&$rule, &$result, $default = null){
		if ( !empty($rule['goto']) ){
			if ( $rule['goto'] == 'DNAT' ){
				if ( !empty($rule['to']) ){
					$a = explode(':', $rule['to']);
					if ( $this->checkIP($a[0]) === 1 ){
						$b = implode(':', $a);
						$this->appendToRule("-j DNAT --to-destination " . $b, $result);
						$this->array_remove_key($rule, "goto", "to");
						return true;
					} else {
						$this->logError('Error: Invalid IP Address in DNAT rule - ' . var_export($rule, true), true);
					}
				} else if ( !empty($rule['to-destination']) ){
					$a = explode(':', $rule['to-destination']);
					if ( $this->checkIP($a[0]) === 1 ){
						$b = implode(':', $a);
						$this->appendToRule("-j DNAT --to-destination " . $b, $result);
						$this->array_remove_key($rule, "goto", "to-destination");
						return true;
					} else {
						$this->logError('Error: Invalid IP Address in DNAT rule - ' . var_export($rule, true), true);
					}
				} else {
					$this->logError('Error: goto of DNAT specified without a to-destination - ' . var_export($rule, true), true);
				}
			} else if ( $rule['goto'] == 'SNAT' ){
				if ( !empty($rule['to']) ){
					$a = explode(':', $rule['to']);
					if ( $this->checkIP($a[0]) === 1 ){
						$b = implode(':', $a);
						$this->appendToRule("-j SNAT --to-source " . $b, $result);
						$this->array_remove_key($rule, "goto", "to");
						return true;
					} else {
						$this->logError('Error: Invalid IP Address in DNAT rule - ' . var_export($rule, true), true);
					}
				} else if ( !empty($rule['to-source']) ){
					$a = explode(':', $rule['to-source']);
					if ( $this->checkIP($a[0]) === 1 ){
						$b = implode(':', $a);
						$this->appendToRule("-j SNAT --to-source " . $b, $result);
						$this->array_remove_key($rule, "goto", "to-source");
						return true;
					} else {
						$this->logError('Error: Invalid IP Address in SNAT rule - ' . var_export($rule, true), true);
					}
				} else {
					$this->logError('Error: goto of SNAT specified without a to-source - ' . var_export($rule, true), true);
				}
			} else if ( $rule['goto'] == 'REDIRECT' ){
				if ( !empty($rule['to']) ){
					$this->appendToRule("-j REDIRECT --to-ports " . $rule['to'], $result);
					$this->array_remove_key($rule, "goto", "to");
					return true;
				} else if ( !empty($rule['to-ports']) ){
					$this->appendToRule("-j REDIRECT --to-ports " . $rule['to-ports'], $result);
					$this->array_remove_key($rule, "goto", "to-ports");
					return true;
				} else {
					$this->logError('Error: goto of REDIRECT specified without a to-ports - ' . var_export($rule, true), true);
				}
			} else if ( $rule['goto'] == 'RETURN' ){
				$this->appendToRule("-j RETURN", $result);
				$this->array_remove_key($rule, "goto");
				return true;
			} else if ( in_array($rule['goto'], array_keys($this->dataArray['tables']['nat']['other-chains'])) ){
				$this->appendToRule("-j " . $rule['goto'], $result);
				$this->array_remove_key($rule, "goto");
				return true;
			} else {
				$this->logError('Error: Invalid goto Specified for Rule (NAT) - ' . var_export($rule, true), true);
			}
		} else {
			return false;
		}
	}
}