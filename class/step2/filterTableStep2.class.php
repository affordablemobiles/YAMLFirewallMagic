<?php

class filterTableStep2 extends Step2 {
	
	protected function _parse(){
		// First, process the default chains...
		foreach ($this->dataArray['tables']['filter']['default-chains'] as $a => &$b){
			$b['iptables-rules'] = array();
			$this->transformToIPTables($b['rules'], $b['iptables-rules']);
		}
		
		// Then process the firewall chains...
		foreach ($this->dataArray['tables']['filter']['fw-chains'] as $a => &$b){
			$b['iptables-rules'] = array();
			$this->transformToIPTables($b['rules'], $b['iptables-rules'], $b['default-goto']);
		}
		
		// Now the interface chains...
		foreach ($this->dataArray['tables']['filter']['iface-chains'] as &$e){
			$e['iptables-rules'] = array();
			$this->transformToIPTables($e['rules'], $e['iptables-rules'], $b['default-goto']);
		}
		
		// Now the service chains...
		foreach ($this->dataArray['tables']['filter']['service-chains'] as $f => &$g){
			$g['iptables-rules'] = array();
			$this->transformToIPTables($g['rules'], $g['iptables-rules'], $b['default-goto']);
		}
		
		// And finally, the others...
		foreach ($this->dataArray['tables']['filter']['other-chains'] as $h => &$i){
			$i['iptables-rules'] = array();
			$this->transformToIPTables($i['rules'], $i['iptables-rules'], $b['default-goto']);
		}
	}
	
	protected function parseGoTo(&$rule, &$result, $default = null){
		if ( (!empty($rule['goto'])) && (!empty($rule['goto-service'])) ){
			$this->logError('Error: You can\'t have goto and goto-service in the same rule', true);
		} else {
			if (!empty($rule['goto'])){
				$valid = array('ACCEPT', 'REJECT', 'DROP', 'RETURN');
				$valid = array_merge($valid, array_keys($this->dataArray['tables']['filter']['other-chains']));
				if (in_array($rule['goto'], $valid)){
					$this->appendToRule("-j " . $rule['goto'], $result);
					$this->array_remove_key($rule, "goto");
					return true;
				} else {
					$this->logError('Error: Invalid goto Target', true);
				}
			} else if (!empty($rule['goto-service'])){
				if (in_array($rule['goto-service'], array_keys($this->dataArray['tables']['filter']['service-chains']))){
					$this->appendToRule("-j service-" . $rule['goto-service'], $result);
					$this->array_remove_key($rule, "goto-service");
					return true;
				} else {
					$this->logError('Error: Invalid goto-service Target');
				}
			} else if (!empty($default)) {
				$valid = array('ACCEPT', 'REJECT', 'DROP', 'RETURN');
				if (in_array($default, $valid)){
					$this->appendToRule("-j " . $default, $result);
					return true;
				}
			} else {
				return false;
			}
		}
	}
}