<?php

class mangleTableStep2 extends Step2 {
	
	protected function _parse(){
		// First, process the default chains...
		foreach ($this->dataArray['tables']['nat']['default-chains'] as $a => &$b){
			$b['iptables-rules'] = array();
			$this->transformToIPTables($b['rules'], $b['iptables-rules']);
		}
		
		// And finally, the others...
		foreach ($this->dataArray['tables']['nat']['other-chains'] as $h => &$i){
			$i['iptables-rules'] = array();
			$this->transformToIPTables($i['rules'], $i['iptables-rules']);
		}
	}
	
	protected function parseGoTo(&$rule, &$result, $default){
		if ( !empty($rule['goto']) ){
			if ( $rule['goto'] == 'MARK' ){
				if ( !empty($rule['set-mark']) ){
					$this->appendToRule("-j MARK --set-mark " . $rule['set-mark'], $result);
					$this->array_remove_key($rule, "goto", "set-mark");
					return true;
				} else {
					$this->logError('Error: You can\'t have MARK without set-mark - ' . var_export($rule, true), true);
				}
			} else if ( $rule['goto'] == 'RETURN' ){
				$this->appendToRule("-j RETURN", $result);
				$this->array_remove_key($rule, "goto");
				return true;
			} else {
				$this->logError('Error: Invalid goto Specified for Rule (mangle) - ' . var_export($rule, true), true);
			}
		} else {
			return false;
		}
	}
}