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
			var_export($a) . var_export($b);
			$this->transformToIPTables($b['rules'], $b['iptables-rules']);
		}
		/*
		// Now the interface chains...
		foreach ($this->dataArray['tables']['filter']['iface-chains'] as &$e){
			$e['iptables-rules'] = array();
			$this->transformToIPTables($e['rules'], $e['iptables-rules']);
		}
		
		// Now the service chains...
		foreach ($this->dataArray['tables']['filter']['service-chains'] as $f => &$g){
			$g['iptables-rules'] = array();
			$this->transformToIPTables($g['rules'], $g['iptables-rules']);
		}
		
		// And finally, the others...
		foreach ($this->dataArray['tables']['filter']['other-chains'] as $h => &$i){
			$i['iptables-rules'] = array();
			$this->transformToIPTables($i['rules'], $i['iptables-rules']);
		}*/
	}
	
	protected function parseGoTo(&$rule, &$result){
		return true;
	}
}