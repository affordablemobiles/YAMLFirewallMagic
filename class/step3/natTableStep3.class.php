<?php

class natTableStep3 extends Step3 {
	
	protected function _parse(){
		
		$this->_rulesToChain('PREROUTING', array_merge($this->dataArray['tables']['nat']['default-chains']['PREROUTING']['iptables-rules'], $this->_ipChainRules()), array( 'policy' => $this->dataArray['tables']['nat']['default-chains']['PREROUTING']['policy'], 'default' => true));
		$this->_rulesToChain('INPUT', $this->dataArray['tables']['nat']['default-chains']['INPUT']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['nat']['default-chains']['INPUT']['policy'], 'default' => true));
		$this->_rulesToChain('OUTPUT', $this->dataArray['tables']['nat']['default-chains']['OUTPUT']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['nat']['default-chains']['OUTPUT']['policy'], 'default' => true));
		$this->_rulesToChain('POSTROUTING', $this->dataArray['tables']['nat']['default-chains']['POSTROUTING']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['nat']['default-chains']['OUTPUT']['policy'], 'default' => true));
		
		foreach ($this->dataArray['tables']['nat']['ip-chains'] as $b){
			$this->_rulesToChain('ipc-' . $b['in-iface'] . '-addr-' . str_replace('.', '-', $b['ip-address']), $b['iptables-rules']);
		}
		
		foreach ($this->dataArray['tables']['nat']['other-chains'] as $a => $b){
			$this->_rulesToChain($a, $b['iptables-rules']);
		}
	}
	
	private function _rulesToChain($chain, $rules, $options = array()){
		$chain = $this->_rname($chain);
		
		if ( @is_array($this->chainsArray['nat'][$chain]) ){
			$this->logError('Error: Trying to add a chain that already exists! - ' . $chain, true);
		} else {
			$this->chainsArray['nat'][$chain] = array( 'options' => $options, 'rules' => $rules );
		}
	}
	
	private function _ipChainRules(){
		$rules = array();
		
		foreach ($this->dataArray['tables']['nat']['ip-chains'] as $b){
			$rules[] = '-i ' . $this->dataArray['interfaces'][$b['in-iface']] . ' -d ' . $b['ip-address'] . ' -j ' . $this->_rname('ipc-' . $b['in-iface'] . '-addr-' . str_replace('.', '-', $b['ip-address']));
		}
		
		return $rules;
	}
	
}

?>