<?php

class filterTableStep3 extends Step3 {
	
	protected function _parse(){
		
		$this->_rulesToChain('INPUT', array_merge($this->dataArray['tables']['filter']['default-chains']['INPUT']['iptables-rules'], $this->_fwChainRules()), array( 'policy' => $this->dataArray['tables']['filter']['default-chains']['INPUT']['policy'], 'default' => true));
		$this->_rulesToChain('FORWARD', array_merge($this->dataArray['tables']['filter']['default-chains']['FORWARD']['iptables-rules'], $this->_ifaceChainRules()), array( 'policy' => $this->dataArray['tables']['filter']['default-chains']['FORWARD']['policy'], 'default' => true));
		$this->_rulesToChain('OUTPUT', $this->dataArray['tables']['filter']['default-chains']['OUTPUT']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['filter']['default-chains']['OUTPUT']['policy'], 'default' => true));
		
		foreach ($this->dataArray['tables']['filter']['fw-chains'] as $a => $b){
			$this->_rulesToChain('fwc-' . $a . '-to-fw', $b['iptables-rules']);
		}
		
		foreach ($this->dataArray['tables']['filter']['iface-chains'] as $b){
			$this->_rulesToChain('ifc-' . $b['from'] . '-to-' . $b['to'], $b['iptables-rules']);
		}
		
		foreach ($this->dataArray['tables']['filter']['service-chains'] as $a => $b){
			$this->_rulesToChain('svc-' . $a, $b['iptables-rules']);
		}
		
		foreach ($this->dataArray['tables']['filter']['other-chains'] as $a => $b){
			$this->_rulesToChain($a, $b['iptables-rules']);
		}
	}
	
	private function _rulesToChain($chain, $rules, $options = array()){
		if ( is_array($this->chainsArray['filter'][$chain]) ){
			$this->logError('Error: Trying to add a chain that already exists! - ' . $chain, true);
		} else {
			$this->chainsArray['filter'][$chain] = array( 'options' => $options, 'rules' => $rules );
		}
	}
	
	private function _fwChainRules(){
		$rules = array();
		
		foreach ($this->dataArray['tables']['filter']['fw-chains'] as $a => $b){
			$rules[] = '-i ' . $this->dataArray['interfaces'][$a] . ' -j fwc-' . $a . '-to-fw';
		}
		
		return $rules;
	}
	
	private function _ifaceChainRules(){
		$rules = array();
		
		foreach ($this->dataArray['tables']['filter']['iface-chains'] as $b){
			$rules[] = '-i ' . $b['from'] . ' -o ' . $b['to'] . ' -j ifc-' . $b['from'] . '-to-' . $b['to'];
		}
		
		return $rules;
	}
	
}