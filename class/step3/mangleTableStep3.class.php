<?php

class mangleTableStep3 extends Step3 {
	
	protected function _parse(){
		$this->_rulesToChain('PREROUTING', $this->dataArray['tables']['mangle']['default-chains']['PREROUTING']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['mangle']['default-chains']['PREROUTING']['policy'], 'default' => true));
		$this->_rulesToChain('INPUT', $this->dataArray['tables']['mangle']['default-chains']['INPUT']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['mangle']['default-chains']['INPUT']['policy'], 'default' => true));
		$this->_rulesToChain('FORWARD', $this->dataArray['tables']['mangle']['default-chains']['FORWARD']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['mangle']['default-chains']['FORWARD']['policy'], 'default' => true));
		$this->_rulesToChain('OUTPUT', $this->dataArray['tables']['mangle']['default-chains']['OUTPUT']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['mangle']['default-chains']['OUTPUT']['policy'], 'default' => true));
		$this->_rulesToChain('POSTROUTING', $this->dataArray['tables']['mangle']['default-chains']['POSTROUTING']['iptables-rules'], array( 'policy' => $this->dataArray['tables']['mangle']['default-chains']['OUTPUT']['policy'], 'default' => true));
		
		foreach ($this->dataArray['tables']['mangle']['other-chains'] as $a => $b){
			$this->_rulesToChain($a, $b['iptables-rules']);
		}
	}
	
	private function _rulesToChain($chain, $rules, $options = array()){
		$chain = $this->_rname($chain);
		
		if ( @is_array($this->chainsArray['mangle'][$chain]) ){
			$this->logError('Error: Trying to add a chain that already exists (mangle)! - ' . $chain, true);
		} else {
			$this->chainsArray['mangle'][$chain] = array( 'options' => $options, 'rules' => $rules );
		}
	}
	
}

?>