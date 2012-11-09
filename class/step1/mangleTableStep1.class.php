<?php

class mangleTableStep1 extends Step1 {
	
	protected function _parse(){
		$this->_defaultChains();
		$this->_otherChains();
	}
	
	private function _validDefaultPolicy($policy){
		switch ($policy){
			case 'ACCEPT':
				return true;
				break;
			default:
				return false;
				break;
		}
	}
	
	private function _defaultChains(){
		if ( @is_array( $this->pdata['default-chains'] ) ){
			foreach ( $this->pdata['default-chains'] as $dchain ){
				if (@$dchain['name'] == 'PREROUTING'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['mangle']['default-chains']['PREROUTING']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for PREROUTING chain (mangle) - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain PREROUTING (mangle) - using default of DROP', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['mangle']['default-chains']['PREROUTING']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain PREROUTING doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'INPUT'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['mangle']['default-chains']['INPUT']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for INPUT chain (mangle) - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain INPUT (mangle) - using default of DROP', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['mangle']['default-chains']['INPUT']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain INPUT (mangle) doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'FORWARD'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['mangle']['default-chains']['FORWARD']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for FORWARD chain (mangle) - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain FORWARD (mangle) - using default of DROP', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['mangle']['default-chains']['FORWARD']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain FORWARD (mangle) doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'OUTPUT'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['mangle']['default-chains']['OUTPUT']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for OUTPUT chain (mangle) - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain OUTPUT (mangle) - using default of ACCEPT', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['mangle']['default-chains']['OUTPUT']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain OUTPUT (mangle) doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'POSTROUTING'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['mangle']['default-chains']['POSTROUTING']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for POSTROUTING chain (mangle) - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain POSTROUTING (mangle) - using default of ACCEPT', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['mangle']['default-chains']['POSTROUTING']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain POSTROUTING (mangle) doesn\'t exist.', false);
					}
				} else {
					$this->logError( 'Invalid Default Chain - ' . var_export($dchain, true), false);
				}
			}
		} else {
			$this->logError( 'Warning: default chains block doesn\'t exist for NAT table.', false);
		}
	}
	
	private function _otherChains(){
		if ( @is_array( $this->pdata['other-chains'] ) ){
			foreach( $this->pdata['other-chains'] as $ochain ){
				if ( !empty( $ochain['name'] ) ){
					if ( ! @is_array($this->dataArray['tables']['mangle']['other-chains'][$ochain['name']]) ){
						if ( @is_array( $ochain['rules'] ) ){
							$this->dataArray['tables']['mangle']['other-chains'][$ochain['name']] = array('default-goto' => 'ACCEPT', 'rules' => array());
							foreach ( $ochain['rules'] as $rule ){
								$this->dataArray['tables']['mangle']['other-chains'][$ochain['name']]['rules'][] = $rule;
							}
							if ( !empty( $ochain['default-goto'] ) ){
								$this->dataArray['tables']['mangle']['other-chains'][$ochain['name']]['default-goto'] = $ochain['default-goto'];
							} else {
								$this->logError( 'Warning: using default-goto of ACCEPT for other-chain (mangle) as none specified!', false);
							}
						} else {
							$this->logError( 'Error: rules array missing from other chain (mangle) - ' . var_dump($ochain, true), true);
						}
					} else {
						$this->logError( 'Error: \'other\' chain (mangle) with this name already exists - ' . var_dump($ochain, true), true);
					}
				} else {
					$this->logError( 'Error: you must specify a name for a other chain (mangle) - ' . var_dump($ochain, true), true);
				}
			}
		} else {
			$this->logError( 'Warning: service chains block (mangle) doesn\'t exist.', false);
		}
	}
	
}