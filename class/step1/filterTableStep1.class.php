<?php

class filterTableStep1 extends Step1 {
	
	protected function _parse(){
		$this->_defaultChains();
	}
	
	private function _validDefaultPolicy($policy){
		switch ($policy){
			case 'ACCEPT':
			case 'REJECT':
			case 'DROP':
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
				if (@$dchain['name'] == 'INPUT'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['filter']['default-chains']['INPUT']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for INPUT chain - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain INPUT - using default of DROP', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['filter']['default-chains']['INPUT']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain INPUT doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'FORWARD'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['filter']['default-chains']['FORWARD']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for FORWARD chain - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain FORWARD - using default of DROP', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['filter']['default-chains']['FORWARD']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain FORWARD doesn\'t exist.', false);
					}
				} else if (@$dchain['name'] == 'OUTPUT'){
					if (!empty($dchain['policy'])){
						if ($this->_validDefaultPolicy($dchain['policy'])){
							$this->dataArray['tables']['filter']['default-chains']['OUTPUT']['policy'] = $dchain['policy'];
						} else {
							$this->logError('Error: invalid policy for OUTPUT chain - ' . $dchain['policy'], true);
						}
					} else {
						$this->logError('Warning: policy not defined for default chain OUTPUT - using default of ACCEPT', false);
					}
					if ( @is_array($dchain['rules']) ){
						foreach ($dchain['rules'] as $rule){
							$this->dataArray['tables']['filter']['default-chains']['OUTPUT']['rules'][] = $rule;
						}
					} else {
						$this->logError('Warning: rules array for default chain OUTPUT doesn\'t exist.', false);
					}
				} else {
					$this->logError( 'Invalid Default Chain - ' . var_export($dchain, true), false);
				}
			}
		} else {
			$this->logError( 'Warning: default chains block doesn\'t exist for filter table.', false);
		}
	}
	
}