<?php

class filterTableStep1 extends Step1 {
	
	protected function _parse(){
		$this->_defaultChains();
		$this->_fwChains();
		$this->_ifaceChains();
		$this->_serviceChains();
		$this->_otherChains();
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
	
	private function _fwChains(){
		if ( @is_array( $this->pdata['fw-chains'] ) ){
			foreach( $this->pdata['fw-chains'] as $fwchain ){
				if ( @in_array($fwchain['from'], array_keys($this->dataArray['interfaces'])) ){
					if ( @is_array($this->dataArray['tables']['filter']['fw-chains'][$fwchain['from']]) ){
						$this->logError( 'Error: Firewall Chain for This Interface Already Exists - Duplicate - ' . var_export($fwchain, true), true);
					} else {
						$this->dataArray['tables']['filter']['fw-chains'][$fwchain['from']] = array();
						if ( @is_array($fwchain['rules']) ){
							foreach ($fwchain['rules'] as $rule){
								$this->dataArray['tables']['filter']['fw-chains'][$fwchain['from']]['rules'][] = $rule;
							}
						} else {
							$this->logError( 'Error: Invalid Rules Array for fw-chain - ' . var_export($fwchain, true), true);
						}
						if (!empty($fwchain['default-goto'])){
							$this->dataArray['tables']['filter']['fw-chains']['default-goto'] = $fwchain['default-goto'];
						} else {
							$this->logError( 'Warning: Default-Goto for fw-chain not specified - Using default of DROP', false);
							$this->dataArray['tables']['filter']['fw-chains']['default-goto'] = 'DROP';
						}
					}
				} else {
					$this->logError( 'Error: invalid interface listed for firewall chain - ' . var_export($fwchain, true), true);
				}
			}
		} else {
			$this->logError( 'Warning: firewall chains block doesn\'t exist for filter table.', false);
		}
	}
	
	private function _ifaceChains(){
		if ( @is_array( $this->pdata['iface-chains'] ) ){
			foreach( $this->pdata['iface-chains'] as $ifchain ){
				if ( ( !empty($ifchain['to']) ) && (@in_array($ifchain['to'], array_keys($this->dataArray['interfaces']))) ){
					if ( ( !empty($ifchain['from']) ) && (@in_array($ifchain['from'], array_keys($this->dataArray['interfaces']))) ){
						if ( $ifchain['to'] != $ifchain['from'] ){
							if ( @is_array($ifchain['rules']) ){
								$chain = array( 'to' => $ifchain['to'], 'from' => $ifchain['from'], 'default-goto' => 'ACCEPT', 'rules' => array() );
								foreach ( $ifchain['rules'] as $rule ){
									$chain['rules'][] = $rule;
								}
								if ( !empty( $ifchain['default-goto'] ) ){
									$chain['default-goto'] = $ifchain['default-goto'];
								} else {
									$this->logError( 'Warning: using default-goto of ACCEPT for iface-chain as none specified!', false);
								}
								$this->dataArray['tables']['filter']['iface-chains'][] = $chain;
							}
						} else {
							$this->logError( 'Error: interface chain can\'t filter traffic from and to the same interface without Proxy-ARP enabled', true);
						}
					} else {
						$this->logError( 'Error: Invalid from Interface on iface-chain - ' . var_export($ifchain, true), true);
					}
				} else {
					$this->logError( 'Error: Invalid to Interface on iface-chain - ' . var_export($ifchain, true), true);
				}
			}
		} else {
			$this->logError( 'Warning: interface chains block doesn\'t exist for filter table.', false);
		}
	}
	
	private function _serviceChains(){
		if ( @is_array( $this->pdata['service-chains'] ) ){
			foreach( $this->pdata['service-chains'] as $schain ){
				if ( !empty( $schain['name'] ) ){
					if ( ! @is_array($this->dataArray['tables']['filter']['service-chains'][$schain['name']]) ){
						if ( @is_array( $schain['rules'] ) ){
							$this->dataArray['tables']['filter']['service-chains'][$schain['name']] = array('default-goto' => 'ACCEPT', 'rules' => array());
							foreach ( $schain['rules'] as $rule ){
								$this->dataArray['tables']['filter']['service-chains'][$schain['name']]['rules'][] = $rule;
							}
							if ( !empty( $schain['default-goto'] ) ){
								$this->dataArray['tables']['filter']['service-chains'][$schain['name']]['default-goto'] = $schain['default-goto'];
							} else {
								$this->logError( 'Warning: using default-goto of ACCEPT for service-chain as none specified!', false);
							}
						} else {
							$this->logError( 'Error: rules array missing from service chain - ' . var_dump($schain, true), true);
						}
					} else {
						$this->logError( 'Error: service chain with this name already exists - ' . var_dump($schain, true), true);
					}
				} else {
					$this->logError( 'Error: you must specify a name for a service chain - ' . var_dump($schain, true), true);
				}
			}
		} else {
			$this->logError( 'Warning: service chains block doesn\'t exist.', false);
		}
	}
	
	private function _otherChains(){
		if ( @is_array( $this->pdata['other-chains'] ) ){
			foreach( $this->pdata['other-chains'] as $ochain ){
				if ( !empty( $ochain['name'] ) ){
					if ( ! @is_array($this->dataArray['tables']['filter']['other-chains'][$ochain['name']]) ){
						if ( @is_array( $ochain['rules'] ) ){
							$this->dataArray['tables']['filter']['other-chains'][$ochain['name']] = array('default-goto' => 'ACCEPT', 'rules' => array());
							foreach ( $ochain['rules'] as $rule ){
								$this->dataArray['tables']['filter']['other-chains'][$ochain['name']]['rules'][] = $rule;
							}
							if ( !empty( $ochain['default-goto'] ) ){
								$this->dataArray['tables']['filter']['other-chains'][$ochain['name']]['default-goto'] = $ochain['default-goto'];
							} else {
								$this->logError( 'Warning: using default-goto of ACCEPT for other-chain as none specified!', false);
							}
						} else {
							$this->logError( 'Error: rules array missing from other chain - ' . var_dump($ochain, true), true);
						}
					} else {
						$this->logError( 'Error: \'other\' chain with this name already exists - ' . var_dump($ochain, true), true);
					}
				} else {
					$this->logError( 'Error: you must specify a name for a other chain - ' . var_dump($ochain, true), true);
				}
			}
		} else {
			$this->logError( 'Warning: service chains block doesn\'t exist.', false);
		}
	}
	
}