<?php

class FirewallParser {
	private $parsed;
	
	private $dataArray = array(
								'interfaces' => array(
									/* IFACE => OSIFACE */
								),
								'tables' => array(
									'filter' => array(
										'default-chains' => array(
											'INPUT' => array( 'policy' => 'DROP', 'rules' => array() ),
											'FORWARD' => array( 'policy' => 'DROP', 'rules' => array() ),
											'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() )
										),
										'fw-chains' => array(
											/* IFACE => array( 'default-goto' => D-GT, 'rules' => RULES ) */
										),
										'iface-chains' => array(
											/* array( 'to' => TO, 'from' => FROM, 'default-goto' => D-GT, 'rules' => RULES ) */
										),
										'service-chains' => array(
											/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES ) */
										),
										'other-chains' => array(
											/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES ) */
										)
								),
								'nat' => array(
									'default-chains' => array(
										'PREROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'INPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'POSTROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() )
									),
									'ip-chains' => array(
										/* array( 'in-iface' => IN-IFACE, 'ip-address' => IP-ADDRESS, 'default-goto' => D-GT, 'rules' => RULES ) */
									),
									'other-chains' => array(
										/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES ) */
									)
								),
								'mangle' => array(
									'default-chains' => array(
										'PREROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'INPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'FORWARD' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() ),
										'POSTROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() )
									),
									'other-chains' => array(
										/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES ) */
									)
								),
							)
	);
	
	public function __construct($yamlRulesFile){
		if (is_file($yamlRulesFile)){
			$this->parsed = yaml_parse_file( $yamlRulesFile );
			
			$this->_step1();
			$this->_step2();
		} else {
			die( 'Invalid Rules File - Not Found' );
		}
	}
	
	public function getOutput(){
		return $this->_step3();
	}
	
	private function _step1(){
		
	}
	
	private function _step2(){
		
	}
	
	private function _step3(){
		
	}
	
}