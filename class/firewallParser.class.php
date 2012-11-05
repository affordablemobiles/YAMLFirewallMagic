<?php

require __DIR__ . '/abstract/logableBase.class.php';
require __DIR__ . '/abstract/step1.class.php';

/*---------------------------+
|       Step 1 Classes       |
|     Pre-Processing Work    |
+---------------------------*/
require __DIR__ . '/step1/interfacesStep1.class.php';
require __DIR__ . '/step1/filterTableStep1.class.php';
require __DIR__ . '/step1/natTableStep1.class.php';
require __DIR__ . '/step1/mangleTableStep1.class.php';

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
		$if_step1 = new InterfacesStep1($this->parsed, $this->dataArray);
		foreach ( $this->parsed['tables'] as $table ){
			if (@$table['name'] == 'filter'){
				$ftbl_step1 = new filterTableStep1($table, $this->dataArray);
			} else if (@$table['name'] == 'nat'){
				$ntbl_step1 = new natTableStep1($table, $this->dataArray);
			} else if (@$table['name'] == 'mangle'){
				$mtbl_step1 = new mangleTableStep1($table, $this->dataArray);
			} else {
				die('Invalid Table Detected');
			}
		}
	}
	
	private function _step2(){
		print_r($this->dataArray);
	}
	
	private function _step3(){
		
	}
	
}