<?php

require __DIR__ . '/abstract/logableBase.class.php';
require __DIR__ . '/abstract/step1.class.php';
require __DIR__ . '/abstract/step2.class.php';

/*---------------------------+
|       Step 1 Classes       |
|     Pre-Processing Work    |
+---------------------------*/
require __DIR__ . '/step1/interfacesStep1.class.php';
require __DIR__ . '/step1/filterTableStep1.class.php';
require __DIR__ . '/step1/natTableStep1.class.php';
require __DIR__ . '/step1/mangleTableStep1.class.php';

/*---------------------------+
|       Step 2 Classes       |
|    Transform to IPTables   |
+---------------------------*/
require __DIR__ . '/step2/filterTableStep2.class.php';
require __DIR__ . '/step2/natTableStep2.class.php';
require __DIR__ . '/step2/mangleTableStep2.class.php';

/*---------------------------+
|       Step 3 Classes       |
|     Transform to Chains    |
+---------------------------*/
require __DIR__ . '/step3/filterTableStep3.class.php';
require __DIR__ . '/step3/natTableStep3.class.php';
require __DIR__ . '/step3/mangleTableStep3.class.php';

class FirewallParser {
	private $parsed;
	
	private $dataArray = array(
								'interfaces' => array(
									/* IFACE => OSIFACE */
								),
								'tables' => array(
									'filter' => array(
										'default-chains' => array(
											'INPUT' => array( 'policy' => 'DROP', 'rules' => array() /*, 'iptables-rules' => array() */ ),
											'FORWARD' => array( 'policy' => 'DROP', 'rules' => array() /*, 'iptables-rules' => array() */ ),
											'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ )
										),
										'fw-chains' => array(
											/* IFACE => array( 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
										),
										'iface-chains' => array(
											/* array( 'to' => TO, 'from' => FROM, 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
										),
										'service-chains' => array(
											/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
										),
										'other-chains' => array(
											/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
										)
								),
								'nat' => array(
									'default-chains' => array(
										'PREROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'INPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'POSTROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ )
									),
									'ip-chains' => array(
										/* array( 'in-iface' => IN-IFACE, 'ip-address' => IP-ADDRESS, 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
									),
									'other-chains' => array(
										/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
									)
								),
								'mangle' => array(
									'default-chains' => array(
										'PREROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'INPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'FORWARD' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'OUTPUT' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ ),
										'POSTROUTING' => array( 'policy' => 'ACCEPT', 'rules' => array() /*, 'iptables-rules' => array() */ )
									),
									'other-chains' => array(
										/* NAME => array( 'default-goto' => D-GT, 'rules' => RULES, 'iptables-rules' => IPT-RULES ) */
									)
								),
							)
	);
	
	private $chainsArray = array(
									'filter' => array(
										/* CHAIN-NAME => RULES (ARRAY) */
									),
									'nat' => array(
										/* CHAIN-NAME => RULES (ARRAY) */
									),
									'mangle' => array(
										/* CHAIN-NAME => RULES (ARRAY) */
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
		foreach ( $this->dataArray['tables'] as $name => $table ){
			if (@$name == 'filter'){
				$ftbl_step2 = new filterTableStep2($this->dataArray);
			} else if (@$name == 'nat'){
				$ntbl_step2 = new natTableStep2($this->dataArray);
			} else if (@$name == 'mangle'){
				$mtbl_step2 = new mangleTableStep2($this->dataArray);
			} else {
				die('Invalid Table Detected');
			}
		}
	}
	
	private function _step3(){
		print_r($this->dataArray);
	}
	
}