<?php

require __DIR__ . '/abstract/logableBase.class.php';
require __DIR__ . '/abstract/step1.class.php';
require __DIR__ . '/abstract/step2.class.php';
require __DIR__ . '/abstract/step3.class.php';

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

// Config...
$config = array();
$config['output-type'] = 'iptables-save';
$config['include-path'] = __DIR__ . '/../include';

/*---------------------------+
|       Step 4 Classes       |
|     Transform to Format    |
+---------------------------*/
require __DIR__ . '/abstract/step4-' . $config['output-type'] . '.class.php';
require __DIR__ . '/step4-' . $config['output-type'] . '/filterTableStep4.class.php';
require __DIR__ . '/step4-' . $config['output-type'] . '/natTableStep4.class.php';
require __DIR__ . '/step4-' . $config['output-type'] . '/mangleTableStep4.class.php';

class FirewallParser extends logableBase {
	private $parsed;
	private $basefile;
	
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
										/* CHAIN-NAME => array ( OPTIONS => ARRAY(), RULES => ARRAY() ) */
									),
									'nat' => array(
										/* CHAIN-NAME => RULES ( OPTIONS => ARRAY(), RULES => ARRAY() ) */
									),
									'mangle' => array(
										/* CHAIN-NAME => RULES ( OPTIONS => ARRAY(), RULES => ARRAY() ) */
									)
	);
	
	public function __construct($yamlRulesFile){
		if (is_file($yamlRulesFile)){
			$this->parsed = yaml_parse_file( $yamlRulesFile );
			$this->basefile = realpath($yamlRulesFile);
			
			$this->_step0();
			$this->_step2();
			$this->_step3();
		} else {
			$this->logError( 'Invalid Rules File - Not Found' );
		}
	}
	
	public function getOutput(){
		return $this->_step4();
	}
	
	private function _step0($file = false){
		global $config;
		
		if ($file === false){
			$data = $this->parsed;
		} else {
			$data = yaml_parse_file( $file );
		}
		
		if (is_array($this->parsed['include'])){
			if (count($this->parsed['include']) > 0){
				foreach($this->parsed['include'] as $i){
					if (!empty($i['path'])){
						if ( substr($i['path'], 0, 1) == '/' ){
							$path = $i['path'];
						} else {
							$path = $config['include-path'] . '/' . $i['path'];
						}
						
						if (is_file($path)){
							$this->_step0($path);
						} else {
							$this->logError ( '404 - File Not Found - ' . $path );
						}
					} else {
						$this->logError ( 'Invalid Path Specified - ' . var_dump($i, true) );
					}
				}
			}
		}
		
		$this->_step1($data);
	}
	
	private function _step1($input){
		$if_step1 = new InterfacesStep1($this->parsed, $this->dataArray);
		if (is_array($input['tables'])){
			foreach ( $this->parsed['tables'] as $table ){
				if (@$table['name'] == 'filter'){
					$ftbl_step1 = new filterTableStep1($table, $this->dataArray);
				} else if (@$table['name'] == 'nat'){
					$ntbl_step1 = new natTableStep1($table, $this->dataArray);
				} else if (@$table['name'] == 'mangle'){
					$mtbl_step1 = new mangleTableStep1($table, $this->dataArray);
				} else {
					$this->logError('Invalid Table Detected');
				}
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
				$this->logError('Invalid Table Detected');
			}
		}
	}
	
	private function _step3(){
		$ftbl_step3 = new filterTableStep3($this->dataArray, $this->chainsArray);
		$ntbl_step3 = new natTableStep3($this->dataArray, $this->chainsArray);
		$mtbl_step3 = new mangleTableStep3($this->dataArray, $this->chainsArray);
	}
	
	private function _step4(){
		$output = '';
		
		// Since the actual version of iptables-save does the NAT table first, let us do the same!
		$ntbl_step4 = new natTableStep4($this->chainsArray);
		$output .= $ntbl_step4->output();
		// Now the filter table...
		$ftbl_step4 = new filterTableStep4($this->chainsArray);
		$output .= $ftbl_step4->output();
		// And finally, the mangle table.
		$mtbl_step4 = new mangleTableStep4($this->chainsArray);
		$output .= $mtbl_step4->output();
		
		return $output;
	}
	
}