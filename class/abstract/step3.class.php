<?php

abstract class Step3 extends logableBase {
	protected $dataArray;
	protected $chainsArray;
	
	public function __construct(&$dataArray, &$chainsArray){
		$this->dataArray =& $dataArray;
		$this->chainsArray =& $chainsArray;
		
		$this->_parse();
	}
	
	abstract protected function _parse();
	
}