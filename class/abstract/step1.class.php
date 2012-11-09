<?php

abstract class Step1 extends logableBase {
	protected $dataArray;
	protected $pdata;
	
	public function __construct($parsed, &$dataArray){
		$this->dataArray =& $dataArray;
		$this->pdata = $parsed;
		
		$this->_parse();
	}
	
	abstract protected function _parse();
	
}