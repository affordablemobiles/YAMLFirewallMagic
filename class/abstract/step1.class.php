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
	
	protected function _chkChainLen($chain){
		if (strlen($chain) > 30){
			return false;
		} else {
			return true;
		}
	}
	
}