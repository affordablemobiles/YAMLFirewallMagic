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
	
	protected function _rname($rname){
		if (strlen($rname) > 30){
			$new = substr($rname, 0, (30-strlen('-TR')));
			$new = $new . '-TR';
			return $new;
		} else {
			return $rname;
		}
	}
	
}