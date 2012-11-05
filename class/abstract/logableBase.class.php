<?php

abstract class logableBase {
	
	protected function logError($message, $die = true){
		if ($die){
			die( $message . "\n" );
		} else {
			echo $message . "\n";
		}
	}

}