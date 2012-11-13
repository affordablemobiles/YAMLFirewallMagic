<?php

abstract class logableBase {
	
	protected function logError($message, $die = true){
		if ($die){
			file_put_contents( 'php://stderr', $message . "\n" );
			die();
		} else {
			file_put_contents( 'php://stderr', $message . "\n" );
		}
	}

}