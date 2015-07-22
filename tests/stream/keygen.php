<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

$key = \Defuse\Crypto\Core::createNewRandomKey();

\file_put_contents('key.txt', \Defuse\Crypto\Core::binToHex($key));