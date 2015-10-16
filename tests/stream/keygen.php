<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

$key = \Defuse\Crypto\Encoding::createNewRandomKey();

\file_put_contents('key.txt', \Defuse\Crypto\Encoding::binToHex($key));
