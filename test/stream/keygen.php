<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

$key = \Defuse\Crypto\Crypto::createNewRandomKey();

\file_put_contents('key.txt', $key->saveToAsciiSafeString());
