<?php
require_once \dirname(__DIR__).'/autoload.php';

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Encoding;

$cipher = Encoding::hexToBin('cfdad83ebd506d2c9ada8d48030d0bca2ff94760e6d39c186adb1290d6c47e35821e262673c5631c42ebbaf70774d6ef29aa5eee0e412d646ae380e08189c85d024b5e2009106870f1db25d8b85fd01f');
$plain = Crypto::legacyDecrypt($cipher, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F");

if ($plain !== 'This is a test message') {
    exit(1);
}
