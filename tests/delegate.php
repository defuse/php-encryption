<?php
require_once \dirname(__DIR__).'/autoload.php';

use \Defuse\Crypto\DelegateCrypto;

$message = 'This is a test message';

$delegate = new DelegateCrypto();
$key = $delegate->createNewRandomKey();
$ciphertext = $delegate->encrypt($message, $key);
try {
    $plaintext = $delegate->decrypt($ciphertext, $key);
    if ($message !== $plaintext) {
        var_dump(
            $delegate->binToHex($message),
            $delegate->binToHex($plaintext)
        );
        exit(1);
    }
} catch (\Defuse\Crypto\Exception\CryptoException $ex) {
    echo $ex->getMessage(), "\n";
    exit(1);
}