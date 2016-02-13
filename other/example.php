<?php

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Exception as Ex;

require_once 'autoload.php';

try {
    $key = Crypto::createNewRandomKey();
    // WARNING: Do NOT encode $key with bin2hex() or base64_encode(),
    // they may leak the key to the attacker through side channels.
} catch (Ex\CryptoTestFailedException $ex) {
    die('Cannot safely create a key');
} catch (Ex\CannotPerformOperationException $ex) {
    die('Cannot safely create a key');
}

$message = "ATTACK AT DAWN";
try {
    $ciphertext = Crypto::encrypt($message, $key);
} catch (Ex\CryptoTestFailedException $ex) {
    die('Cannot safely perform encryption');
} catch (Ex\CannotPerformOperationException $ex) {
    die('Cannot safely perform encryption');
}

try {
    $decrypted = Crypto::decrypt($ciphertext, $key);
} catch (Ex\InvalidCiphertextException $ex) { // VERY IMPORTANT
    // Either:
    //   1. The ciphertext was modified by the attacker,
    //   2. The key is wrong, or
    //   3. $ciphertext is not a valid ciphertext or was corrupted.
    // Assume the worst.
    die('DANGER! DANGER! The ciphertext has been tampered with!');
} catch (Ex\CryptoTestFailedException $ex) {
    die('Cannot safely perform decryption');
} catch (Ex\CannotPerformOperationException $ex) {
    die('Cannot safely perform decryption');
}
