<?php
require_once('Crypto.php');
try {
    Crypto::RuntimeTest();
    echo "TEST PASSED!\n";
} catch (CryptoTestFailedException $ex) {
    echo "TEST FAILED!\n";
    throw $ex;
}
?>
