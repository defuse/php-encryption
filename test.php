<?php
require_once('Crypto.php');
try {
    Crypto::RuntimeTest();
    echo "TEST PASSED!\n";
    exit(0);
} catch (CryptoTestFailedException $ex) {
    echo "TEST FAILED!\n";
    var_dump($ex);
    exit(1);
}
?>
