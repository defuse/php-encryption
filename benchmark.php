<?php
use \Defuse\Crypto\Crypto;
require_once'autoload.php';

function showResults($type, $start, $end, $count)
{
    $time = $end - $start;
    $rate = $count / $time;
    echo $type, ': ', $rate, ' calls/s', "\n";
}


// Note: By default, the runtime tests are "cached" and not re-executed for
// every call. To disable this, look at the RuntimeTest() function.

$start = \microtime(true);
for ($i = 0; $i < 1000; $i++) {
    $key = Crypto::createNewRandomKey();
}
$end = \microtime(true);
showResults("createNewRandomKey()", $start, $end, 1000);

$start = \microtime(true);
for ($i = 0; $i < 100; $i++) {
    $ciphertext = Crypto::encrypt(
        \str_repeat("A", 1024*1024),
        \str_repeat("B", 16)
    );
}
$end = microtime(true);
showResults("encrypt(1MB)", $start, $end, 100);

$start = microtime(true);
for ($i = 0; $i < 1000; $i++) {
    $ciphertext = Crypto::encrypt(
        \str_repeat("A", 1024),
        \str_repeat("B", 16)
    );
}
$end = \microtime(true);
showResults("encrypt(1KB)", $start, $end, 1000);
