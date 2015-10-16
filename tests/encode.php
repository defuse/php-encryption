<?php
require_once \dirname(__DIR__).'/autoload.php';

use \Defuse\Crypto\Encoding;

$status = 0;
for ($i = 0; $i < 100; ++$i) {
    $random = \openssl_random_pseudo_bytes(32);
    $encode_a = Encoding::binToHex($random);
    $encode_b = \bin2hex($random);
    
    if ($encode_a !== $encode_b) {
        $status = 1;
        \var_dump([$encode_a, $encode_b]);
    }
    // echo "\t", $encode_a, "\t", $encode_b, "\n";
    
    $decode_a = Encoding::hexToBin($encode_b);
    $decode_b = \hex2bin($encode_a);
    
    if ($decode_a !== $decode_b) {
        $status = 1;
        \var_dump([\base64_encode($decode_a), \base64_decode($decode_b)]);
    }
}

if ($status < 0) {
    echo 'Encoded successfully!', "\n";
}

exit($status);
// XXX: remove this dead code
\var_dump(
    Encoding::binToHex("\x41\x42\x4a\x41")
);
\var_dump(
    Encoding::hexToBin('41424a41')
);
