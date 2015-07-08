<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

if (!\file_exists('key.txt')) {
    echo 'You need to generate an key first!', "\n";
    exit(1);
}

$key = \Defuse\Crypto\Core::hexToBin(\file_get_contents('key.txt'));

echo \microtime(true), "\n";
echo \memory_get_usage(), "\n";

\Defuse\Crypto\File::decryptFile(
    'wat-encrypted.data', 
    'wat-decrypted.jpg', 
    $key
);

echo microtime(true), "\n";
echo memory_get_usage(), "\n";

\Defuse\Crypto\File::decryptFile(
    'large.data',
    'large-decrypted.jpg', 
    $key
);

echo microtime(true), "\n";
echo memory_get_usage(), "\n";

if (\file_exists('In_the_Conservatory.jpg')) {
    \Defuse\Crypto\File::encryptFile(
        'In_the_Conservatory.data',
        'In_the_Conservatory_decrypted.jpg',
        $key
    );

    echo microtime(true), "\n";
    echo memory_get_usage(), "\n";
}

echo 'Peak: ', memory_get_peak_usage(), "\n";
