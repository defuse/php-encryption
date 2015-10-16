<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

if (!\file_exists('key.txt')) {
    echo 'You need to generate an encryption key first!', "\n";
    exit(1);
}

$mem = 0;
$start_time = $end_time = \microtime(true);
$key = \Defuse\Crypto\Encoding::hexToBin(\file_get_contents('key.txt'));

echo 'Decrypting', "\n", str_repeat('-', 50), "\n\n";
echo "Load Key:\n\t";

echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

\Defuse\Crypto\File::decryptFile(
    'wat-encrypted.data', 
    'wat-decrypted.jpg', 
    $key
);

$end_time = \microtime(true);
echo "wat-encrypted.data:\n\t";
echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

\Defuse\Crypto\File::decryptFile(
    'large.data',
    'large-decrypted.jpg', 
    $key
);

$end_time = \microtime(true);
echo "large.data:\n\t";
echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

if (\file_exists('In_the_Conservatory.jpg')) {
    \Defuse\Crypto\File::encryptFile(
        'In_the_Conservatory.data',
        'In_the_Conservatory_decrypted.jpg',
        $key
    );
    
    $end_time = \microtime(true);
    echo "In_the_Conservatory.data:\n\t";
    echo \number_format($end_time - $start_time, 2),
        's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
        "\n";
    $end_time = $start_time;
}

echo 'Peak Memory: ', \number_format(\memory_get_peak_usage() / 1048576, 2), ' MB', "\n\n";
