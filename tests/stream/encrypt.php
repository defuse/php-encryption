<?php
require_once \dirname(\dirname(__DIR__)).'/autoload.php';

if (!\file_exists('key.txt')) {
    echo 'You need to generate an encryption key first!', "\n";
    exit(1);
}

$mem = 0;
$start_time = $end_time = \microtime(true);
$key = \Defuse\Crypto\Core::hexToBin(\file_get_contents('key.txt'));

echo 'Encrypting', "\n", str_repeat('-', 50), "\n\n";
echo "Load Key:\n\t";

echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

\Defuse\Crypto\File::encryptFile(
    'wat-gigantic-duck.jpg', 
    'wat-encrypted.data', 
    $key
);

$end_time = \microtime(true);
echo "wat-gigantic-duck.jpg:\n\t";

echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

\Defuse\Crypto\File::encryptFile(
    'large.jpg',
    'large.data',
    $key
);
$end_time = \microtime(true);
echo "large.jpg:\n\t";
echo \number_format($end_time - $start_time, 2),
    's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
    "\n";
$end_time = $start_time;

if (\file_exists('In_the_Conservatory.jpg')) {
    \Defuse\Crypto\File::encryptFile(
        'In_the_Conservatory.jpg',
        'In_the_Conservatory.data',
        $key
    );
    $end_time = \microtime(true);
    echo "In_the_Conservatory.jpg:\n\t";
    echo \number_format($end_time - $start_time, 2),
        's (Memory: ', \number_format(\memory_get_usage() / 1024, 2), ' KB)',
        "\n";
    $end_time = $start_time;
}

echo 'Peak Memory: ', \number_format(\memory_get_peak_usage() / 1048576, 2), ' MB', "\n\n";
