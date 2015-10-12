<?php
require_once \dirname(__DIR__).'/autoload.php';

$config = [
    'BLOCK_SIZE' => 16,
    'KEY_BYTE_SIZE' => 16,
    'HASH_FUNCTION' => 'sha256',
    'MAC_BYTE_SIZE' => 32,
    'ENCRYPTION_INFO' => 'DefusePHP|KeyForEncryption',
    'AUTHENTICATION_INFO' => 'DefusePHP|KeyForAuthentication',
    'CIPHER_METHOD' => 'aes-128-ctr',
    'BUFFER' => 1048576
];

$ctr = [
    str_repeat("\0", \openssl_cipher_iv_length('aes-128-ctr')),
    str_repeat("\0", \openssl_cipher_iv_length('aes-128-ctr') - 2) . "\x00\x40"
];
$test = \Defuse\Crypto\Core::incrementCounter($ctr[0], 64, $config);
if ($test !== $ctr[1]) {
    echo "Counter mode malfunction\n";
    exit(255);
}
$a = str_repeat('a', 2048);

/**
 * Let's verify that our counter is behaving properly
 */
$cipher = openssl_encrypt($a, $config['CIPHER_METHOD'], 'YELLOW SUBMARINE', OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $ctr[0]);
$slice = mb_substr($cipher, 1024, 1024, '8bit');
$decrypt = openssl_decrypt($slice, $config['CIPHER_METHOD'], 'YELLOW SUBMARINE', OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $test);

if (!preg_match('/^a{1024}$/', $decrypt)) {
    echo "Counter mode calculation error\n";
    exit(255);
}

/**
 * We should carry
 */
$start = str_repeat("\xFF", \openssl_cipher_iv_length('aes-128-ctr'));
$end = \Defuse\Crypto\Core::incrementCounter($start, 1, $config);
if ($end !== $ctr[0]) {
    echo "Carry error\n";
    exit(255);
}