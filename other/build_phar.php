<?php
$dist = dirname(__DIR__).'/dist';
if (!\is_dir($dist)) {
    \mkdir($dist, 0755);
}
if (\file_exists($dist.'/defuse-crypto.phar')) {
    \unlink($dist.'/defuse-crypto.phar');
}
$phar = new \Phar(
    $dist.'/defuse-crypto.phar',
    \FilesystemIterator::CURRENT_AS_FILEINFO | \FilesystemIterator::KEY_AS_FILENAME,
    'defuse-crypto.phar'
);

$phar->buildFromDirectory(dirname(__DIR__).'/src');
$phar->setStub(
    $phar->createDefaultStub('phar_autoloader.php', 'phar_autoloader.php')
);

/**
 * If we pass an (optional) path to a private key as a second argument, we will
 * sign the Phar with OpenSSL.
 * 
 * If you leave this out, it will produce an unsigned .phar!
 */
if ($argc > 1) {
    if (!@\is_readable($argv[1])) {
        echo 'Could not read the private key file:', $argv[1], "\n";
        exit(255);
    }
    $pkeyFile = \file_get_contents($argv[1]);
    
    $private = \openssl_get_privatekey($pkeyFile);
    if ($private !== false) {
        $phar->setSignatureAlgorithm(\Phar::OPENSSL, $private);
        
        /**
         * Save the corresponding public key to the file
         */
        if (!@\is_readable($dist.'/defuse-crypto.phar.pubkey')) {
            $details = \openssl_pkey_get_details($private);
            \file_put_contents(
                $dist.'/defuse-crypto.phar.pubkey',
                $details['key']
            );
        }
    } else {
        echo 'An error occurred reading the private key from OpenSSL.', "\n";
        exit(255);
    }
}
