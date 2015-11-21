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