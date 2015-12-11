<?php
require_once \dirname(__DIR__).'/autoload.php';

$key = \Defuse\Crypto\Key::LoadFromAsciiSafeString(\file_get_contents('key.txt'));

echo 'Buffers: ', \Defuse\Crypto\File::BUFFER, "\n";
echo microtime(true), "\n";
echo memory_get_usage(), "\n";

\Defuse\Crypto\File::encryptFile(
    'wat-gigantic-duck.jpg',
    'wat-encrypted.data',
    $key
);

$ifp = fopen('wat-encrypted.data', 'rb');
\stream_set_read_buffer($ifp, 0);
$ofp = fopen('damaged.data', 'wb');
\stream_set_write_buffer($ifp, 0);
$i = 0;
while (!\feof($ifp)) {
    $buff = \fread($ifp, 4096);
    if ($i === 0) {
        $c = \ord($buff[0]);
        $buff[0] = $c === 0 ? 255 : 0;
    }
    \fwrite($ofp, $buff);
    ++$i;
}
fclose($ifp);
fclose($ofp);

\Defuse\Crypto\File::decryptFile(
    'damaged.data',
    'wat-damaged.jpg',
    $key
);
