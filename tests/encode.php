<?php
require_once \dirname(__DIR__).'/autoload.php';

use \Defuse\Crypto\Crypto;

\var_dump(
    Crypto::binToHex("\x41\x42\x4a\x41")
);
\var_dump(
    Crypto::hexToBin('41424a41')
);