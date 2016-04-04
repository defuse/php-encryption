<?php

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;

class CryptoTest extends PHPUnit_Framework_TestCase
{
    # Test for issue #165 -- encrypting then decrypting empty string fails.
    public function testEmptyString()
    {
        $str    = '';
        $key    = Key::createNewRandomKey();
        $cipher = Crypto::encrypt($str, $key);
        $this->assertSame(
            $str,
            Crypto::decrypt($cipher, $key)
        );
    }
}
