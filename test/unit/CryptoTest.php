<?php
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;

class CryptoTest extends PHPUnit_Framework_TestCase
{
    public function testEmptyString()
    {
        $str = '';
        $key = Key::CreateNewRandomKey();
        $cipher = Crypto::encrypt($str, $key);
        $this->assertEquals(
            Crypto::decrypt($cipher, $key),
            $str
        );
    }
}
