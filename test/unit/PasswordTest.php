<?php

use \Defuse\Crypto\KeyProtectedByPassword;

class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testKeyFromPasswordCorrect()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey2 = KeyProtectedByPassword::loadFromAsciiSafeString($pkey1->saveToAsciiSafeString());

        $key1 = $pkey1->unlockKey('password');
        $key2 = $pkey2->unlockKey('password');

        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     */
    public function testKeyFromPasswordWrong()
    {
        $pkey = KeyProtectedByPassword::createRandomPasswordProtectedKey('rightpassword');
        $key1 = $pkey->unlockKey('wrongpassword');
    }

    // TODO more tests (of the checksummed encoding, etc.)
}
