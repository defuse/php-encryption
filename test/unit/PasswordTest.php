<?php

use \Defuse\Crypto\Key;
use \Defuse\Crypto\Salt;

class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testKeyFromPasswordCorrect()
    {
        $salt1 = Salt::createNewRandomSalt();
        $salt2 = Salt::loadFromAsciiSafeString($salt1->saveToAsciiSafeString());

        $key1 = Key::createKeyBasedOnPassword('password', $salt1);
        $key2 = Key::createKeyBasedOnPassword('password', $salt2);

        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    public function testKeyFromPasswordWrong()
    {
        $salt = Salt::createNewRandomSalt();
        $key1 = Key::createKeyBasedOnPassword('password1', $salt);
        $key2 = Key::createKeyBasedOnPassword('password2', $salt);
        $this->assertNotEquals($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\CannotPerformOperationException
     * @expectedExceptionMessage You must provide an instance of the Salt class (not a string).
     */
    public function testStringInsteadOfSaltObject()
    {
        Key::createKeyBasedOnPassword('password', str_repeat('A', 32));
    }
}
