<?php
use \Defuse\Crypto\Key;
use \Defuse\Crypto\Salt;

class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testKeyFromPasswordCorrect()
    {
        $salt1 = Salt::CreateNewRandomSalt();
        $salt2 = Salt::LoadFromAsciiSafeString($salt1->saveToAsciiSafeString());

        $key1 = Key::CreateKeyBasedOnPassword("password", $salt1);
        $key2 = Key::CreateKeyBasedOnPassword("password", $salt2);

        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    public function testKeyFromPasswordWrong()
    {
        $salt = Salt::CreateNewRandomSalt();
        $key1 = Key::CreateKeyBasedOnPassword("password1", $salt);
        $key2 = Key::CreateKeyBasedOnPassword("password2", $salt);
        $this->assertNotEquals($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\CannotPerformOperationException
     * @expectedExceptionMessage You must provide an instance of the Salt class (not a string).
     */
    public function testStringInsteadOfSaltObject()
    {
        Key::CreateKeyBasedOnPassword("password", str_repeat("A", 32));
    }
}
