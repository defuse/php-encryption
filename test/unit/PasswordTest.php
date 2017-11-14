<?php

use \Defuse\Crypto\KeyProtectedByPassword;

class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testKeyProtectedByPasswordCorrect()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey2 = KeyProtectedByPassword::loadFromAsciiSafeString($pkey1->saveToAsciiSafeString());

        $key1 = $pkey1->unlockKey('password');
        $key2 = $pkey2->unlockKey('password');

        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     */
    public function testKeyProtectedByPasswordWrong()
    {
        $pkey = KeyProtectedByPassword::createRandomPasswordProtectedKey('rightpassword');
        $key1 = $pkey->unlockKey('wrongpassword');
    }
    /**
     * Check that a new password was set.
     */
    public function testChangePassword()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey1_enc_ascii = $pkey1->saveToAsciiSafeString();
        $key1 = $pkey1->unlockKey('password')->saveToAsciiSafeString();

        $pkey1->changePassword('password', 'new password');
        $pkey1_enc_ascii_new = $pkey1->saveToAsciiSafeString();
        $key1_new = $pkey1->unlockKey('new password')->saveToAsciiSafeString();

        // The encrypted_key should not be the same.
        $this->assertNotSame($pkey1_enc_ascii, $pkey1_enc_ascii_new);

        // The encrypted_key should not be the same.
        $this->assertSame($key1, $key1_new);
    }
}
