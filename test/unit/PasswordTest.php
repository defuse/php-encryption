<?php

use \Defuse\Crypto\KeyProtectedByPassword;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class PasswordTest extends TestCase
{
    public function testKeyProtectedByPasswordCorrect()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey2 = KeyProtectedByPassword::loadFromAsciiSafeString($pkey1->saveToAsciiSafeString());

        $key1 = $pkey1->unlockKey('password');
        $key2 = $pkey2->unlockKey('password');

        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    public function testKeyProtectedByPasswordWrong()
    {
        $pkey = KeyProtectedByPassword::createRandomPasswordProtectedKey('rightpassword');
        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
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

        // The actual key should be the same.
        $this->assertSame($key1, $key1_new);
    }

    /**
     * Check that changing the password actually changes the password.
     */
    function testPasswordActuallyChanges()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey1->changePassword('password', 'new password');

        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        $pkey1->unlockKey('password');
    }

    function testMalformedLoad()
    {
        $pkey1 = KeyProtectedByPassword::createRandomPasswordProtectedKey('password');
        $pkey1_enc_ascii = $pkey1->saveToAsciiSafeString();

        $pkey1_enc_ascii[0] = "\xFF";

        $this->expectException(\Defuse\Crypto\Exception\BadFormatException::class);
        KeyProtectedByPassword::loadFromAsciiSafeString($pkey1_enc_ascii);
    }
}
