<?php

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
use Defuse\Crypto\Exception as Ex;

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

    // This mirrors the one in RuntimeTests.php, but for passwords.
    // We can't runtime-test the password stuff because it runs PBKDF2.
    public function testEncryptDecryptWithPassword()
    {
        $data = "EnCrYpT EvErYThInG\x00\x00";
        $password = 'password';

        // Make sure encrypting then decrypting doesn't change the message.
        $ciphertext = Crypto::encryptWithPassword($data, $password, true);
        try {
            $decrypted = Crypto::decryptWithPassword($ciphertext, $password, true);
        } catch (Ex\WrongKeyOrModifiedCiphertextException $ex) {
            // It's important to catch this and change it into a
            // Ex\EnvironmentIsBrokenException, otherwise a test failure could trick
            // the user into thinking it's just an invalid ciphertext!
            throw new Ex\EnvironmentIsBrokenException();
        }
        if ($decrypted !== $data) {
            throw new Ex\EnvironmentIsBrokenException();
        }

        // Modifying the ciphertext: Appending a string.
        try {
            Crypto::decryptWithPassword($ciphertext . 'a', $password, true);
            throw new Ex\EnvironmentIsBrokenException();
        } catch (Ex\WrongKeyOrModifiedCiphertextException $e) { /* expected */
        }

        // Modifying the ciphertext: Changing an HMAC byte.
        $indices_to_change = [
            0, // The header.
            Core::HEADER_VERSION_SIZE + 1, // the salt
            Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + 1, // the IV
            Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + Core::BLOCK_BYTE_SIZE + 1, // the ciphertext
        ];

        foreach ($indices_to_change as $index) {
            try {
                $ciphertext[$index] = \chr((\ord($ciphertext[$index]) + 1) % 256);
                Crypto::decryptWithPassword($ciphertext, $password, true);
                throw new Ex\EnvironmentIsBrokenException();
            } catch (Ex\WrongKeyOrModifiedCiphertextException $e) { /* expected */
            }
        }

        // Decrypting with the wrong password.
        $password       = 'password';
        $data           = 'abcdef';
        $ciphertext     = Crypto::encryptWithPassword($data, $password, true);
        $wrong_password = 'wrong_password';
        try {
            Crypto::decryptWithPassword($ciphertext, $wrong_password, true);
            throw new Ex\EnvironmentIsBrokenException();
        } catch (Ex\WrongKeyOrModifiedCiphertextException $e) { /* expected */
        }

        // TypeError; password needs to be a string, not an object
        $password        = Key::createNewRandomKey();
        try {
            $ciphertext     = Crypto::encryptWithPassword($data, $password, true);
            $this->fail('Crypto::encryptWithPassword() should not accept key objects');
        } catch (\TypeError $e) { /* expected */
        }

        // Ciphertext too small.
        $password        = \random_bytes(32);
        $ciphertext      = \str_repeat('A', Core::MINIMUM_CIPHERTEXT_SIZE - 1);
        try {
            Crypto::decryptWithPassword($ciphertext, $password, true);
            throw new Ex\EnvironmentIsBrokenException();
        } catch (Ex\WrongKeyOrModifiedCiphertextException $e) { /* expected */
        }
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     */
    public function testDecryptRawAsHex()
    {
        $ciphertext = Crypto::encryptWithPassword('testdata', 'password', true);
        Crypto::decryptWithPassword($ciphertext, 'password', false);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     */
    public function testDecryptHexAsRaw()
    {
        $ciphertext = Crypto::encryptWithPassword('testdata', 'password', false);
        Crypto::decryptWithPassword($ciphertext, 'password', true);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptTypeErrorA()
    {
        $key = Key::createNewRandomKey();
        Crypto::encrypt(3, $key, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptTypeErrorB()
    {
        Crypto::encrypt("plaintext", 3, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptTypeErrorC()
    {
        $key = Key::createNewRandomKey();
        Crypto::encrypt("plaintext", $key, 3);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptWithPasswordTypeErrorA()
    {
        Crypto::encryptWithPassword(3, "password", false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptWithPasswordTypeErrorB()
    {
        Crypto::encryptWithPassword("plaintext", 3, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testEncryptWithPasswordTypeErrorC()
    {
        Crypto::encryptWithPassword("plaintext", "password", 3);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptTypeErrorA()
    {
        $key = Key::createNewRandomKey();
        Crypto::decrypt(3, $key, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptTypeErrorB()
    {
        Crypto::decrypt("ciphertext", 3, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptTypeErrorC()
    {
        $key = Key::createNewRandomKey();
        Crypto::decrypt("ciphertext", $key, 3);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptWithPasswordTypeErrorA()
    {
        Crypto::decryptWithPassword(3, "password", false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptWithPasswordTypeErrorB()
    {
        Crypto::decryptWithPassword("ciphertext", 3, false);
    }

    /**
     * @expectedException \TypeError
     */
    public function testDecryptWithPasswordTypeErrorC()
    {
        Crypto::decryptWithPassword("ciphertext", "password", 3);
    }

    /**
     * @expectedException \TypeError
     */
    public function testLegacyDecryptTypeErrorA()
    {
        Crypto::legacyDecrypt(3, "key");
    }

    /**
     * @expectedException \TypeError
     */
    public function testLegacyDecryptTypeErrorB()
    {
        Crypto::legacyDecrypt("ciphertext", 3);
    }

}
