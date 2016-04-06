<?php

use Defuse\Crypto\Exception as Ex;

use \Defuse\Crypto\Core;
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

    // This mirrors the one in RuntimeTests.php, but for passwords.
    // We can't runtime-test the password stuff because it runs PBKDF2.
    public function testEncryptDecryptWithPassword()
    {
        $data = "EnCrYpT EvErYThInG\x00\x00";
        $password = "password";

        // Make sure encrypting then decrypting doesn't change the message.
        $ciphertext = Crypto::encryptWithPassword($data, $password, true);
        try {
            $decrypted = Crypto::decryptWithPassword($ciphertext, $password, true);
        } catch (Ex\InvalidCiphertextException $ex) {
            // It's important to catch this and change it into a
            // Ex\CryptoTestFailedException, otherwise a test failure could trick
            // the user into thinking it's just an invalid ciphertext!
            throw new Ex\CryptoTestFailedException();
        }
        if ($decrypted !== $data) {
            throw new Ex\CryptoTestFailedException();
        }

        // Modifying the ciphertext: Appending a string.
        try {
            Crypto::decryptWithPassword($ciphertext . 'a', $password, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */
        }

        // Modifying the ciphertext: Changing an IV byte.
        try {
            $ciphertext[4] = \chr((\ord($ciphertext[4]) + 1) % 256);
            Crypto::decryptWithPassword($ciphertext, $password, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */
        }

        // Decrypting with the wrong password.
        $password       = "password";
        $data           = 'abcdef';
        $ciphertext     = Crypto::encryptWithPassword($data, $password, true);
        $wrong_password = "wrong_password";
        try {
            Crypto::decryptWithPassword($ciphertext, $wrong_password, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */
        }

        // Ciphertext too small (shorter than HMAC).
        $password   = "password";
        $ciphertext = \str_repeat('A', Core::MAC_BYTE_SIZE - 1);
        try {
            Crypto::decryptWithPassword($ciphertext, $password, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */
        }
    }
}
