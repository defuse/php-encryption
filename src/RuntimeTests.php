<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Crypto;

/*
 * We're using static class inheritance to get access to protected methods
 * inside Crypto. To keep things easy to understand, DO NOT USE self:: in this
 * class. Always prefix explicitly with Crypto:: or RuntimeTests::.
 */

class RuntimeTests extends Crypto
{
    /*
     * Runs tests.
     * Raises Ex\CannotPerformOperationException or Ex\CryptoTestFailedException if
     * one of the tests fail. If any tests fails, your system is not capable of
     * performing encryption, so make sure you fail safe in that case.
     */
    public static function runtimeTest()
    {
        // 0: Tests haven't been run yet.
        // 1: Tests have passed.
        // 2: Tests are running right now.
        // 3: Tests have failed.
        static $test_state = 0;

        $config = Crypto::getVersionConfigFromHeader(Core::CURRENT_VERSION, Core::CURRENT_VERSION);

        if ($test_state === 1 || $test_state === 2) {
            return;
        }

        if ($test_state === 3) {
            /* If an intermittent problem caused a test to fail previously, we
             * want that to be indicated to the user with every call to this
             * library. This way, if the user first does something they really
             * don't care about, and just ignores all exceptions, they won't get 
             * screwed when they then start to use the library for something
             * they do care about. */
            throw new Ex\CryptoTestFailedException("Tests failed previously.");
        }

        try {
            $test_state = 2;

            Core::ensureFunctionExists('openssl_get_cipher_methods');
            if (\in_array($config->cipherMethod(), \openssl_get_cipher_methods()) === false) {
                throw new Ex\CryptoTestFailedException("Cipher method not supported.");
            }

            RuntimeTests::AESTestVector($config);
            RuntimeTests::HMACTestVector($config);
            RuntimeTests::HKDFTestVector($config);

            RuntimeTests::testEncryptDecrypt($config);
            if (Core::ourStrlen(Crypto::createNewRandomKey()->getRawBytes()) != $config->keyByteSize()) {
                throw new Ex\CryptoTestFailedException();
            }

            if ($config->encryptionInfoString() == $config->authenticationInfoString()) {
                throw new Ex\CryptoTestFailedException();
            }
        } catch (Ex\CryptoTestFailedException $ex) {
            // Do this, otherwise it will stay in the "tests are running" state.
            $test_state = 3;
            throw $ex;
        }

        // Change this to '0' make the tests always re-run (for benchmarking).
        $test_state = 1;
    }

    private static function testEncryptDecrypt($config)
    {
        $key = Crypto::createNewRandomKey();
        $data = "EnCrYpT EvErYThInG\x00\x00";
        if (empty($config)) {
            $config = Crypto::getVersionConfigFromHeader(Core::CURRENT_VERSION, Core::CURRENT_VERSION);
        }

        // Make sure encrypting then decrypting doesn't change the message.
        $ciphertext = Crypto::encrypt($data, $key, true);
        try {
            $decrypted = Crypto::decrypt($ciphertext, $key, true);
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
            Crypto::decrypt($ciphertext . "a", $key, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */ }

        // Modifying the ciphertext: Changing an IV byte.
        try {
            $ciphertext[4] = chr((ord($ciphertext[4]) + 1) % 256);
            Crypto::decrypt($ciphertext, $key, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */ }

        // Decrypting with the wrong key.
        $key = Crypto::createNewRandomKey();
        $data = "abcdef";
        $ciphertext = Crypto::encrypt($data, $key, true);
        $wrong_key = Crypto::createNewRandomKey();
        try {
            Crypto::decrypt($ciphertext, $wrong_key, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */ }

        // Ciphertext too small (shorter than HMAC).
        $key = Crypto::createNewRandomKey();
        $ciphertext = \str_repeat("A", $config->macByteSize() - 1);
        try {
            Crypto::decrypt($ciphertext, $key, true);
            throw new Ex\CryptoTestFailedException();
        } catch (Ex\InvalidCiphertextException $e) { /* expected */ }
    }

    /**
     * Run-time testing
     *
     * @throws Ex\CryptoTestFailedException
     */
    private static function HKDFTestVector($config)
    {
        // HKDF test vectors from RFC 5869
        if (empty($config)) {
            $config = Crypto::getVersionConfigFromHeader(Core::CURRENT_VERSION, Core::CURRENT_VERSION);
        }

        // Test Case 1
        $ikm = \str_repeat("\x0b", 22);
        $salt = Encoding::hexToBin("000102030405060708090a0b0c");
        $info = Encoding::hexToBin("f0f1f2f3f4f5f6f7f8f9");
        $length = 42;
        $okm = Encoding::hexToBin(
            "3cb25f25faacd57a90434f64d0362f2a" .
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" .
            "34007208d5b887185865"
        );
        $computed_okm = Core::HKDF("sha256", $ikm, $length, $info, $salt, $config);
        if ($computed_okm !== $okm) {
            throw new Ex\CryptoTestFailedException();
        }

        // Test Case 7
        $ikm = \str_repeat("\x0c", 22);
        $length = 42;
        $okm = Encoding::hexToBin(
            "2c91117204d745f3500d636a62f64f0a" .
            "b3bae548aa53d423b0d1f27ebba6f5e5" .
            "673a081d70cce7acfc48"
        );
        $computed_okm = Core::HKDF("sha1", $ikm, $length, '', null, $config);
        if ($computed_okm !== $okm) {
            throw new Ex\CryptoTestFailedException();
        }

    }

    /**
     * Run-Time tests
     *
     * @throws Ex\CryptoTestFailedException
     */
    private static function HMACTestVector($config)
    {
        if (empty($config)) {
            $config = Crypto::getVersionConfigFromHeader(Core::CURRENT_VERSION, Core::CURRENT_VERSION);
        }
        // HMAC test vector From RFC 4231 (Test Case 1)
        $key = \str_repeat("\x0b", 20);
        $data = "Hi There";
        $correct = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        if (\hash_hmac($config->hashFunctionName(), $data, $key) !== $correct) {
            throw new Ex\CryptoTestFailedException();
        }
    }

    /**
     * Run-time tests
     *
     * @throws Ex\CryptoTestFailedException
     */
    private static function AESTestVector($config)
    {
        // AES CTR mode test vector from NIST SP 800-38A
        $key = Encoding::hexToBin(
            "603deb1015ca71be2b73aef0857d7781".
            "1f352c073b6108d72d9810a30914dff4"
        );
        $iv = Encoding::hexToBin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        $plaintext = Encoding::hexToBin(
            "6bc1bee22e409f96e93d7e117393172a" .
            "ae2d8a571e03ac9c9eb76fac45af8e51" .
            "30c81c46a35ce411e5fbc1191a0a52ef" .
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        $ciphertext = Encoding::hexToBin(
            "601ec313775789a5b7a7f504bbf3d228".
            "f443e3ca4d62b59aca84e990cacaf5c5".
            "2b0930daa23de94ce87017ba2d84988d".
            "dfc9c58db67aada613c2dd08457941a6"
        );

        $config = Crypto::getVersionConfigFromHeader(Core::CURRENT_VERSION, Core::CURRENT_VERSION);

        $computed_ciphertext = Crypto::plainEncrypt($plaintext, $key, $iv, $config);
        if ($computed_ciphertext !== $ciphertext) {
            echo str_repeat("\n", 30);
            var_dump($config);
            echo \bin2hex($computed_ciphertext);
            echo "\n---\n";
            echo \bin2hex($ciphertext);
            echo str_repeat("\n", 30);
            throw new Ex\CryptoTestFailedException();
        }

        $computed_plaintext = Crypto::plainDecrypt($ciphertext, $key, $iv, $config);
        if ($computed_plaintext !== $plaintext) {
            throw new Ex\CryptoTestFailedException();
        }
    }

}
