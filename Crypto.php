<?php

/*
 * PHP Encryption Library
 * Copyright (c) 2014, Taylor Hornby
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

class CannotPerformOperationException extends Exception {}
class InvalidCiphertextException extends Exception {}
class CryptoTestFailedException extends Exception {}

class Crypto
{
    // Ciphertext format: [____HMAC____][____IV____][____CIPHERTEXT____].

    const CIPHER = MCRYPT_RIJNDAEL_128;
    const KEY_BYTE_SIZE = 16;
    const CIPHER_MODE = 'cbc';
    const HASH_FUNCTION = 'sha256';
    const MAC_BYTE_SIZE = 32;

    const ENCRYPTION_INFO = 'DefusePHP|KeyForEncryption';
    const AUTHENTICATION_INFO = 'DefusePHP|KeyForAuthentication';

    /*
     * Use this to generate the encryption key.
     */
    public static function CreateNewRandomKey()
    {
        Crypto::RuntimeTest();

        return self::SecureRandom(self::KEY_BYTE_SIZE);
    }

    public static function Encrypt($plaintext, $key)
    {
        Crypto::RuntimeTest();

        if (strlen($key) !== self::KEY_BYTE_SIZE)
        {
            throw new CannotPerformOperationException("Bad key.");
        }

        // Generate a sub-key for encryption.
        $keysize = self::KEY_BYTE_SIZE;
        $ekey = self::HKDF(self::HASH_FUNCTION, $key, $keysize, self::ENCRYPTION_INFO);

        // Generate a random initialization vector.
        $ivsize = mcrypt_get_iv_size(self::CIPHER, self::CIPHER_MODE);
        $iv = self::SecureRandom($ivsize);

        $ciphertext = $iv . self::PlainEncrypt($plaintext, $ekey, $iv);

        // Generate a sub-key for authentication and apply the HMAC.
        $akey = self::HKDF(self::HASH_FUNCTION, $key, self::KEY_BYTE_SIZE, self::AUTHENTICATION_INFO);
        $auth = hash_hmac(self::HASH_FUNCTION, $ciphertext, $akey, true);
        $ciphertext = $auth . $ciphertext;

        return $ciphertext;
    }

    public static function Decrypt($ciphertext, $key)
    {
        Crypto::RuntimeTest();

        // Extract the HMAC from the front of the ciphertext.
        if(strlen($ciphertext) <= self::MAC_BYTE_SIZE) {
            throw new InvalidCiphertextException();
        }
        $hmac = substr($ciphertext, 0, self::MAC_BYTE_SIZE);
        $ciphertext = substr($ciphertext, self::MAC_BYTE_SIZE);

        // Regenerate the same authentication sub-key.
        $akey = self::HKDF(self::HASH_FUNCTION, $key, self::KEY_BYTE_SIZE, self::AUTHENTICATION_INFO);

        if (self::VerifyHMAC($hmac, $ciphertext, $akey))
        {
            // Regenerate the same encryption sub-key.
            $keysize = self::KEY_BYTE_SIZE;
            $ekey = self::HKDF(self::HASH_FUNCTION, $key, $keysize, self::ENCRYPTION_INFO);

            // Extract the initialization vector from the ciphertext.
            $ivsize = mcrypt_get_iv_size(self::CIPHER, self::CIPHER_MODE);
            if(strlen($ciphertext) <= $ivsize) {
                throw new InvalidCiphertextException();
            }
            $iv = substr($ciphertext, 0, $ivsize);
            $ciphertext = substr($ciphertext, $ivsize);
            
            $plaintext = self::PlainDecrypt($ciphertext, $ekey, $iv);

            return $plaintext;
        }
        else
        {
            /*
             * We throw an exception instead of returning FALSE because we want
             * a script that doesn't handle this condition to CRASH, instead
             * of thinking the ciphertext decrypted to the value FALSE.
             */
             throw new InvalidCiphertextException();
        }
    }

    /*
     * Never call this method directly!
     */
    private static function PlainEncrypt($plaintext, $key, $iv)
    {
        $crypt = mcrypt_module_open(self::CIPHER, "", self::CIPHER_MODE, "");

        // Pad the plaintext to a multiple of the block size.
        $block = mcrypt_enc_get_block_size($crypt);
        $pad = $block - (strlen($plaintext) % $block);
        $plaintext .= str_repeat(chr($pad), $pad);

        mcrypt_generic_init($crypt, $key, $iv);
        $ciphertext = mcrypt_generic($crypt, $plaintext);
        mcrypt_generic_deinit($crypt);
        mcrypt_module_close($crypt);

        return $ciphertext;
    }

    /*
     * Never call this method directly!
     */
    private static function PlainDecrypt($ciphertext, $key, $iv)
    {
        $crypt = mcrypt_module_open(self::CIPHER, "", self::CIPHER_MODE, "");

        mcrypt_generic_init($crypt, $key, $iv);
        $plaintext = mdecrypt_generic($crypt, $ciphertext);
        mcrypt_generic_deinit($crypt);
        mcrypt_module_close($crypt);

        // Remove the padding.
        $pad = ord($plaintext[strlen($plaintext) - 1]);
        $plaintext = substr($plaintext, 0, strlen($plaintext) - $pad);

        return $plaintext;
    }

    /*
     * Returns a random binary string of length $octets bytes.
     */
    private static function SecureRandom($octets)
    {
        $random = mcrypt_create_iv($octets, MCRYPT_DEV_URANDOM);
        if ($random === FALSE) {
            throw new CannotPerformOperationException();
        } else {
            return $random;
        }
    }

    /*
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     */
    private static function HKDF($hash, $ikm, $length, $info = '', $salt = NULL)
    {
        // Find the correct digest length as quickly as we can.
        $digest_length = self::MAC_BYTE_SIZE;
        if ($hash != self::HASH_FUNCTION) {
            $digest_length = strlen(hash_hmac($hash, '', '', true));
        }

        // Sanity-check the desired output length.
        if (empty($length) || !is_int($length) ||
            $length < 0 || $length > 255 * $digest_length) {
            return CannotPerformOperationException();
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (is_null($salt)) {
            $salt = str_repeat("\x00", $digest_length);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = hash_hmac($hash, $ikm, $salt, true);

        // HKDF-Expand:

        // This check is useless, but it serves as a reminder to the spec.
        if (strlen($prk) < $digest_length) {
            throw new CannotPerformOperationException();
        }

        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; strlen($t) < $length; $block_index++) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = hash_hmac(
                $hash,
                $last_block . $info . chr($block_index),
                $prk,
                true
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }

        // ORM = first L octets of T
        return substr($t, 0, $length);
    }

    private static function VerifyHMAC($correct_hmac, $message, $key)
    {
        $message_hmac = hash_hmac(self::HASH_FUNCTION, $message, $key, true);

        // We can't just compare the strings with '==', since it would make
        // timing attacks possible. We could use the XOR-OR constant-time
        // comparison algorithm, but I'm not sure if that's good enough way up
        // here in an interpreted language. So we use the method of HMACing the 
        // strings we want to compare with a random key, then comparing those.

        // NOTE: This leaks information when the strings are not the same
        // length, but they should always be the same length here. Enforce it:
        if (strlen($correct_hmac) !== strlen($message_hmac)) {
            throw new CannotPerformOperationException();
        }

        $blind = self::CreateNewRandomKey();
        $message_compare = hash_hmac(self::HASH_FUNCTION, $message_hmac, $blind);
        $correct_compare = hash_hmac(self::HASH_FUNCTION, $correct_hmac, $blind);
        return $correct_compare === $message_compare;
    }

    public static function RuntimeTest()
    {
        // 0: Tests haven't been run yet.
        // 1: Tests have passed.
        // 2: Tests are running right now.
        // 3: Tests have failed.
        static $test_state = 0;

        if ($test_state === 1 || $test_state === 2) {
            return;
        }

        try {
            $test_state = 2;
            self::AESTestVector();
            self::HMACTestVector();
            self::HKDFTestVector();

            self::TestEncryptDecrypt();
            if (strlen(Crypto::CreateNewRandomKey()) != self::KEY_BYTE_SIZE) {
                throw new CryptoTestFailedException();
            }

            if (self::ENCRYPTION_INFO == self::AUTHENTICATION_INFO) {
                throw new CryptoTestFailedException();
            }
        } catch (CryptoTestFailedException $ex) {
            // Do this, otherwise it will stay in the "tests are running" state.
            $test_state = 3;
            throw $ex;
        }

        // Change this to '0' make the tests always re-run (for benchmarking).
        $test_state = 1;
    }

    private static function TestEncryptDecrypt()
    {
        $key = Crypto::CreateNewRandomKey();
        $data = "EnCrYpT EvErYThInG\x00\x00";

        // Make sure encrypting then decrypting doesn't change the message.
        $ciphertext = Crypto::Encrypt($data, $key);
        $decrypted = Crypto::Decrypt($ciphertext, $key);
        if($decrypted !== $data)
        {
            throw new CryptoTestFailedException();
        }

        // Modifying the ciphertext: Appending a string.
        try {
            Crypto::Decrypt($ciphertext . "a", $key);
            throw new CryptoTestFailedException();
        } catch (InvalidCiphertextException $e) { /* expected */ }

        // Modifying the ciphertext: Changing an IV byte.
        try {
            $ciphertext[0] = chr((ord($ciphertext[0]) + 1) % 256);
            Crypto::Decrypt($ciphertext, $key);
            throw new CryptoTestFailedException();
        } catch (InvalidCiphertextException $e) { /* expected */ }

        // Decrypting with the wrong key.
        $key = Crypto::CreateNewRandomKey();
        $data = "abcdef";
        $ciphertext = Crypto::Encrypt($data, $key);
        $wrong_key = Crypto::CreateNewRandomKey();
        try {
            Crypto::Decrypt($ciphertext, $wrong_key);
            throw new CryptoTestFailedException();
        } catch (InvalidCiphertextException $e) { /* expected */ }

        // Ciphertext too small (shorter than HMAC).
        $key = Crypto::CreateNewRandomKey();
        $ciphertext = str_repeat("A", self::MAC_BYTE_SIZE - 1);
        try {
            Crypto::Decrypt($ciphertext, $key);
            throw new CryptoTestFailedException();
        } catch (InvalidCiphertextException $e) { /* expected */ }
    }

    private static function HKDFTestVector()
    {
        // HKDF test vectors from RFC 5869

        // Test Case 1
        $ikm = str_repeat("\x0b", 22);
        $salt = self::hexToBytes("000102030405060708090a0b0c");
        $info = self::hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        $length = 42;
        $okm = self::hexToBytes(
            "3cb25f25faacd57a90434f64d0362f2a" .
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" .
            "34007208d5b887185865"
        );
        $computed_okm = self::HKDF("sha256", $ikm, $length, $info, $salt);
        if ($computed_okm !== $okm) {
            throw new CryptoTestFailedException();
        }

        // Test Case 7
        $ikm = str_repeat("\x0c", 22);
        $length = 42;
        $okm = self::hexToBytes(
            "2c91117204d745f3500d636a62f64f0a" .
            "b3bae548aa53d423b0d1f27ebba6f5e5" .
            "673a081d70cce7acfc48"
        );
        $computed_okm = self::HKDF("sha1", $ikm, $length);
        if ($computed_okm !== $okm) {
            throw new CryptoTestFailedException();
        }

    }

    private static function HMACTestVector()
    {
        // HMAC test vector From RFC 4231 (Test Case 1)
        $key = str_repeat("\x0b", 20);
        $data = "Hi There";
        $correct = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        if (hash_hmac(self::HASH_FUNCTION, $data, $key) != $correct) {
            throw new CryptoTestFailedException();
        }
    }

    private static function AESTestVector()
    {
        // AES CBC mode test vector from NIST SP 800-38A
        $key = self::hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        $iv = self::hexToBytes("000102030405060708090a0b0c0d0e0f");
        $plaintext = self::hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a" . 
            "ae2d8a571e03ac9c9eb76fac45af8e51" .
            "30c81c46a35ce411e5fbc1191a0a52ef" .
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        $ciphertext = self::hexToBytes(
            "7649abac8119b246cee98e9b12e9197d" .
            "5086cb9b507219ee95db113a917678b2" .
            "73bed6b8e3c1743b7116e69e22229516" .
            "3ff1caa1681fac09120eca307586e1a7" .
            /* Block due to padding. Not from NIST test vector. 
                Padding Block: 10101010101010101010101010101010
                Ciphertext:    3ff1caa1681fac09120eca307586e1a7
                           (+) 2fe1dab1780fbc19021eda206596f1b7 
                           AES 8cb82807230e1321d3fae00d18cc2012
             
             */
            "8cb82807230e1321d3fae00d18cc2012"
        );

        $computed_ciphertext = self::PlainEncrypt($plaintext, $key, $iv);
        if ($computed_ciphertext !== $ciphertext) {
            echo bin2hex($computed_ciphertext);
            throw new CryptoTestFailedException();
        }

        $computed_plaintext = self::PlainDecrypt($ciphertext, $key, $iv);
        if ($computed_plaintext !== $plaintext) {
            throw new CryptoTestFailedException();
        }
    }

    private static function hexToBytes($hex_string)
    {
        return pack("H*", $hex_string);
    }

}

?>
