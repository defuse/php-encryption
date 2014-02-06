<?php

/*
 * PHP Encryption Library
 * Copyright (c) 2013, Taylor Hornby
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

// Configuration constants. Don't change unless you know what you're doing.
// The block cipher to use for encryption.
define('CRYPTO_CIPHER_ALG', MCRYPT_RIJNDAEL_128);
// The hash function to use for HMAC.
define('CRYPTO_HMAC_ALG', 'sha256');
// The byte length of the encryption and HMAC keys.
define('CRYPTO_KEY_BYTE_SIZE', 16);
// The block cipher mode of operation to use.
define('CRYPTO_CIPHER_MODE', 'cbc');
// The length of an HMAC, so it can be extracted from the ciphertext.
define('CRYPTO_HMAC_BYTES', strlen(hash_hmac(CRYPTO_HMAC_ALG, '', '', true)));

// Distinguisher strings for the KDF.
define('ENCR_DISTINGUISHER', 'DefusePHP|KeyForEncryption');
define('AUTH_DISTINGUISHER', 'DefusePHP|KeyForAuthentication');

class CannotPerformOperationException extends Exception {}

class Crypto
{
    // Ciphertext format: [____HMAC____][____IV____][____CIPHERTEXT____].

    /*
     * Use this to generate the encryption key.
     */
    public static function CreateNewRandomKey()
    {
        return self::SecureRandom(CRYPTO_KEY_BYTE_SIZE);
    }

    public static function Encrypt($plaintext, $key)
    {
        if (strlen($key) < CRYPTO_KEY_BYTE_SIZE)
        {
            throw new CannotPerformOperationException("Key too small.");
        }

        // Open the encryption module and get some parameters.
        $crypt = mcrypt_module_open(CRYPTO_CIPHER_ALG, "", CRYPTO_CIPHER_MODE, "");
        $keysize = mcrypt_enc_get_key_size($crypt);
        $ivsize = mcrypt_enc_get_iv_size($crypt);

        // Generate a sub-key for encryption.
        $ekey = self::HKDF(CRYPTO_HMAC_ALG, $key, $keysize, ENCR_DISTINGUISHER);
        // Generate a random initialization vector.
        $iv = self::SecureRandom($ivsize);

        // Pad the plaintext to a multiple of the block size (PKCS #7)
        $block = mcrypt_enc_get_block_size($crypt);
        $pad = $block - (strlen($plaintext) % $block);
        $plaintext .= str_repeat(chr($pad), $pad);

        // Do the encryption.
        mcrypt_generic_init($crypt, $ekey, $iv);
        $ciphertext = $iv . mcrypt_generic($crypt, $plaintext); 
        mcrypt_generic_deinit($crypt);
        mcrypt_module_close($crypt);

        // Generate a sub-key for authentication.
        $akey = self::HKDF(CRYPTO_HMAC_ALG, $key, CRYPTO_KEY_BYTE_SIZE, AUTH_DISTINGUISHER);
        // Apply the HMAC.
        $auth = hash_hmac(CRYPTO_HMAC_ALG, $ciphertext, $akey, true);
        $ciphertext = $auth . $ciphertext;

        return $ciphertext;
    }

    public static function Decrypt($ciphertext, $key)
    {
        // Extract the HMAC from the front of the ciphertext.
        if(strlen($ciphertext) <= CRYPTO_HMAC_BYTES)
            return false;
        $hmac = substr($ciphertext, 0, CRYPTO_HMAC_BYTES);
        $ciphertext = substr($ciphertext, CRYPTO_HMAC_BYTES);

        // Re-generate the same authentication sub-key.
        $akey = self::HKDF(CRYPTO_HMAC_ALG, $key, CRYPTO_KEY_BYTE_SIZE, AUTH_DISTINGUISHER);

        // Make sure the HMAC is correct. If not, the ciphertext has been changed.
        if (self::VerifyHMAC($hmac, $ciphertext, $akey))
        {
            // Open the encryption module and get some parameters.
            $crypt = mcrypt_module_open(CRYPTO_CIPHER_ALG, "", CRYPTO_CIPHER_MODE, "");
            $keysize = mcrypt_enc_get_key_size($crypt);
            $ivsize = mcrypt_enc_get_iv_size($crypt);

            // Re-generate the same encryption sub-key.
            $ekey = self::HKDF(CRYPTO_HMAC_ALG, $key, $keysize, ENCR_DISTINGUISHER);

            // Extract the initialization vector from the ciphertext.
            if(strlen($ciphertext) <= $ivsize)
                return false;
            $iv = substr($ciphertext, 0, $ivsize);
            $ciphertext = substr($ciphertext, $ivsize);
            
            // Do the decryption.
            mcrypt_generic_init($crypt, $ekey, $iv);
            $plaintext = mdecrypt_generic($crypt, $ciphertext);
            mcrypt_generic_deinit($crypt);
            mcrypt_module_close($crypt);

            // Remove the padding.
            $pad = ord($plaintext[strlen($plaintext) - 1]);
            $plaintext = substr($plaintext, 0, strlen($plaintext) - $pad);

            return $plaintext;
        }
        else
        {
            // If the ciphertext has been modified, refuse to decrypt it.
            return false;
        }
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
        $digest_length = CRYPTO_HMAC_BYTES;
        if ($hash != CRYPTO_HMAC_ALG) {
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
        $message_hmac = hash_hmac(CRYPTO_HMAC_ALG, $message, $key, true);

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

        $blind = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        if ($blind === FALSE) {
            throw new CannotPerformOperationException();
        }

        $message_compare = hash_hmac(CRYPTO_HMAC_ALG, $message_hmac, $blind);
        $correct_compare = hash_hmac(CRYPTO_HMAC_ALG, $correct_hmac, $blind);
        return $correct_compare === $message_compare;
    }

    /*
     * A simple test and demonstration of how to use this class.
     */
    public static function Test()
    {
        echo "Running crypto test...\n";

        $key = Crypto::CreateNewRandomKey();
        $data = "EnCrYpT EvErYThInG\x00\x00";

        $ciphertext = Crypto::Encrypt($data, $key);
        echo "Ciphertext: " . bin2hex($ciphertext) . "\n";

        $decrypted = Crypto::Decrypt($ciphertext, $key);
        echo "Decrypted: " . $decrypted . "\n";

        if($decrypted != $data)
        {
            echo "FAIL: Decrypted data is not the same as the original.";
            return false;
        }

        if(Crypto::Decrypt($ciphertext . "a", $key) !== false)
        {
            echo "FAIL: Ciphertext tampering not detected.";
            return false;
        }

        $ciphertext[0] = chr((ord($ciphertext[0]) + 1) % 256);
        if(Crypto::Decrypt($ciphertext, $key) !== false)
        {
            echo "FAIL: Ciphertext tampering not detected.";
            return false;
        }

        $key = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        $data = "abcdef";
        $ciphertext = Crypto::Encrypt($data, $key);
        $wrong_key = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        if (Crypto::Decrypt($ciphertext, $wrong_key))
        {
            echo "FAIL: Ciphertext decrypts with an incorrect key.";
            return false;
        }


        $hkdf_tests = array(
            // Test Case 1
            array(
                "hash" => "sha256",
                "ikm" => str_repeat("\x0b", 22),
                "salt" => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C",
                "info" => "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9",
                "l" => 42,
                "okm" => "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f" . 
                         "\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a" .
                         "\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf\x34" .
                         "\x00\x72\x08\xd5\xb8\x87\x18\x58\x65"
            ),
            // Test Case 2
            array(
                "hash" => "sha256",
                "ikm" => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b" .
                         "\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17" . 
                         "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23" . 
                         "\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" . 
                         "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b" .
                         "\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47" .
                         "\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",

                "salt" => "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a" . 
                          "\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75" .
                          "\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80" .
                          "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b" .
                          "\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96" .
                          "\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1" .
                          "\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac" .
                          "\xad\xae\xaf",

                "info" => "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba" .
                          "\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5" .
                          "\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" .
                          "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb" .
                          "\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6" .
                          "\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1" .
                          "\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc" .
                          "\xfd\xfe\xff",
                "l" => 82,
                "okm" => "\xb1\x1e\x39\x8d\xc8\x03\x27\xa1\xc8\xe7\xf7" .
                         "\x8c\x59\x6a\x49\x34\x4f\x01\x2e\xda\x2d\x4e" .
                         "\xfa\xd8\xa0\x50\xcc\x4c\x19\xaf\xa9\x7c\x59" .
                         "\x04\x5a\x99\xca\xc7\x82\x72\x71\xcb\x41\xc6" .
                         "\x5e\x59\x0e\x09\xda\x32\x75\x60\x0c\x2f\x09" .
                         "\xb8\x36\x77\x93\xa9\xac\xa3\xdb\x71\xcc\x30" .
                         "\xc5\x81\x79\xec\x3e\x87\xc1\x4c\x01\xd5\xc1" .
                         "\xf3\x43\x4f\x1d\x87"
            ),
            // Test Case 3
            array(
                "hash" => "sha256",
                "ikm" => str_repeat("\x0b", 22),
                "salt" => "",
                "info" => "",
                "l" => 42,
                "okm" => "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f" .
                         "\x80\x2a\x06\x3c\x5a\x31\xb8\xa1\x1f\x5c" .
                         "\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73" .
                         "\x8d\x2d\x9d\x20\x13\x95\xfa\xa4\xb6\x1a" .
                         "\x96\xc8"
            ),
            // Test Case 7
            array(
                "hash" => "sha1",
                "ikm" => str_repeat("\x0c", 22),
                "salt" => NULL,
                "info" => '',
                "l" => 42,
                "okm" => "\x2c\x91\x11\x72\x04\xd7\x45\xf3\x50\x0d" .
                         "\x63\x6a\x62\xf6\x4f\x0a\xb3\xba\xe5\x48" .
                         "\xaa\x53\xd4\x23\xb0\xd1\xf2\x7e\xbb\xa6" .
                         "\xf5\xe5\x67\x3a\x08\x1d\x70\xcc\xe7\xac" .
                         "\xfc\x48"
            ),
        );

        foreach ($hkdf_tests as $test) {
            $computed = self::HKDF($test['hash'], $test['ikm'], $test['l'], $test['info'], $test['salt']);
            $correct = $test['okm'];
            if ($computed !== $correct) {
                echo "FAIL: HKDF test vector.\n";
                echo "COMPUTED " . bin2hex($computed) . "\n";
                echo "CORRECT " . bin2hex($correct) . "\n";
                return FALSE;
            }
        }

        echo "PASS\n";
        return true;
    }

}

// Run the test when and only when this script is executed on the command line.
if(isset($argv) && realpath($argv[0]) == __FILE__)
{
    Crypto::Test();
}

?>
