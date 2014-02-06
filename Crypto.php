<?php

/*
 * Data encryption in PHP.
 *
 * This script is released into the public domain by Defuse Security.
 * You may use it for any purpose whatsoever and redistribute it with or without
 * modification.
 *
 * https://defuse.ca/secure-php-encryption.htm
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
        $ekey = self::HKDF($key, $keysize, ENCR_DISTINGUISHER);
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
        $akey = self::HKDF($key, CRYPTO_KEY_BYTE_SIZE, AUTH_DISTINGUISHER);
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
        $akey = self::HKDF($key, CRYPTO_KEY_BYTE_SIZE, AUTH_DISTINGUISHER);

        // Make sure the HMAC is correct. If not, the ciphertext has been changed.
        if (self::VerifyHMAC($hmac, $ciphertext, $akey))
        {
            // Open the encryption module and get some parameters.
            $crypt = mcrypt_module_open(CRYPTO_CIPHER_ALG, "", CRYPTO_CIPHER_MODE, "");
            $keysize = mcrypt_enc_get_key_size($crypt);
            $ivsize = mcrypt_enc_get_iv_size($crypt);

            // Re-generate the same encryption sub-key.
            $ekey = self::HKDF($key, $keysize, ENCR_DISTINGUISHER);

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
     * Creates a sub-key from a master key for a specific purpose.
     */
    private static function CreateSubkey($master, $purpose, $bytes)
    {
        $source = hash_hmac("sha512", $purpose, $master, true);
        if(strlen($source) < $bytes) {
            trigger_error("Subkey too big.", E_USER_ERROR);
            return $source; // fail safe
        }

        return substr($source, 0, $bytes);
    }

    /*
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     */
    private static function HKDF($ikm, $length, $info = '', $salt = NULL)
    {
        if (empty($length) || !is_int($length) ||
            $length < 0 || $length > 255 * CRYPTO_HMAC_BYTES) {
            return CannotPerformOperationException();
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (is_null($salt)) {
            $salt = str_repeat("\x00", CRYPTO_HMAC_BYTES);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = hash_hmac(CRYPTO_HMAC_ALG, $ikm, $salt, true);

        // HKDF-Expand:

        // This check is useless, but it serves as a reminder to the spec.
        if (strlen($prk) < CRYPTO_HMAC_BYTES) {
            throw new CannotPerformOperationException();
        }

        $t = '';
        $last_block = '';
        for ($block_index = 1; strlen($t) < $length; $block_index++) {
            $last_block = hash_hmac(
                CRYPTO_HMAC_ALG,
                $last_block . $info . chr($block_index),
                $prk,
                true
            );
            $t .= $last_block;
        }

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
        // TODO: Make this better so it can be a runtime test.
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
                "ikm" => str_repeat("\x0b", 22),
                "salt" => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C",
                "info" => "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9",
                "l" => 42,
                "okm" => "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65"
            ),
            // Test Case 3
            array(
                "ikm" => str_repeat("\x0b", 22),
                "salt" => "",
                "info" => "",
                "l" => 42,
                "okm" => "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8"
            )
            // TODO: add the other test cases, espcially the one where no salt
            // is provided. We may have to make HKDF() take the hash as
            // a paremeter to accomodate this, but that's better anyway.
        );

        foreach ($hkdf_tests as $test) {
            $computed = self::HKDF($test['ikm'], $test['l'], $test['info'], $test['salt']);
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
