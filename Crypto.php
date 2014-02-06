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

class Crypto
{
    // Ciphertext format: [____HMAC____][____IV____][____CIPHERTEXT____].

    public static function Encrypt($plaintext, $key)
    {
        if(strlen($key) < 16)
        {
            trigger_error("Key too small.", E_USER_ERROR);
            return false;
        }

        // Open the encryption module and get some parameters.
        $crypt = mcrypt_module_open(CRYPTO_CIPHER_ALG, "", CRYPTO_CIPHER_MODE, "");
        $keysize = mcrypt_enc_get_key_size($crypt);
        $ivsize = mcrypt_enc_get_iv_size($crypt);

        // Generate a sub-key for encryption.
        $ekey = self::CreateSubkey($key, "encryption", $keysize);
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
        $akey = self::CreateSubkey($key, "authentication", CRYPTO_KEY_BYTE_SIZE);
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
        $akey = self::CreateSubkey($key, "authentication", CRYPTO_KEY_BYTE_SIZE);

        // Make sure the HMAC is correct. If not, the ciphertext has been changed.
        if(self::SlowEquals($hmac, hash_hmac(CRYPTO_HMAC_ALG, $ciphertext, $akey, true)))
        {
            // Open the encryption module and get some parameters.
            $crypt = mcrypt_module_open(CRYPTO_CIPHER_ALG, "", CRYPTO_CIPHER_MODE, "");
            $keysize = mcrypt_enc_get_key_size($crypt);
            $ivsize = mcrypt_enc_get_iv_size($crypt);

            // Re-generate the same encryption sub-key.
            $ekey = self::CreateSubkey($key, "encryption", $keysize);

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
    public static function SecureRandom($octets)
    {
        return mcrypt_create_iv($octets, MCRYPT_DEV_URANDOM);
    }

    /*
     * A simple test and demonstration of how to use this class.
     */
    public static function Test()
    {
        echo "Running crypto test...\n";

        $key = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
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

        echo "PASS\n";
        return true;
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
     * Compares two strings in constant time.
     */
    private static function SlowEquals($a, $b)
    {
        $diff = strlen($a) ^ strlen($b);
        for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
        {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0;
    }

}

// Run the test when and only when this script is executed on the command line.
if(isset($argv) && realpath($argv[0]) == __FILE__)
{
    Crypto::Test();
}

?>
