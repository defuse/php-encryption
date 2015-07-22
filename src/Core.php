<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

class Core
{
    const VERSION = "\xD3\xF5\x02\x00";
    const HEADER_VERSION_SIZE = 4; // This should never change

    /**
     * Use this to generate a random encryption key.
     *
     * @return string
     */
    public static function createNewRandomKey()
    {
        $valid = 0;
        $config = self::getCoreVersionConfig(1, 0, $valid);
        return self::secureRandom($config['KEY_BYTE_SIZE']);
    }
    /**
     * Convert a binary string into a hexadecimal string without cache-timing 
     * leaks
     *
     * @param string $bin_string (raw binary)
     * @return string
     */
    public static function binToHex($bin_string)
    {
        $hex = '';
        $len = self::ourStrlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($bin_string[$i]) & 0xf;
            $b = \ord($bin_string[$i]) >> 4;
            $hex .= \chr(87 + $b + ((($b - 10) >> 8) & ~38));
            $hex .= \chr(87 + $c + ((($c - 10) >> 8) & ~38));
        }
        return $hex;
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing 
     * leaks
     *
     * @param string $hex_string
     * @return string (raw binary)
     */
    public static function hexToBin($hex_string)
    {
        $hex_pos = 0;
        $bin = '';
        $hex_len = self::ourStrlen($hex_string);
        $state = 0;
        $c_acc = 0;

        while ($hex_pos < $hex_len) {
            $c = \ord($hex_string[$hex_pos]);
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                throw new \RangeException(
                    'Crypto::hexToBin() only expects hexadecimal characters'
                );
            }
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= \chr($c_acc | $c_val);
            }
            $state = $state ? 0 : 1;
            ++$hex_pos;
        }
        return $bin;
    }

    /**
     * Increment a counter (prevent nonce reuse)
     *
     * @param string $ctr - raw binary
     * @param int $inc - how much?
     *
     * @return string (raw binary)
     */
    public static function incrementCounter($ctr, $inc, &$config)
    {
        static $ivsize = null;
        if ($ivsize === null) {
            $ivsize = \openssl_cipher_iv_length($config['CIPHER_METHOD']);
        }

        /**
         * We start at the rightmost byte (big-endian)
         * So, too, does OpenSSL: http://stackoverflow.com/a/3146214/2224584
         */

        for ($i = $ivsize - 1; $i >= 0; --$i) {
            $c = \ord($ctr[$i]);

            $ctr[$i] = \chr(($c + $inc) & 0xFF);
            if (($c + $inc) <= 255) {
                // We don't need to keep incrementing to the left unless we exceed 255
                break;
            }
            $inc = ($inc >> 8) & ~0;
            ++$inc;
        }
        return $ctr;
    }

    /**
     * Returns a random binary string of length $octets bytes.
     *
     * @param int $octets
     * @return string (raw binary)
     * @throws Ex\CannotPerformOperationException
     */
    protected static function secureRandom($octets)
    {
        self::ensureFunctionExists('openssl_random_pseudo_bytes');
        $secure = false;
        $random = \openssl_random_pseudo_bytes($octets, $secure);
        if ($random === false || $secure === false) {
            throw new Ex\CannotPerformOperationException(
                "openssl_random_pseudo_bytes() failed."
            );
        }
        return $random;
    }
    /**
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     *
     * @param string $hash Hash Function
     * @param string $ikm Initial Keying Material
     * @param int $length How many bytes?
     * @param string $info What sort of key are we deriving?
     * @param string $salt
     * @return string
     * @throws Ex\CannotPerformOperationException
     */
    protected static function HKDF($hash, $ikm, $length, $info = '', $salt = null, $config = null)
    {
        if (empty($config)) {
            $valid = 0;
            $config = self::getVersionConfig(1, 0, $valid);
        }
        // Find the correct digest length as quickly as we can.
        $digest_length = $config['MAC_BYTE_SIZE'];
        if ($hash != $config['HASH_FUNCTION']) {
            $digest_length = self::ourStrlen(\hash_hmac($hash, '', '', true));
        }
        // Sanity-check the desired output length.
        if (empty($length) || !\is_int($length) ||
            $length < 0 || $length > 255 * $digest_length) {
            throw new Ex\CannotPerformOperationException(
                "Bad output length requested of HKDF."
            );
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (\is_null($salt)) {
            $salt = \str_repeat("\x00", $digest_length);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = \hash_hmac($hash, $ikm, $salt, true);

        // HKDF-Expand:

        // This check is useless, but it serves as a reminder to the spec.
        if (self::ourStrlen($prk) < $digest_length) {
            throw new Ex\CannotPerformOperationException();
        }

        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; self::ourStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = \hash_hmac(
                $hash,
                $last_block . $info . \chr($block_index),
                $prk,
                true
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }

        // ORM = first L octets of T
        $orm = self::ourSubstr($t, 0, $length);
        if ($orm === false) {
            throw new Ex\CannotPerformOperationException();
        }
        return $orm;
    }

    /**
     * Verify a HMAC without crypto side-channels
     *
     * @staticvar boolean $native Use native hash_equals()?
     * @param string $expected string (raw binary)
     * @param string $given string (raw binary)
     * @return boolean
     * @throws Ex\CannotPerformOperation
     */
    protected static function hashEquals($expected, $given)
    {
        static $native = null;
        if ($native === null) {
            $native = \function_exists('hash_equals');
        }
        if ($native) {
            return \hash_equals($expected, $given);
        }
        static $config = null;
        if ($config === null) {
            $valid = 0;
            $config = self::getCoreVersionConfig(1, 0, $valid);
        }

        // We can't just compare the strings with '==', since it would make
        // timing attacks possible. We could use the XOR-OR constant-time
        // comparison algorithm, but I'm not sure if that's good enough way up
        // here in an interpreted language. So we use the method of HMACing the
        // strings we want to compare with a random key, then comparing those.

        // NOTE: This leaks information when the strings are not the same
        // length, but they should always be the same length here. Enforce it:
        if (self::ourStrlen($expected) !== self::ourStrlen($given)) {
            throw new Ex\CannotPerformOperationException();
        }

        $blind = self::createNewRandomKey();
        $message_compare = hash_hmac($config['HASH_FUNCTION'], $given, $blind);
        $correct_compare = hash_hmac($config['HASH_FUNCTION'], $expected, $blind);
        return $correct_compare === $message_compare;
    }
    /**
     * If the constant doesn't exist, throw an exception
     *
     * @param string $name
     * @throws Ex\CannotPerformOperationException
     */
    protected static function ensureConstantExists($name)
    {
        if (!\defined($name)) {
            throw new Ex\CannotPerformOperationException();
        }
    }

    /**
     * If the functon doesn't exist, throw an exception
     *
     * @param string $name Function name
     * @throws Ex\CannotPerformOperationException
     */
    protected static function ensureFunctionExists($name)
    {
        if (!\function_exists($name)) {
            throw new Ex\CannotPerformOperationException();
        }
    }

    /*
     * We need these strlen() and substr() functions because when
     * 'mbstring.func_overload' is set in php.ini, the standard strlen() and
     * substr() are replaced by mb_strlen() and mb_substr().
     */

    /**
     * Safe string length
     *
     * @staticvar boolean $exists
     * @param string $str
     * @return int
     */
    protected static function ourStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === false) {
                throw new Ex\CannotPerformOperationException();
            }
            return $length;
        } else {
            return \strlen($str);
        }
    }

    /**
     * Safe substring
     *
     * @staticvar boolean $exists
     * @param string $str
     * @param int $start
     * @param int $length
     * @return string
     */
    protected static function ourSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_substr');
        }
        if ($exists)
        {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = self::ourStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }

            return \mb_substr($str, $start, $length, '8bit');
        }

        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if (isset($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }

    /**
     * Take a 4-byte header and get meaningful version information out of it.
     * Common configuration options should go in Core.php
     *
     * DO NOT CHANGE THESE VALUES!
     *
     * We spent *weeks* testing this code, making sure it is as perfect and
     * correct as possible. Are you going to do the same after making your
     * changes? Probably not. Besides, any change to these constants will break
     * the runtime tests, which are extremely important for your security.
     * You're literally millions of times more likely to screw up your own
     * security by changing something here than you are to fall victim to an
     * 128-bit key brute-force attack. You're also breaking your own
     * compatibility with future updates to this library, so you'll be left
     * vulnerable if we ever find a security bug and release a fix.
     *
     * So, PLEASE, do not change these constants.
     *
     * @param int $major
     * @param int $minor
     * @param ref $valid
     * @return type
     */
    protected static function getCoreVersionConfig($major, $minor, &$valid)
    {
        if ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'BLOCK_SIZE' => 16,
                        'KEY_BYTE_SIZE' => 16,
                        'SALT_SIZE' => 16,
                        'HASH_FUNCTION' => 'sha256',
                        'MAC_BYTE_SIZE' => 32,
                        'ENCRYPTION_INFO' => 'DefusePHP|KeyForEncryption',
                        'AUTHENTICATION_INFO' => 'DefusePHP|KeyForAuthentication'
                    ];
                default:
                    $valid |= 0xFF;
                    break;
            }
        } elseif ($major === 1) {
            $valid |= 0xFF; // Set to a nonzero value to mark it as invalid
            return [
                'BLOCK_SIZE' => 16,
                'KEY_BYTE_SIZE' => 16,
                'SALT_SIZE' => null,
                'HASH_FUNCTION' => 'sha256',
                'MAC_BYTE_SIZE' => 32,
                'ENCRYPTION_INFO' => 'DefusePHP|KeyForEncryption',
                'AUTHENTICATION_INFO' => 'DefusePHP|KeyForAuthentication'
            ];
        }
        $valid |= 0xFF; // Set to a nonzero value to mark it as invalid
    }
}
