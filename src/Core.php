<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Crypto;

final class Core
{
    const HEADER_VERSION_SIZE = 4;  /* This must never change. */

    const HEADER_MAGIC =            "\xDE\xF5";
    const CURRENT_VERSION =         "\xDE\xF5\x02\x00";
    const LEGACY_VERSION =          "\xDE\xF5\x01\x00";

    const HEADER_MAGIC_FILE =       "\xDE\xF4";
    const CURRENT_FILE_VERSION =    "\xDE\xF4\x02\x00";

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
            $ivsize = \openssl_cipher_iv_length($config->cipherMethod());
            if ($ivsize === false) {
                throw new Ex\CannotPerformOperationException(
                    "Problem obtaining the correct nonce length."
                );
            }
        }

        if (self::ourStrlen($ctr) !== $ivsize) {
            throw new Ex\CannotPerformOperationException(
                "Trying to increment a nonce of the wrong size."
            );
        }

        if (!is_int($inc)) {
            throw new Ex\CannotPerformOperationException(
                "Trying to increment nonce by a non-integer."
            );
        }

        if ($inc < 0) {
            throw new Ex\CannotPerformOperationException(
                "Trying to increment nonce by a negative amount."
            );
        }

        /**
         * We start at the rightmost byte (big-endian)
         * So, too, does OpenSSL: http://stackoverflow.com/a/3146214/2224584
         */
        for ($i = $ivsize - 1; $i >= 0; --$i) {
            $sum = \ord($ctr[$i]) + $inc;

            /* Detect integer overflow and fail. */
            if (!is_int($sum)) {
                throw new Ex\CannotPerformOperationException(
                    "Integer overflow in CTR mode nonce increment."
                );
            }

            $ctr[$i] = \chr($sum & 0xFF);
            $inc = $sum >> 8;
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
    public static function secureRandom($octets)
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
    public static function HKDF($hash, $ikm, $length, $info = '', $salt = null, $config = null)
    {
        // Find the correct digest length as quickly as we can.
        $digest_length = $config->macByteSize();
        if ($hash != $config->hashFunctionName()) {
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
     * @throws Ex\CannotPerformOperationException
     */
    public static function hashEquals($expected, $given)
    {
        static $native = null;
        if ($native === null) {
            $native = \function_exists('hash_equals');
        }
        if ($native) {
            return \hash_equals($expected, $given);
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

        $blind = self::secureRandom(32);
        $message_compare = hash_hmac('sha256', $given, $blind);
        $correct_compare = hash_hmac('sha256', $expected, $blind);
        return $correct_compare === $message_compare;
    }
    /**
     * If the constant doesn't exist, throw an exception
     *
     * @param string $name
     * @throws Ex\CannotPerformOperationException
     */
    public static function ensureConstantExists($name)
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
    public static function ensureFunctionExists($name)
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
    public static function ourStrlen($str)
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
    public static function ourSubstr($str, $start, $length = null)
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

}
