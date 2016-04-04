<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Encoding;

final class Core
{
    const HEADER_VERSION_SIZE = 4;  /* This must never change. */
    const MINIMUM_FILE_SIZE = 84;   /* Absolute minimum */

    const HEADER_MAGIC =            "\xDE\xF5";
    const CURRENT_VERSION =         "\xDE\xF5\x02\x00";

    const CIPHER_METHOD = 'aes-256-ctr';
    const BLOCK_BYTE_SIZE = 16;
    const KEY_BYTE_SIZE = 32;
    const SALT_BYTE_SIZE = 32;
    const MAC_BYTE_SIZE = 32;
    const HASH_FUNCTION_NAME = 'sha256';
    const ENCRYPTION_INFO_STRING = 'DefusePHP|V2|KeyForEncryption';
    const AUTHENTICATION_INFO_STRING = 'DefusePHP|V2|KeyForAuthentication';
    const BUFFER_BYTE_SIZE = 1048576;

    const LEGACY_CIPHER_METHOD = 'aes-128-cbc';
    const LEGACY_BLOCK_BYTE_SIZE = 16;
    const LEGACY_KEY_BYTE_SIZE = 16;
    const LEGACY_HASH_FUNCTION_NAME = 'sha256';
    const LEGACY_MAC_BYTE_SIZE = 32;
    const LEGACY_ENCRYPTION_INFO_STRING = 'DefusePHP|KeyForEncryption';
    const LEGACY_AUTHENTICATION_INFO_STRING = 'DefusePHP|KeyForAuthentication';

    const CHECKSUM_BYTE_SIZE = 32;
    const CHECKSUM_HASH_ALGO = 'sha256';
    const SERIALIZE_HEADER_BYTES = 4;

    /**
     * Increment a counter (prevent nonce reuse)
     *
     * @param string $ctr - raw binary
     * @param int $inc - how much?
     *
     * @return string (raw binary)
     */
    public static function incrementCounter($ctr, $inc, $cipherMethod)
    {
        static $ivsize = null;
        if ($ivsize === null) {
            $ivsize = Core::cipherIvLength($cipherMethod);
        }

        if (Core::ourStrlen($ctr) !== $ivsize) {
            throw new Ex\CannotPerformOperationException(
                "Trying to increment a nonce of the wrong size."
            );
        }

        if (!\is_int($inc)) {
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
            if (!\is_int($sum)) {
                throw new Ex\CannotPerformOperationException(
                    "Integer overflow in CTR mode nonce increment."
                );
            }

            $ctr[$i] = \pack('C', $sum & 0xFF);
            $inc = $sum >> 8;
        }
        return $ctr;
    }

    /**
     * Returns the cipher initialization vector (iv) length.
     *
     * @param string $method
     * @return int
     * @throws Ex\CannotPerformOperationException
     */
    public static function cipherIvLength($method)
    {
        Core::ensureFunctionExists('openssl_cipher_iv_length');
        $ivsize = \openssl_cipher_iv_length($method);

        if ($ivsize === false || $ivsize <= 0) {
            throw new Ex\CannotPerformOperationException(
                'Could not get the IV length from OpenSSL'
            );
        }

        return $ivsize;
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
        Core::ensureFunctionExists('openssl_random_pseudo_bytes');
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
    public static function HKDF($hash, $ikm, $length, $info = '', $salt = null)
    {
        $digest_length = Core::ourStrlen(\hash_hmac($hash, '', '', true));

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
        if (Core::ourStrlen($prk) < $digest_length) {
            throw new Ex\CannotPerformOperationException();
        }

        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; Core::ourStrlen($t) < $length; ++$block_index) {
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
        $orm = Core::ourSubstr($t, 0, $length);
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
        if (Core::ourStrlen($expected) !== Core::ourStrlen($given)) {
            throw new Ex\CannotPerformOperationException();
        }

        $blind = Core::secureRandom(32);
        $message_compare = \hash_hmac('sha256', $given, $blind);
        $correct_compare = \hash_hmac('sha256', $expected, $blind);
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
                    $length = Core::ourStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }

            // This is required to make mb_substr behavior identical to substr.
            // Without this, mb_substr() would return false, contra to what the
            // PHP documentation says (it doesn't say it can return false.)
            if ($start === Core::ourStrlen($str) && $length === 0) {
                return '';
            }

            if ($start > Core::ourStrlen($str)) {
                return false;
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

    /*
     * Copied from https://github.com/defuse/password-hashing
     *
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    public static function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        // Type checks:
        if (!\is_string($algorithm)) {
            throw new InvalidArgumentException(
                "pbkdf2(): algorithm must be a string"
            );
        }
        if (!\is_string($password)) {
            throw new InvalidArgumentException(
                "pbkdf2(): password must be a string"
            );
        }
        if (!\is_string($salt)) {
            throw new InvalidArgumentException(
                "pbkdf2(): salt must be a string"
            );
        }
        // Coerce strings to integers with no information loss or overflow
        $count += 0;
        $key_length += 0;

        $algorithm = \strtolower($algorithm);
        if (!\in_array($algorithm, \hash_algos(), true)) {
            throw new CannotPerformOperationException(
                "Invalid or unsupported hash algorithm."
            );
        }

        // Whitelist, or we could end up with people using CRC32.
        $ok_algorithms = array(
            "sha1", "sha224", "sha256", "sha384", "sha512",
            "ripemd160", "ripemd256", "ripemd320", "whirlpool"
        );
        if (!\in_array($algorithm, $ok_algorithms, true)) {
            throw new CannotPerformOperationException(
                "Algorithm is not a secure cryptographic hash function."
            );
        }

        if ($count <= 0 || $key_length <= 0) {
            throw new CannotPerformOperationException(
                "Invalid PBKDF2 parameters."
            );
        }

        if (\function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return \hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }

        $hash_length = Core::ourStrlen(\hash($algorithm, "", true));
        $block_count = \ceil($key_length / $hash_length);

        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . \pack("N", $i);
            // first iteration
            $last = $xorsum = \hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = \hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if($raw_output) {
            return Core::ourSubstr($output, 0, $key_length);
        } else {
            return \bin2hex(Core::ourSubstr($output, 0, $key_length));
        }
    }

    public static function saveBytesToChecksummedAsciiSafeString($header, $bytes)
    {
        // Headers must be a constant length to prevent one type's header from
        // being a prefix of another type's header, leading to ambiguity.
        if (Core::ourStrlen($header) !== Core::SERIALIZE_HEADER_BYTES) {
            throw new Ex\CannotPerformOperationException(
                "Header must be 4 bytes."
            );
        }

        return Encoding::binToHex(
            $header .
            $bytes .
            \hash(
                Core::CHECKSUM_HASH_ALGO,
                $header . $bytes,
                true
            )
        );
    }

    public static function loadBytesFromChecksummedAsciiSafeString($expected_header, $string)
    {
        // Headers must be a constant length to prevent one type's header from
        // being a prefix of another type's header, leading to ambiguity.
        if (Core::ourStrlen($expected_header) !== Core::SERIALIZE_HEADER_BYTES) {
            throw new Ex\CannotPerformOperationException(
                "Header must be 4 bytes."
            );
        }

        try {
            $bytes = Encoding::hexToBin($string);
        } catch (\RangeException $ex) {
            throw new Ex\CannotPerformOperationException(
                "String has invalid hex encoding."
            );
        }

        /* Make sure we have enough bytes to get the version header and checksum. */
        if (Core::ourStrlen($bytes) < Core::SERIALIZE_HEADER_BYTES + Core::CHECKSUM_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException(
                "Encoded data is shorter than expected."
            );
        }

        /* Grab the version header. */
        $actual_header = Core::ourSubstr($bytes, 0, Core::SERIALIZE_HEADER_BYTES);

        if ($actual_header !== $expected_header) {
            throw new Ex\CannotPerformOperationException(
                "Invalid header."
            );
        }

        /* Grab the bytes that are part of the checksum. */
        $checked_bytes = Core::ourSubstr(
            $bytes,
            0,
            Core::ourStrlen($bytes) - Core::CHECKSUM_BYTE_SIZE
        );

        /* Grab the included checksum. */
        $checksum_a = Core::ourSubstr(
            $bytes,
            Core::ourStrlen($bytes) - Core::CHECKSUM_BYTE_SIZE,
            Core::CHECKSUM_BYTE_SIZE
        );

        /* Re-compute the checksum. */
        $checksum_b = \hash(Core::CHECKSUM_HASH_ALGO, $checked_bytes, true);

        /* Validate it. It *is* important for this to be constant time. */
        if (!Core::hashEquals($checksum_a, $checksum_b)) {
            throw new Ex\CannotPerformOperationException(
                "Saved key is corrupted -- checksums don't match."
            );
        }

        return Core::ourSubstr(
            $bytes,
            Core::SERIALIZE_HEADER_BYTES,
            Core::ourStrlen($bytes) - Core::SERIALIZE_HEADER_BYTES - Core::CHECKSUM_BYTE_SIZE
        );
    }

}
