<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Core;
use \Defuse\Crypto\Encoding;

final class Key
{
    /* We keep the key versioning independent of the ciphertext versioning. */
    const KEY_HEADER_SIZE = 4;
    const KEY_MAGIC = "\xDE\xF0";
    const KEY_CURRENT_VERSION = "\xDE\xF0\x00\x00";

    const KEY_BYTE_SIZE = 32;
    const CHECKSUM_BYTE_SIZE = 32;
    const CHECKSUM_HASH_ALGO = 'sha256';
    const PBKDF2_ITERATIONS = 100000;

    /*
     * Format:
     * bin2hex([__HEADER__][____KEY BYTES___][___CHECKSUM___])
     * 
     * HEADER:      The 4-byte version header.
     * KEY BYTES:   The raw key bytes (length may depend on version).
     * CHECKSUM:    SHA256(HEADER . KEY BYTES).
     *
     * The checksum field is for detecting accidental corruption *only*. It
     * provides no cryptographic functionality.
     *
     * SECURITY NOTE: 
     *
     *      The checksum introduces a potential security weakness.
     *
     *      Suppose an adversary has an exploit against the process containing
     *      the key that allows them to overwrite an arbitrary byte of memory.
     *      The adversary has exhausted all options, and can't get remote code
     *      execution.
     *
     *      If they can overwrite a byte of the key, then force the checksum 
     *      validation to run, then determine (possibly through a side channel)
     *      whether or not the checksum was correct, they learn whether their
     *      guess for that byte was correct or not. They can recover the key
     *      using at most 256 queries per byte.
     *
     *      This attack also applies to authenticated encryption as a whole, in
     *      the situation where the adversary can overwrite a byte of the key
     *      and then cause a valid ciphertext to be decrypted, and then
     *      determine whether the MAC check passed or failed. This is much more
     *      plausible than attacking encoded keys.
     *
     *      By using the full SHA256 hash instead of truncating it, I'm ensuring
     *      that both ways of going about the attack are equivalently difficult
     *      (a shorter checksum might be more useful if the arbitrary write
     *      is more coarse-grained than a single byte).
     */

    private $key_bytes = null;

    public static function CreateNewRandomKey()
    {
        return new Key(Core::secureRandom(self::KEY_BYTE_SIZE));
    }

    public static function CreateKeyBasedOnPassword($password, $salt) 
    {
        if (!\is_a($salt, "\Defuse\Crypto\Salt")) {
            throw new Ex\CannotPerformOperationException(
                "You must provide an instance of the Salt class (not a string)."
            );
        }
        return new Key(
            Core::pbkdf2('sha256', $password, $salt->getRawBytes(), self::PBKDF2_ITERATIONS, self::KEY_BYTE_SIZE, true)
        );
    }

    public static function LoadFromAsciiSafeString($savedKeyString)
    {
        try {
            $bytes = Encoding::hexToBin($savedKeyString);
        } catch (\RangeException $ex) {
            throw new Ex\CannotPerformOperationException(
                "Key has invalid hex encoding."
            );
        }

        /* Make sure we have enough bytes to get the version header. */
        if (Core::ourStrlen($bytes) < self::KEY_HEADER_SIZE) {
            throw new Ex\CannotPerformOperationException(
                "Saved Key is shorter than the version header."
            );
        }

        /* Grab the version header. */
        $version_header = Core::ourSubstr($bytes, 0, self::KEY_HEADER_SIZE);

        if ($version_header !== self::KEY_CURRENT_VERSION) {
            throw new Ex\CannotPerformOperationException(
                "Invalid key version header."
            );
        }

        /* Now that we know the version, check the length is correct. */
        if (Core::ourStrlen($bytes) !== self::KEY_HEADER_SIZE +
                                        self::KEY_BYTE_SIZE +
                                        self::CHECKSUM_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException(
                "Saved Key is not the correct size."
            );
        }

        /* Grab the bytes that are part of the checksum. */
        $checked_bytes = Core::ourSubstr(
            $bytes,
            0,
            self::KEY_HEADER_SIZE + self::KEY_BYTE_SIZE
        );

        /* Grab the included checksum. */
        $checksum_a = Core::ourSubstr(
            $bytes,
            self::KEY_HEADER_SIZE + self::KEY_BYTE_SIZE,
            self::CHECKSUM_BYTE_SIZE
        );

        /* Re-compute the checksum. */
        $checksum_b = \hash(self::CHECKSUM_HASH_ALGO, $checked_bytes, true);

        /* Validate it. It *is* important for this to be constant time. */
        if (!Core::hashEquals($checksum_a, $checksum_b)) {
            throw new Ex\CannotPerformOperationException(
                "Saved key is corrupted -- checksums don't match."
            );
        }

        /* Everything checks out. Grab the key and create a Key object. */
        $key_bytes = Core::ourSubstr($bytes, self::KEY_HEADER_SIZE, self::KEY_BYTE_SIZE);
        return new Key($key_bytes);
    }

    public function saveToAsciiSafeString()
    {
        return Encoding::binToHex(
            self::KEY_CURRENT_VERSION .
            $this->key_bytes .
            \hash(
                self::CHECKSUM_HASH_ALGO,
                self::KEY_CURRENT_VERSION . $this->key_bytes,
                true
            )
        );
    }

    public function getRawBytes()
    {
        return $this->key_bytes;
    }

    private function __construct($bytes)
    {
        if (Core::ourStrlen($bytes) !== self::KEY_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException(
                "Bad key length."
            );
        }
        $this->key_bytes = $bytes;
    }

    /*
     * NEVER use this, exept for testing.
     */
    public static function LoadFromRawBytesForTestingPurposesOnlyInsecure($bytes)
    {
        return new Key($bytes);
    }

}
