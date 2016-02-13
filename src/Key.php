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

    const MIN_SAFE_KEY_BYTE_SIZE = 16;

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

    private $key_version_header = null;
    private $key_bytes = null;
    private $config = null;

    public static function CreateNewRandomKey()
    {
        $config = self::GetKeyVersionConfigFromKeyHeader(self::KEY_CURRENT_VERSION);
        $bytes = Core::secureRandom($config->keyByteSize());
        return new Key(self::KEY_CURRENT_VERSION, $bytes);
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

        /* Grab the config for that version. */
        $config = self::GetKeyVersionConfigFromKeyHeader($version_header);

        /* Now that we know the version, check the length is correct. */
        if (Core::ourStrlen($bytes) !== self::KEY_HEADER_SIZE +
                                        $config->keyByteSize() +
                                        $config->checksumByteSize()) {
            throw new Ex\CannotPerformOperationException(
                "Saved Key is not the correct size."
            );
        }

        /* Grab the bytes that are part of the checksum. */
        $checked_bytes = Core::ourSubstr(
            $bytes,
            0,
            self::KEY_HEADER_SIZE + $config->keyByteSize()
        );

        /* Grab the included checksum. */
        $checksum_a = Core::ourSubstr(
            $bytes,
            self::KEY_HEADER_SIZE + $config->keyByteSize(),
            $config->checksumByteSize()
        );

        /* Re-compute the checksum. */
        $checksum_b = hash($config->checksumHashFunction(), $checked_bytes, true);

        /* Validate it. It *is* important for this to be constant time. */
        if (!Core::hashEquals($checksum_a, $checksum_b)) {
            throw new Ex\CannotPerformOperationException(
                "Saved key is corrupted -- checksums don't match."
            );
        }

        /* Everything checks out. Grab the key and create a Key object. */
        $key_bytes = Core::ourSubstr($bytes, self::KEY_HEADER_SIZE, $config->keyByteSize());
        return new Key($version_header, $key_bytes);
    }

    private function __construct($version_header, $bytes)
    {
        $this->key_version_header = $version_header;
        $this->key_bytes = $bytes;
        $this->config = self::GetKeyVersionConfigFromKeyHeader($this->key_version_header);
    }

    public function saveToAsciiSafeString()
    {
        return Encoding::binToHex(
            $this->key_version_header .
            $this->key_bytes .
            hash(
                $this->config->checksumHashFunction(),
                $this->key_version_header . $this->key_bytes,
                true
            )
        );
    }

    public function isSafeForCipherTextVersion($major, $minor)
    {
        /* Legacy decryption uses raw key byte strings, not Key. */
        return $major == 2 && $minor == 0;
    }

    public function getRawBytes()
    {
        if (is_null($this->key_bytes) || Core::ourStrlen($this->key_bytes) < self::MIN_SAFE_KEY_BYTE_SIZE) {
            throw new CannotPerformOperationException(
                "An attempt was made to use an uninitialzied or too-short key"
            );
        }
        return $this->key_bytes;
    }

    private static function GetKeyVersionConfigFromKeyHeader($key_header) {
        if ($key_header === self::KEY_CURRENT_VERSION) {
            return new KeyConfig([
                'key_byte_size' => 32,
                'checksum_hash_function' => 'sha256',
                'checksum_byte_size' => 32
            ]);
        }
        throw new Ex\CannotPerformOperationException(
            "Invalid key version header."
        );
    }

    /*
     * NEVER use this, exept for testing.
     */
    public static function LoadFromRawBytesForTestingPurposesOnlyInsecure($bytes)
    {
        return new Key(self::KEY_CURRENT_VERSION, $bytes);
    }

}
