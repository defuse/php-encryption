<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class Key
{
    const KEY_CURRENT_VERSION = "\xDE\xF0\x00\x00";
    const KEY_BYTE_SIZE       = 32;

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

    /**
     * Create new random key.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return \Defuse\Crypto\Key
     */
    public static function createNewRandomKey()
    {
        return new Key(Core::secureRandom(self::KEY_BYTE_SIZE));
    }

    /**
     * Load a key from ascii safe string.
     *
     * @param $savedKeyString
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return \Defuse\Crypto\Key
     */
    public static function loadFromAsciiSafeString($savedKeyString)
    {
        $key_bytes = Encoding::loadBytesFromChecksummedAsciiSafeString(self::KEY_CURRENT_VERSION, $savedKeyString);
        return new Key($key_bytes);
    }

    /**
     * Save to ascii safe string.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return string
     */
    public function saveToAsciiSafeString()
    {
        return Encoding::saveBytesToChecksummedAsciiSafeString(
            self::KEY_CURRENT_VERSION,
            $this->key_bytes
        );
    }

    /**
     * Gets raw bytes
     *
     * @return mixed
     */
    public function getRawBytes()
    {
        return $this->key_bytes;
    }

    /**
     * Constructs a new Key object.
     *
     *
     * @param $bytes
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    private function __construct($bytes)
    {
        if (Core::ourStrlen($bytes) !== self::KEY_BYTE_SIZE) {
            throw new Ex\EnvironmentIsBrokenException(
                'Bad key length.'
            );
        }
        $this->key_bytes = $bytes;
    }

    /**
     * NEVER use this, except for testing.
     *
     * @param $bytes
     *
     * @return \Defuse\Crypto\Key
     *
     * @internal
     */
    public static function loadFromRawBytesForTestingPurposesOnlyInsecure($bytes)
    {
        return new Key($bytes);
    }
}
