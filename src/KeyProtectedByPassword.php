<?php

namespace Defuse\Crypto;

final class KeyProtectedByPassword
{
    const PASSWORD_KEY_CURRENT_VERSION = "\xDE\xF1\x00\x00";
    const PBKDF2_ITERATIONS            = 100000; // TODO: remove me
    const SALT_BYTE_SIZE               = 32;

    private $salt          = null;
    private $encrypted_key = null;

    // TODO: reuse the "single use" password encryption to implement this class,
    // after it's done (then we don't need a salt!)

    public static function createRandomPasswordProtectedKey($password)
    {
        /* Create a new random key. */
        $inner_key = Key::CreateNewRandomKey();

        /* Encrypt that key with the password and a random salt. */
        $salt      = Core::secureRandom(self::SALT_BYTE_SIZE);
        $outer_key = Key::LoadFromRawBytesForTestingPurposesOnlyInsecure(
            Core::pbkdf2('sha256', $password, $salt, self::PBKDF2_ITERATIONS, Key::KEY_BYTE_SIZE, true)
        );
        $encrypted_key = Crypto::encrypt(
            $inner_key->saveToAsciiSafeString(),
            $outer_key,
            true
        );

        return new KeyProtectedByPassword($salt, $encrypted_key);
    }

    public static function loadFromAsciiSafeString($savedKeyString)
    {
        $salt_and_encrypted_key = Core::loadBytesFromChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $savedKeyString
        );
        $salt          = Core::ourSubstr($salt_and_encrypted_key, 0, self::SALT_BYTE_SIZE);
        $encrypted_key = Core::ourSubstr($salt_and_encrypted_key, self::SALT_BYTE_SIZE);
        return new KeyProtectedByPassword($salt, $encrypted_key);
    }

    public function saveToAsciiSafeString()
    {
        return Core::saveBytesToChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $this->salt . $this->encrypted_key
        );
    }

    public function unlockKey($password)
    {
        $outer_key = Key::LoadFromRawBytesForTestingPurposesOnlyInsecure(
            Core::pbkdf2('sha256', $password, $this->salt, self::PBKDF2_ITERATIONS, Key::KEY_BYTE_SIZE, true)
        );
        $inner_key_encoded = Crypto::decrypt(
            $this->encrypted_key,
            $outer_key,
            true
        );
        return Key::LoadFromAsciiSafeString($inner_key_encoded);
    }

    private function __construct($salt, $encrypted_key)
    {
        $this->salt          = $salt;
        $this->encrypted_key = $encrypted_key;
    }
}
