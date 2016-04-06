<?php

namespace Defuse\Crypto;

final class KeyProtectedByPassword
{
    const PASSWORD_KEY_CURRENT_VERSION = "\xDE\xF1\x00\x00";

    private $encrypted_key = null;

    public static function createRandomPasswordProtectedKey($password)
    {
        /* Create a new random key. */
        $inner_key = Key::createNewRandomKey();
        $encrypted_key = Crypto::encryptWithPassword(
            $inner_key->saveToAsciiSafeString(),
            $password,
            true
        );

        return new KeyProtectedByPassword($encrypted_key);
    }

    public static function loadFromAsciiSafeString($savedKeyString)
    {
        $encrypted_key = Core::loadBytesFromChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $savedKeyString
        );
        return new KeyProtectedByPassword($encrypted_key);
    }

    public function saveToAsciiSafeString()
    {
        return Core::saveBytesToChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $this->encrypted_key
        );
    }

    public function unlockKey($password)
    {
        $inner_key_encoded = Crypto::decryptWithPassword(
            $this->encrypted_key,
            $password,
            true
        );
        return Key::LoadFromAsciiSafeString($inner_key_encoded);
    }

    private function __construct($encrypted_key)
    {
        $this->encrypted_key = $encrypted_key;
    }
}
