<?php

namespace Defuse\Crypto;

final class KeyProtectedByPassword
{
    const PASSWORD_KEY_CURRENT_VERSION = "\xDE\xF1\x00\x00";

    private $encrypted_key = null;

    /**
     * Creates a random key protected by the provided password.
     *
     * @param string $password
     *
     * @throws Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return KeyProtectedByPassword
     */
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

    /**
     * Loads a KeyProtectedByPassword from its encoded form.
     *
     * @param string $saved_key_string
     *
     * @throws Defuse\Crypto\Exception\BadFormatException
     *
     * @return KeyProtectedByPassword
     */
    public static function loadFromAsciiSafeString($saved_key_string)
    {
        $encrypted_key = Encoding::loadBytesFromChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $saved_key_string
        );
        return new KeyProtectedByPassword($encrypted_key);
    }

    /**
     * Encodes the KeyProtectedByPassword into a string of printable ASCII
     * characters.
     *
     * @throws Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return string
     */
    public function saveToAsciiSafeString()
    {
        return Encoding::saveBytesToChecksummedAsciiSafeString(
            self::PASSWORD_KEY_CURRENT_VERSION,
            $this->encrypted_key
        );
    }

    /**
     * Decrypts the protected key, returning an unprotected Key object that can
     * be used for encryption and decryption.
     *
     * @throws Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws Defuse\Crypto\Exception\BadFormatException
     * @throws Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     *
     * @return Key
     */
    public function unlockKey($password)
    {
        $inner_key_encoded = Crypto::decryptWithPassword(
            $this->encrypted_key,
            $password,
            true
        );
        return Key::loadFromAsciiSafeString($inner_key_encoded);
    }

    /**
     * Constructor for KeyProtectedByPassword.
     *
     * @param string $encrypted_key
     */
    private function __construct($encrypted_key)
    {
        $this->encrypted_key = $encrypted_key;
    }
}
