<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class Salt
{
    const SALT_CURRENT_VERSION = "\xDE\xF1\x00\x00";
    const SALT_BYTE_SIZE       = 32;

    private $salt = null;

    /**
     * Create new random salt.
     *
     * @throws \Defuse\Crypto\Exception\CannotPerformOperationException
     *
     * @return \Defuse\Crypto\Salt
     */
    public static function createNewRandomSalt()
    {
        return new Salt(
            Core::secureRandom(self::SALT_BYTE_SIZE)
        );
    }

    /**
     * Load salt from ascii safe string.
     *
     * @param $savedSaltString
     *
     * @throws \Defuse\Crypto\Exception\CannotPerformOperationException
     *
     * @return \Defuse\Crypto\Salt
     */
    public static function loadFromAsciiSafeString($savedSaltString)
    {
        $bytes = Core::loadBytesFromChecksummedAsciiSafeString(self::SALT_CURRENT_VERSION, $savedSaltString);
        return new Salt($bytes);
    }

    /**
     * Save to ascii safe string.
     *
     * @throws \Defuse\Crypto\Exception\CannotPerformOperationException
     *
     * @return string
     */
    public function saveToAsciiSafeString()
    {
        return Core::saveBytesToChecksummedAsciiSafeString(
            self::SALT_CURRENT_VERSION,
            $this->salt
        );
    }

    /**
     * Gets raw bytes of salt.
     *
     * @return mixed
     */
    public function getRawBytes()
    {
        return $this->salt;
    }

    /**
     * Constructs a new Salt object.
     *
     * @param $bytes
     *
     * @throws \Defuse\Crypto\Exception\CannotPerformOperationException
     */
    private function __construct($bytes)
    {
        if (Core::ourStrlen($bytes) !== self::SALT_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException(
                'Bad salt length.'
            );
        }
        $this->salt = $bytes;
    }
}
