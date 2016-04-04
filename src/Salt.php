<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Core;
use \Defuse\Crypto\Encoding;

final class Salt
{
    const SALT_CURRENT_VERSION = "\xDE\xF1\x00\x00";
    const SALT_BYTE_SIZE = 32;

    private $salt = null;

    public static function CreateNewRandomSalt()
    {
        return new Salt(
            Core::secureRandom(self::SALT_BYTE_SIZE)
        );
    }

    public static function LoadFromAsciiSafeString($savedSaltString)
    {
        $bytes = Core::loadBytesFromChecksummedAsciiSafeString(self::SALT_CURRENT_VERSION, $savedSaltString);
        return new Salt($bytes);
    }

    public function saveToAsciiSafeString()
    {
        return Core::saveBytesToChecksummedAsciiSafeString(
            self::SALT_CURRENT_VERSION,
            $this->salt
        );
    }

    public function getRawBytes()
    {
        return $this->salt;
    }

    private function __construct($bytes)
    {
        if (Core::ourStrlen($bytes) !== self::SALT_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException(
                "Bad salt length."
            );
        }
        $this->salt = $bytes;
    }

}
