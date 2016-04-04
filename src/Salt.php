<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Core;
use \Defuse\Crypto\Encoding;

final class Salt
{
    const SALT_BYTE_SIZE = 32;

    private $salt = null;

    public static function CreateNewRandomSalt()
    {
        return new Salt(
            Core::secureRandom(self::SALT_BYTE_SIZE)
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

        return new Salt($bytes);
    }

    public function saveToAsciiSafeString()
    {
        return Encoding::binToHex($this->salt);
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
