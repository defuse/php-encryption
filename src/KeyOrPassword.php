<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class KeyOrPassword
{
    const PBKDF2_ITERATIONS    = 100000;
    const SECRET_TYPE_KEY      = 1;
    const SECRET_TYPE_PASSWORD = 2;

    private $secret_type = null;
    private $secret      = null;

    public static function createFromKey(Key $key)
    {
        return new KeyOrPassword(self::SECRET_TYPE_KEY, $key);
    }

    public static function createFromPassword($password)
    {
        return new KeyOrPassword(self::SECRET_TYPE_PASSWORD, $password);
    }

    public function deriveKeys($salt)
    {
        if (Core::ourStrlen($salt) !== Core::SALT_BYTE_SIZE) {
            throw new Ex\CannotPerformOperationException("Bad salt.");
        }

        if ($this->secret_type === self::SECRET_TYPE_KEY) {
            $akey = Core::HKDF(
                Core::HASH_FUNCTION_NAME,
                $this->secret->getRawBytes(),
                Core::KEY_BYTE_SIZE,
                Core::AUTHENTICATION_INFO_STRING,
                $salt
            );
            $ekey = Core::HKDF(
                Core::HASH_FUNCTION_NAME,
                $this->secret->getRawBytes(),
                Core::KEY_BYTE_SIZE,
                Core::ENCRYPTION_INFO_STRING,
                $salt
            );
            return new DerivedKeys($akey, $ekey);
        } elseif ($this->secret_type === SECRET_TYPE_PASSWORD) {
            $prekey = Core::pbkdf2(
                'sha256',
                $this->secret,
                $salt,
                self::PBKDF2_ITERATIONS,
                Core::KEY_BYTE_SIZE,
                true
            );
            // TODO: Is reusing the same $salt between PBKDF2 and HKDF acceptable?
            $akey = Core::HKDF(
                Core::HASH_FUNCTION_NAME,
                $prekey,
                Core::KEY_BYTE_SIZE,
                Core::AUTHENTICATION_INFO_STRING,
                $salt
            );
            $ekey = Core::HKDF(
                Core::HASH_FUNCTION_NAME,
                $prekey,
                Core::KEY_BYTE_SIZE,
                Core::ENCRYPTION_INFO_STRING,
                $salt
            );
            return new DerivedKeys($akey, $ekey);
        } else {
            throw new Ex\CannotPerformOperationException("Bad secret type.");
        }
    }

    public static function deriveKeysFromPassword($password)
    {
        $salt = Core::secureRandom(Core::SALT_BYTE_SIZE);
    }

    private function __construct($secret_type, $secret)
    {
        $this->secret_type = $secret_type;
        $this->secret = $secret;
    }
}
