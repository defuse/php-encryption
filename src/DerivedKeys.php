<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class DerivedKeys
{
    private $akey = null;
    private $ekey = null;

    public function getAuthenticationKey()
    {
        return $this->akey;
    }

    public function getEncryptionKey()
    {
        return $this->ekey;
    }

    public function __construct($akey, $ekey)
    {
        $this->akey = $akey;
        $this->ekey = $ekey;
    }
}
