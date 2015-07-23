<?php
namespace Defuse\Crypto;

interface CryptoInterface
{
    public function createNewRandomKey();
    public function encrypt($plaintext, $key);
    public function decrypt($ciphertext, $key);
}
