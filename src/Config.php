<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Core;

class Config
{
    private $cipher_method;
    private $block_byte_size;
    private $key_byte_size;
    private $salt_byte_size;
    private $mac_byte_size;
    private $hash_function_name;
    private $encryption_info_string;
    private $authentication_info_string;

    public function __construct($config_array)
    {
        $expected_keys = array(
            "cipher_method",
            "block_byte_size",
            "key_byte_size",
            "salt_byte_size",
            "mac_byte_size",
            "hash_function_name",
            "encryption_info_string",
            "authentication_info_string"
        );
        if (sort($expected_keys) !== true) {
            throw Ex\CannotPerformOperationException(
                "sort() failed."
            );
        }

        $actual_keys = array_keys($config_array);
        if (sort($actual_keys) !== true) {
            throw Ex\CannotPerformOperationException(
                "sort() failed."
            );
        }

        if ($expected_keys !== $actual_keys) {
            throw new Ex\CannotPerformOperationException(
                "Trying to instantiate a bad configuration."
            );
        }

        $this->cipher_method = $config_array["cipher_method"];
        $this->block_byte_size = $config_array["block_byte_size"];
        $this->key_byte_size = $config_array["key_byte_size"];
        $this->salt_byte_size = $config_array["salt_byte_size"];
        $this->mac_byte_size = $config_array["mac_byte_size"];
        $this->hash_function_name = $config_array["hash_function_name"];
        $this->encryption_info_string = $config_array["encryption_info_string"];
        $this->authentication_info_string = $config_array["authentication_info_string"];

        Core::ensureFunctionExists('openssl_get_cipher_methods');
        if (\in_array($this->cipher_method, \openssl_get_cipher_methods()) === false) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid OpenSSL cipher method."
            );
        }

        if (!\is_int($this->block_byte_size) || $this->block_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid block byte size."
            );
        }

        if (!\is_int($this->key_byte_size) || $this->key_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid key byte size."
            );
        }

        if ($this->salt_byte_size !== false) {
            if (!is_int($this->salt_byte_size) || $this->salt_byte_size <= 0) {
                throw new Ex\CannotPerformOperationException(
                    "Configuration contains an invalid salt byte size."
                );
            }
        }

        if (!\is_int($this->mac_byte_size) || $this->mac_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid MAC byte size."
            );
        }

        if (\in_array($this->hash_function_name, \hash_algos()) === false) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid hash function name."
            );
        }

        if (!\is_string($this->encryption_info_string) || $this->encryption_info_string === "") {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid encryption info string."
            );
        }

        if (!\is_string($this->authentication_info_string) || $this->authentication_info_string === "") {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid authentication info string."
            );
        }
    }

    public function cipherMethod()
    {
        return $this->cipher_method;
    }

    public function blockByteSize()
    {
        return $this->block_byte_size;
    }

    public function keyByteSize()
    {
        return $this->key_byte_size;
    }

    public function saltByteSize()
    {
        return $this->salt_byte_size;
    }

    public function macByteSize()
    {
        return $this->mac_byte_size;
    }

    public function hashFunctionName()
    {
        return $this->hash_function_name;
    }

    public function encryptionInfoString()
    {
        return $this->encryption_info_string;
    }

    public function authenticationInfoString()
    {
        return $this->authentication_info_string;
    }
}
