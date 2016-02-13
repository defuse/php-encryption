<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

final class KeyConfig
{
    private $key_byte_size;
    private $checksum_hash_function;
    private $checksum_byte_size;
    private $password_prehash_function;
    private $password_salt_bytes;
    private $pbkdf2_hash_function;
    private $pbkdf2_iterations;

    public function __construct($config_array)
    {
        $expected_keys = array(
            "key_byte_size",
            "checksum_hash_function",
            "password_prehash_function",
            "password_salt_bytes",
            "pbkdf2_hash_function",
            "pbkdf2_iterations",
            "checksum_byte_size"
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
                "Trying to instantiate a bad key configuration."
            );
        }

        $this->key_byte_size = $config_array["key_byte_size"];
        $this->checksum_hash_function = $config_array["checksum_hash_function"];
        $this->password_prehash_function = $config_array["password_prehash_function"];
        $this->password_salt_bytes = $config_array["password_salt_bytes"];
        $this->pbkdf2_hash_function = $config_array["pbkdf2_hash_function"];
        $this->pbkdf2_iterations = $config_array["pbkdf2_iterations"];
        $this->checksum_byte_size = $config_array["checksum_byte_size"];

        if (!\is_int($this->key_byte_size) || $this->key_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Invalid key byte size."
            );
        }

        if (\in_array($this->checksum_hash_function, \hash_algos()) === false) {
            throw new Ex\CannotPerformOperationException(
                "Invalid hash function name."
            );
        }

        if ($this->password_prehash_function !== null || $this->password_salt_bytes !== null) {
            if (\in_array($this->password_prehash_function, \hash_algos()) === false) {
                throw new Ex\CannotPerformOperationException(
                    "Invalid hash function name."
                );
            }
            if (\in_array($this->pbkdf2_hash_function, \hash_algos()) === false) {
                throw new Ex\CannotPerformOperationException(
                    "Invalid hash function name."
                );
            }
            if (!\is_int($this->password_salt_bytes) || $this->password_salt_bytes <= 0) {
                throw new Ex\CannotPerformOperationException(
                    "Invalid checksum byte size."
                );
            }
            if (!\is_int($this->pbkdf2_iterations) || $this->pbkdf2_iterations <= 0) {
                throw new Ex\CannotPerformOperationException(
                    "Invalid checksum byte size."
                );
            }
        }

        if (!\is_int($this->checksum_byte_size) || $this->checksum_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Invalid checksum byte size."
            );
        }
    }

    public function keyByteSize()
    {
        return $this->key_byte_size;
    }

    public function checksumHashFunction()
    {
        return $this->checksum_hash_function;
    }

    public function checksumByteSize()
    {
        return $this->checksum_byte_size;
    }

    public function passwordPrehashAlgo()
    {
        return $this->password_prehash_function;
    }

    public function passwordSaltBytes()
    {
        return $this->password_salt_bytes;
    }

    public function pbkdf2Algo()
    {
        return $this->pbkdf2_hash_function;
    }

    public function pbkdf2Iterations()
    {
        return $this->pbkdf2_iterations;
    }
}