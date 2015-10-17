<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Config;

class FileConfig extends Config
{
    private $buffer_byte_size;

    public function __construct($config_array)
    {
        if (!array_key_exists("buffer_byte_size", $config_array)) {
            throw new Ex\CannotPerformOperationException(
                "Trying to instantiate a bad file configuration."
            );
        }

        $this->buffer_byte_size = $config_array["buffer_byte_size"];
        if (!is_int($this->buffer_byte_size) || $this->buffer_byte_size <= 0) {
            throw new Ex\CannotPerformOperationException(
                "Configuration contains an invalid buffer byte size."
            );
        }

        unset($config_array["buffer_byte_size"]);
        parent::__construct($config_array);
    }

    public function bufferByteSize()
    {
        return $this->buffer_byte_size;
    }
}
