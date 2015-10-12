<?php
namespace Defuse\Crypto;

interface StreamInterface
{
    /**
     * Encrypt the contents at $inputFilename, storing the result in $outputFilename
     * using HKDF of $key to perform authenticated encryption
     * 
     * @param string $inputFilename
     * @param string $outputFilename
     * @param string $key
     * @return boolean
     */
    public static function encryptFile($inputFilename, $outputFilename, $key);

    /**
     * Decrypt the contents at $inputFilename, storing the result in $outputFilename
     * using HKDF of $key to decrypt then verify
     * 
     * @param string $inputFilename
     * @param string $outputFilename
     * @param string $key
     * @return boolean
     */
    public static function decryptFile($inputFilename, $outputFilename, $key);

    /**
     * Encrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to perform authenticated encryption
     * 
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param string $key
     * @return boolean
     */
    public static function encryptResource($inputHandle, $outputHandle, $key);

    /**
     * Decrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to decrypt then verify
     * 
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param string $key
     * @return boolean
     */
    public static function decryptResource($inputHandle, $outputHandle, $key);
}
