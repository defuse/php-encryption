<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

use \Defuse\Crypto\Core;
use \Defuse\Crypto\FileConfig;

/*
 * PHP Encryption Library
 * Copyright (c) 2014-2015, Taylor Hornby <https://defuse.ca>
 * All rights reserved.
 *
 * Streaming File Encryption Class
 * Copyright (c) 2015 Paragon Initiative Enterprises <https://paragonie.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
final class File implements StreamInterface
{
    /**
     * Use this to generate a random encryption key.
     *
     * @return string
     */
    public static function createNewRandomKey()
    {
        $config = self::getFileVersionConfigFromHeader(
            Core::CURRENT_FILE_VERSION,
            Core::CURRENT_FILE_VERSION
        );
        return Core::secureRandom($config->keyByteSize());
    }

    /**
     * Encrypt the contents at $inputFilename, storing the result in
     * $outputFilename using HKDF of $key to perform authenticated encryption
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param Key $key
     * @return boolean
     */
    public static function encryptFile($inputFilename, $outputFilename, Key $key)
    {
        if (!\is_string($inputFilename)) {
            throw new Ex\InvalidInput(
                'Input filename must be a string!'
            );
        }
        if (!\is_string($outputFilename)) {
            throw new Ex\InvalidInput(
                'Output filename must be a string!'
            );
        }

        /** Open the file handles **/

            /**
             * Input file handle
             */
            $if = \fopen($inputFilename, 'rb');
            if ($if === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot open input file for encrypting'
                );
            }
            \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = \fopen($outputFilename, 'wb');
            if ($of === false) {
                fclose($if);
                throw new Ex\CannotPerformOperationException(
                    'Cannot open output file for encrypting'
                );
            }
            \stream_set_write_buffer($of, 0);

        /**
         * Use encryptResource() to actually write the encrypted data to $of
         */
        try {
            $encrypted = self::encryptResource($if, $of, $key);
        } catch (\Ex\CryptoException $ex) {
            fclose($if);
            fclose($of);
            throw $ex;
        }

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\CannotPerformOperationException(
                'Cannot close input file for encrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\CannotPerformOperationException(
                'Cannot close input file for encrypting'
            );
        }

        /**
         *  Return the result (which should be true)
         */
        return $encrypted;
    }

    /**
     * Decrypt the contents at $inputFilename, storing the result in $outputFilename
     * using HKDF of $key to decrypt then verify
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param Key $key
     * @return boolean
     */
    public static function decryptFile($inputFilename, $outputFilename, Key $key)
    {
        if (!\is_string($inputFilename)) {
            throw new Ex\InvalidInput(
                'Input filename must be a string!'
            );
        }
        if (!\is_string($outputFilename)) {
            throw new Ex\InvalidInput(
                'Output filename must be a string!'
            );
        }

        /** Open the file handles **/

            /**
             * Input file handle
             */
            $if = \fopen($inputFilename, 'rb');
            if ($if === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot open input file for decrypting'
                );
            }
            \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = \fopen($outputFilename, 'wb');
            if ($of === false) {
                fclose($if);
                throw new Ex\CannotPerformOperationException(
                    'Cannot open output file for decrypting'
                );
            }
            \stream_set_write_buffer($of, 0);

        /**
         * Use decryptResource() to actually write the decrypted data to $of
         */
        try {
            $decrypted = self::decryptResource($if, $of, $key);
        } catch (\Ex\CryptoException $ex) {
            fclose($if);
            fclose($of);
            throw $ex;
        }

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\CannotPerformOperationException(
                'Cannot close input file for decrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\CannotPerformOperationException(
                'Cannot close input file for decrypting'
            );
        }

        /**
         * Return the result (which should be true)
         */
        return $decrypted;
    }

    /**
     * Encrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to perform authenticated encryption
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param Key $key
     * @return boolean
     */
    public static function encryptResource($inputHandle, $outputHandle, Key $key)
    {
        // Because we don't have strict typing in PHP 5
        if (!\is_resource($inputHandle)) {
            throw new Ex\InvalidInput(
                'Input handle must be a resource!'
            );
        }
        if (!\is_resource($outputHandle)) {
            throw new Ex\InvalidInput(
                'Output handle must be a resource!'
            );
        }
        $config = self::getFileVersionConfigFromHeader(
            Core::CURRENT_FILE_VERSION,
            Core::CURRENT_FILE_VERSION
        );
        $inputStat = \fstat($inputHandle);
        $inputSize = $inputStat['size'];

        // Let's add this check before anything
        if (!\in_array($config->hashFunctionName(), \hash_algos())) {
            throw new Ex\CannotPerformOperationException(
                'The specified hash function does not exist'
            );
        }

        /**
         *  Let's split our keys
         */
        $file_salt = Core::secureRandom($config->saltByteSize());

        // $ekey -- Encryption Key -- used for AES
        $ekey = Core::HKDF(
            $config->hashFunctionName(),
            $key->getRawBytes(),
            $config->keyByteSize(),
            $config->encryptionInfoString(),
            $file_salt,
            $config
        );

        // $akey -- Authentication Key -- used for HMAC
        $akey = Core::HKDF(
            $config->hashFunctionName(),
            $key->getRawBytes(),
            $config->keyByteSize(),
            $config->authenticationInfoString(),
            $file_salt,
            $config
        );

        /**
         *  Generate a random initialization vector.
         */
        Core::ensureFunctionExists("openssl_cipher_iv_length");
        $ivsize = \openssl_cipher_iv_length($config->cipherMethod());
        if ($ivsize === false || $ivsize <= 0) {
            throw new Ex\CannotPerformOperationException(
                'Improper IV size'
            );
        }
        $iv = Core::secureRandom($ivsize);

        /**
         * First let's write our header, file salt, and IV to the first N blocks of the output file
         */
        self::writeBytes(
            $outputHandle,
            Core::CURRENT_FILE_VERSION . $file_salt . $iv, 
            Core::HEADER_VERSION_SIZE + $config->saltByteSize() + $ivsize
        );

        /**
         * We're going to initialize a HMAC-SHA256 with the given $akey
         * and update it with each ciphertext chunk
         */
        $hmac = \hash_init($config->hashFunctionName(), HASH_HMAC, $akey);
        if ($hmac === false) {
            throw new Ex\CannotPerformOperationException(
                'Cannot initialize a hash context'
            );
        }

        /**
         * We operate on $thisIv using a hash-based PRF derived from the initial
         * IV for the first block
         */
        $thisIv = $iv;

        /**
         * How much do we increase the counter after each buffered encryption to
         * prevent nonce reuse?
         */
        $inc = $config->bufferByteSize() / $config->blockByteSize();

        /**
         * Let's MAC our salt and IV/nonce
         */
        \hash_update($hmac, Core::CURRENT_FILE_VERSION);
        \hash_update($hmac, $file_salt);
        \hash_update($hmac, $iv);

        /**
         * Iterate until we reach the end of the input file
         */
        $breakR = false;
        while (!\feof($inputHandle)) {
            $pos = \ftell($inputHandle);
            if ($pos + $config->bufferByteSize() >= $inputSize) {
                $breakR = true;
                // We need to break after this loop iteration
                $read = self::readBytes(
                    $inputHandle,
                    $inputSize - $pos
                );
            } else {
                $read = self::readBytes(
                    $inputHandle,
                    $config->bufferByteSize()
                );
            }
            $thisIv = Core::incrementCounter($thisIv, $inc, $config);

            /**
             * Perform the AES encryption. Encrypts the plaintext.
             */
            $encrypted = \openssl_encrypt(
                $read,
                $config->cipherMethod(),
                $ekey,
                OPENSSL_RAW_DATA,
                $thisIv
            );
            /**
             * Check that the encryption was performed successfully
             */
            if ($encrypted === false) {
                throw new Ex\CannotPerformOperationException(
                    'OpenSSL encryption error'
                );
            }

            /**
             * Write the ciphertext to the output file
             */
            self::writeBytes($outputHandle, $encrypted, Core::ourStrlen($encrypted));

            /**
             * Update the HMAC for the entire file with the data from this block
             */
            \hash_update($hmac, $encrypted);
            if ($breakR) {
                break;
            }
        }

        // Now let's get our HMAC and append it
        $finalHMAC = \hash_final($hmac, true);

        self::writeBytes($outputHandle, $finalHMAC, $config->macByteSize());
        return true;
    }

    /**
     * Decrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to decrypt then verify
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param Key $key
     * @return boolean
     */
    public static function decryptResource($inputHandle, $outputHandle, Key $key)
    {
        // Because we don't have strict typing in PHP 5
        if (!\is_resource($inputHandle)) {
            throw new Ex\InvalidInput(
                'Input handle must be a resource!'
            );
        }
        if (!\is_resource($outputHandle)) {
            throw new Ex\InvalidInput(
                'Output handle must be a resource!'
            );
        }

        // Parse the header.
        $header = self::readBytes($inputHandle, Core::HEADER_VERSION_SIZE);
        $config = self::getFileVersionConfigFromHeader(
            $header,
            Core::CURRENT_FILE_VERSION
        );

        // Let's add this check before anything
        if (!\in_array($config->hashFunctionName(), \hash_algos())) {
            throw new Ex\CannotPerformOperationException(
                'The specified hash function does not exist'
            );
        }
        
        // Let's grab the file salt.
        $file_salt = self::readBytes($inputHandle, $config->saltByteSize());
            
        // For storing MACs of each buffer chunk
        $macs = [];

        /**
         * 1. We need to decode some values from our files
         */
            /**
             * Let's split our keys
             *
             * $ekey -- Encryption Key -- used for AES
             */
            $ekey = Core::HKDF(
                $config->hashFunctionName(),
                $key->getRawBytes(),
                $config->keyByteSize(),
                $config->encryptionInfoString(),
                $file_salt,
                $config
            );

            /**
             * $akey -- Authentication Key -- used for HMAC
             */
            $akey = Core::HKDF(
                $config->hashFunctionName(),
                $key->getRawBytes(),
                $config->keyByteSize(),
                $config->authenticationInfoString(),
                $file_salt,
                $config
            );

            /**
             * Grab our IV from the encrypted message
             *
             * It should be the first N blocks of the file (N = 16)
             */
            $ivsize = \openssl_cipher_iv_length($config->cipherMethod());
            $iv = self::readBytes($inputHandle, $ivsize);

            // How much do we increase the counter after each buffered encryption to prevent nonce reuse
            $inc = $config->bufferByteSize() / $config->blockByteSize();

            $thisIv = $iv;

            /**
             * Let's grab our MAC
             *
             * It should be the last N blocks of the file (N = 32)
             */
            if (\fseek($inputHandle, (-1 * $config->macByteSize()), SEEK_END) === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot seek to beginning of MAC within input file'
                );
            }

            // Grab our last position of ciphertext before we read the MAC
            $cipher_end = \ftell($inputHandle);
            if ($cipher_end === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot read input file'
                );
            }
            --$cipher_end; // We need to subtract one

            // We keep our MAC stored in this variable
            $stored_mac = self::readBytes($inputHandle, $config->macByteSize());

            /**
             * We begin recalculating the HMAC for the entire file...
             */
            $hmac = \hash_init($config->hashFunctionName(), HASH_HMAC, $akey);
            if ($hmac === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot initialize a hash context'
                );
            }

            /**
             * Reset file pointer to the beginning of the file after the header
             */
            if (\fseek($inputHandle, Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot read seek within input file'
                );
            }

            /**
             * Set it to the first non-salt and non-IV byte
             */
            if (\fseek($inputHandle, $config->saltByteSize() + $ivsize, SEEK_CUR) === false) {
                throw new Ex\CannotPerformOperationException(
                    'Cannot read seek input file to beginning of ciphertext'
                );
            }
        /**
         * 2. Let's recalculate the MAC
         */
            /**
             * Let's initialize our $hmac hasher with our Salt and IV
             */
            \hash_update($hmac, $header);
            \hash_update($hmac, $file_salt);
            \hash_update($hmac, $iv);
            $hmac2 = \hash_copy($hmac);

            $break = false;
            while (!$break) {
                /**
                 * First, grab the current position
                 */
                $pos = \ftell($inputHandle);
                if ($pos === false) {
                    throw new Ex\CannotPerformOperationException(
                        'Could not get current position in input file during decryption'
                    );
                }

                /**
                 * Would a full DBUFFER read put it past the end of the
                 * ciphertext? If so, only return a portion of the file.
                 */
                if ($pos + $config->bufferByteSize() >= $cipher_end) {
                    $break = true;
                    $read = self::readBytes(
                        $inputHandle,
                        $cipher_end - $pos + 1
                    );
                } else {
                    $read = self::readBytes(
                        $inputHandle,
                        $config->bufferByteSize()
                    );
                }
                if ($read === false) {
                    throw new Ex\CannotPerformOperationException(
                        'Could not read input file during decryption'
                    );
                }
                /**
                 * We're updating our HMAC and nothing else
                 */
                \hash_update($hmac, $read);

                /**
                 * Store a MAC of each chunk
                 */
                $chunkMAC = \hash_copy($hmac);
                if ($chunkMAC === false) {
                    throw new Ex\CannotPerformOperationException(
                        'Cannot duplicate a hash context'
                    );
                }
                $macs []= \hash_final($chunkMAC);
            }
            /**
             * We should now have enough data to generate an identical HMAC
             */
            $finalHMAC = \hash_final($hmac, true);
        /**
         * 3. Did we match?
         */
            if (!Core::hashEquals($finalHMAC, $stored_mac)) {
                throw new Ex\InvalidCiphertextException(
                    'Message Authentication failure; tampering detected.'
                );
            }
        /**
         * 4. Okay, let's begin decrypting
         */
            /**
             * Return file pointer to the first non-header, non-IV byte in the file
             */
            if (\fseek($inputHandle, $config->saltByteSize() + $ivsize + Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
                throw new Ex\CannotPerformOperationException(
                    'Could not move the input file pointer during decryption'
                );
            }

            /**
             * Should we break the writing?
             */
            $breakW = false;

            /**
             * This loop writes plaintext to the destination file:
             */
            while (!$breakW) {
                /**
                 * Get the current position
                 */
                $pos = \ftell($inputHandle);
                if ($pos === false) {
                    throw new Ex\CannotPerformOperationException(
                        'Could not get current position in input file during decryption'
                    );
                }

                /**
                 * Would a full BUFFER read put it past the end of the
                 * ciphertext? If so, only return a portion of the file.
                 */
                if ($pos + $config->bufferByteSize() >= $cipher_end) {
                    $breakW = true;
                    $read = self::readBytes(
                        $inputHandle,
                        $cipher_end - $pos + 1
                    );
                } else {
                    $read = self::readBytes(
                        $inputHandle,
                        $config->bufferByteSize()
                    );
                }

                /**
                 * Recalculate the MAC, compare with the one stored in the $macs
                 * array to ensure attackers couldn't tamper with the file
                 * after MAC verification
                 */
                \hash_update($hmac2, $read);
                $calcMAC = \hash_copy($hmac2);
                if ($calcMAC === false) {
                    throw new Ex\CannotPerformOperationException(
                        'Cannot duplicate a hash context'
                    );
                }
                $calc = \hash_final($calcMAC);

                if (empty($macs)) {
                    throw new Ex\InvalidCiphertextException(
                        'File was modified after MAC verification'
                    );
                } elseif (!Core::hashEquals(\array_shift($macs), $calc)) {
                    throw new Ex\InvalidCiphertextException(
                        'File was modified after MAC verification'
                    );
                }

                $thisIv = Core::incrementCounter($thisIv, $inc, $config);

                /**
                 * Perform the AES decryption. Decrypts the message.
                 */
                $decrypted = \openssl_decrypt(
                    $read,
                    $config->cipherMethod(),
                    $ekey,
                    OPENSSL_RAW_DATA,
                    $thisIv
                );

                /**
                 * Test for decryption faulure
                 */
                if ($decrypted === false) {
                    throw new Ex\CannotPerformOperationException(
                        'OpenSSL decryption error'
                    );
                }

                /**
                 * Write the plaintext out to the output file
                 */
                self::writeBytes(
                    $outputHandle,
                    $decrypted,
                    Core::ourStrlen($decrypted)
                );
            }
        return true;
    }

    /**
     * Get the encryption configuration based on the version in a header.
     *
     * @param string $header The header to read the version number from.
     * @param string $min_ver_header The header of the minimum version number allowed.
     * @return array
     * @throws Ex\InvalidCiphertextException
     */
    private static function getFileVersionConfigFromHeader($header, $min_ver_header)
    {
        if (Core::ourSubstr($header, 0, 2) !== Core::ourSubstr(Core::HEADER_MAGIC_FILE, 0, 2)) {
            throw new Ex\InvalidCiphertextException(
                "Ciphertext file has a bad magic number."
            );
        }

        $major = \ord($header[2]);
        $minor = \ord($header[3]);

        $min_major = \ord($min_ver_header[2]);
        $min_minor = \ord($min_ver_header[3]);

        if ($major < $min_major || ($major === $min_major && $minor < $min_minor)) {
            throw new Ex\InvalidCiphertextException(
                "Ciphertext is requesting an insecure fallback."
            );
        }

        $config = self::getFileVersionConfigFromMajorMinor($major, $minor);

        return $config;
    }

    /**
     *
     * @param int $major The major version number.
     * @param int $minor The minor version number.
     * @return array
     * @throws Ex\InvalidCiphertextException
     */
    private static function getFileVersionConfigFromMajorMinor($major, $minor)
    {
        if ($major === 2) {
            switch ($minor) {
            case 0:
                return new FileConfig([
                    'cipher_method' => 'aes-256-ctr',
                    'block_byte_size' => 16,
                    'key_byte_size' => 32,
                    'salt_byte_size' => 32,
                    'hash_function_name' => 'sha256',
                    'mac_byte_size' => 32,
                    'encryption_info_string' => 'DefusePHP|V2File|KeyForEncryption',
                    'authentication_info_string' => 'DefusePHP|V2File|KeyForAuthentication',
                    'buffer_byte_size' => 1048576
                ]);
            default:
                throw new Ex\InvalidCiphertextException(
                    "Unsupported file ciphertext version."
                );
            }
        } else {
            throw new Ex\InvalidCiphertextException(
                "Unsupported file ciphertext version."
            );
        }
    }

    /**
     * Read from a stream; prevent partial reads
     *
     * @param resource $stream
     * @param int $num
     * @return string
     *
     * @throws \RangeException
     * @throws Ex\CannotPerformOperationException
     */
    final public static function readBytes($stream, $num)
    {
        if ($num <= 0) {
            throw new \RangeException(
                'Tried to read less than 0 bytes'
            );
        }
        $buf = '';
        $remaining = $num;
        while ($remaining > 0 && !\feof($stream)) {
            $read = \fread($stream, $remaining);
            
            if ($read === false) {
                throw new Ex\CannotPerformOperationException(
                    'Could not read from the file'
                );
            }
            $buf .= $read;
            $remaining -= Core::ourStrlen($read);
        }
        if (Core::ourStrlen($buf) !== $num) {
            throw new Ex\CannotPerformOperationException(
                'Tried to read past the end of the file'
            );
        }
        return $buf;
    }

    /**
     * Write to a stream; prevent partial writes
     *
     * @param resource $stream
     * @param string $buf
     * @param int $num (number of bytes)
     * @return string
     * @throws Ex\CannotPerformOperationException
     */
    final public static function writeBytes($stream, $buf, $num = null)
    {
        $bufSize = Core::ourStrlen($buf);
        if ($num === null) {
            $num = $bufSize;
        }
        if ($num > $bufSize) {
            throw new Ex\CannotPerformOperationException(
                'Trying to write more bytes than the buffer contains.'
            );
        }
        if ($num < 0) {
            throw new Ex\CannotPerformOperationException(
                'Tried to write less than 0 bytes'
            );
        }
        $remaining = $num;
        while ($remaining > 0) {
            $written = \fwrite($stream, $buf, $remaining);
            if ($written === false) {
                throw new Ex\CannotPerformOperationException(
                    'Could not write to the file'
                );
            }
            $buf = Core::ourSubstr($buf, $written, null);
            $remaining -= $written;
        }
        return $num;
    }
}
