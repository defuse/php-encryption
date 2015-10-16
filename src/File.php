<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

use \Defuse\Crypto\Core;

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
        $config = self::getFileVersionConfigFromHeader(Core::CURRENT_FILE_VERSION);
        return Core::secureRandom($config['KEY_BYTE_SIZE']);
    }

    /**
     * Encrypt the contents at $inputFilename, storing the result in
     * $outputFilename using HKDF of $key to perform authenticated encryption
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param string $key
     * @return boolean
     */
    public static function encryptFile($inputFilename, $outputFilename, $key)
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
                throw new Ex\CannotPerformOperation(
                    'Cannot open input file for encrypting'
                );
            }
            \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = \fopen($outputFilename, 'wb');
            if ($of === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot open output file for encrypting'
                );
            }
            \stream_set_write_buffer($of, 0);

        /**
         * Use encryptResource() to actually write the encrypted data to $of
         */
        $encrypted = self::encryptResource($if, $of, $key);

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot close input file for encrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\CannotPerformOperation(
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
     * @param string $key
     * @return boolean
     */
    public static function decryptFile($inputFilename, $outputFilename, $key)
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
                throw new Ex\CannotPerformOperation(
                    'Cannot open input file for decrypting'
                );
            }
            \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = \fopen($outputFilename, 'wb');
            if ($of === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot open output file for decrypting'
                );
            }
            \stream_set_write_buffer($of, 0);

        /**
         * Use decryptResource() to actually write the decrypted data to $of
         */
        $decrypted = self::decryptResource($if, $of, $key);

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot close input file for decrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\CannotPerformOperation(
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
     * @param string $key
     * @return boolean
     */
    public static function encryptResource($inputHandle, $outputHandle, $key)
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
        $config = self::getFileVersionConfigFromHeader(Core::CURRENT_FILE_VERSION);

        // Let's add this check before anything
        if (!\in_array($config['HASH_FUNCTION'], \hash_algos())) {
            throw new Ex\CannotPerformOperation(
                'The specified hash function does not exist'
            );
        }

        // Sanity check; key must be the appropriate length!
        if (Core::ourStrlen($key) !== $config['KEY_BYTE_SIZE']) {
            throw new Ex\InvalidInput(
                'Invalid key length. Keys should be '.$config['KEY_BYTE_SIZE'].' bytes long.'
            );
        }

        /**
         *  Let's split our keys
         */
        $file_salt = Core::secureRandom($config['SALT_SIZE']);

        // $ekey -- Encryption Key -- used for AES
        $ekey = Core::HKDF(
            $config['HASH_FUNCTION'],
            $key,
            $config['KEY_BYTE_SIZE'],
            $config['ENCRYPTION_INFO'],
            $file_salt,
            $config
        );

        // $akey -- Authentication Key -- used for HMAC
        $akey = Core::HKDF(
            $config['HASH_FUNCTION'],
            $key,
            $config['KEY_BYTE_SIZE'],
            $config['AUTHENTICATION_INFO'],
            $file_salt,
            $config
        );

        /**
         *  Generate a random initialization vector.
         */
        Core::ensureFunctionExists("openssl_cipher_iv_length");
        $ivsize = \openssl_cipher_iv_length($config['CIPHER_METHOD']);
        if ($ivsize === false || $ivsize <= 0) {
            throw new Ex\CannotPerformOperation(
                'Improper IV size'
            );
        }
        $iv = Core::secureRandom($ivsize);

        /**
         * First let's write our header, file salt, and IV to the first N blocks of the output file
         */
        if (\fwrite(
            $outputHandle,
            Core::CURRENT_FILE_VERSION . $file_salt . $iv, 
            Core::HEADER_VERSION_SIZE + $config['SALT_SIZE'] + $ivsize
        ) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot write to output file'
            );
        }

        /**
         * We're going to initialize a HMAC-SHA256 with the given $akey
         * and update it with each ciphertext chunk
         */
        $hmac = \hash_init($config['HASH_FUNCTION'], HASH_HMAC, $akey);
        if ($hmac === false) {
            throw new Ex\CannotPerformOperation(
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
        $inc = $config['BUFFER'] / $config['BLOCK_SIZE'];

        /**
         * Let's MAC our salt and IV/nonce
         */
        \hash_update($hmac, Core::CURRENT_FILE_VERSION);
        \hash_update($hmac, $file_salt);
        \hash_update($hmac, $iv);

        /**
         * Iterate until we reach the end of the input file
         */
        while (!\feof($inputHandle)) {
            $read = \fread($inputHandle, $config['BUFFER']);
            if ($read === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }
            $thisIv = Core::incrementCounter($thisIv, $inc, $config);

            /**
             * Perform the AES encryption. Encrypts the plaintext.
             */
            $encrypted = \openssl_encrypt(
                $read,
                $config['CIPHER_METHOD'],
                $ekey,
                OPENSSL_RAW_DATA,
                $thisIv
            );
            /**
             * Check that the encryption was performed successfully
             */
            if ($encrypted === false) {
                throw new Ex\CannotPerformOperation(
                    'OpenSSL encryption error'
                );
            }

            /**
             * Write the ciphertext to the output file
             */
            if (\fwrite($outputHandle, $encrypted, Core::ourStrlen($encrypted)) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot write to output file during encryption'
                );
            }

            /**
             * Update the HMAC for the entire file with the data from this block
             */
            \hash_update($hmac, $encrypted);
        }

        // Now let's get our HMAC and append it
        $finalHMAC = \hash_final($hmac, true);

        $appended = \fwrite($outputHandle, $finalHMAC, $config['MAC_BYTE_SIZE']);
        if ($appended === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot write to output file'
            );
        }
        return true;
    }

    /**
     * Decrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to decrypt then verify
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param string $key
     * @return boolean
     */
    public static function decryptResource($inputHandle, $outputHandle, $key)
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

        // Parse the header, ensuring we get 4 bytes
        $header = '';
        $remaining = 4;
        do {
            $header .= \fread($inputHandle, $remaining);
            $remaining = 4 - Core::ourStrlen($header);
        } while ($remaining > 0);

        $config = self::getFileVersionConfigFromHeader($header);

        // Let's add this check before anything
        if (!\in_array($config['HASH_FUNCTION'], \hash_algos())) {
            throw new Ex\CannotPerformOperation(
                'The specified hash function does not exist'
            );
        }

        // Sanity check; key must be the appropriate length!
        if (Core::ourStrlen($key) !== $config['KEY_BYTE_SIZE']) {
            throw new Ex\InvalidInput(
                'Invalid key length. Keys should be '.$config['KEY_BYTE_SIZE'].' bytes long.'
            );
        }
        // Let's grab the file salt.
        $file_salt = \fread($inputHandle, $config['SALT_SIZE']);
        if ($file_salt === false ) {
            throw new Ex\CannotPerformOperation(
                'Cannot read input file'
            );
        }
            
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
                $config['HASH_FUNCTION'],
                $key,
                $config['KEY_BYTE_SIZE'],
                $config['ENCRYPTION_INFO'],
                $file_salt,
                $config
            );

            /**
             * $akey -- Authentication Key -- used for HMAC
             */
            $akey = Core::HKDF(
                $config['HASH_FUNCTION'],
                $key,
                $config['KEY_BYTE_SIZE'],
                $config['AUTHENTICATION_INFO'],
                $file_salt,
                $config
            );

            /**
             * Grab our IV from the encrypted message
             *
             * It should be the first N blocks of the file (N = 16)
             */
            $ivsize = \openssl_cipher_iv_length($config['CIPHER_METHOD']);
            $iv = \fread($inputHandle, $ivsize);
            if ($iv === false ) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }

            // How much do we increase the counter after each buffered encryption to prevent nonce reuse
            $inc = $config['BUFFER'] / $config['BLOCK_SIZE'];

            $thisIv = $iv;

            /**
             * Let's grab our MAC
             *
             * It should be the last N blocks of the file (N = 32)
             */
            if (\fseek($inputHandle, (-1 * $config['MAC_BYTE_SIZE']), SEEK_END) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot seek to beginning of MAC within input file'
                );
            }

            // Grab our last position of ciphertext before we read the MAC
            $cipher_end = \ftell($inputHandle);
            if ($cipher_end === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }
            --$cipher_end; // We need to subtract one

            // We keep our MAC stored in this variable
            $stored_mac = \fread($inputHandle, $config['MAC_BYTE_SIZE']);
            if ($stored_mac === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }

            /**
             * We begin recalculating the HMAC for the entire file...
             */
            $hmac = \hash_init($config['HASH_FUNCTION'], HASH_HMAC, $akey);
            if ($hmac === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot initialize a hash context'
                );
            }

            /**
             * Reset file pointer to the beginning of the file after the header
             */
            if (\fseek($inputHandle, Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read seek within input file'
                );
            }

            /**
             * Set it to the first non-salt and non-IV byte
             */
            if (\fseek($inputHandle, $config['SALT_SIZE'] + $ivsize, SEEK_CUR) === false) {
                throw new Ex\CannotPerformOperation(
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
                    throw new Ex\CannotPerformOperation(
                        'Could not get current position in input file during decryption'
                    );
                }

                /**
                 * Would a full DBUFFER read put it past the end of the
                 * ciphertext? If so, only return a portion of the file.
                 */
                if ($pos + $config['BUFFER'] >= $cipher_end) {
                    $break = true;
                    $read = \fread($inputHandle, $cipher_end - $pos + 1);
                } else {
                    $read = \fread($inputHandle, $config['BUFFER']);
                }
                if ($read === false) {
                    throw new Ex\CannotPerformOperation(
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
                    throw new Ex\CannotPerformOperation(
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
                throw new Ex\InvalidCiphertext(
                    'Message Authentication failure; tampering detected.'
                );
            }
        /**
         * 4. Okay, let's begin decrypting
         */
            /**
             * Return file pointer to the first non-header, non-IV byte in the file
             */
            if (\fseek($inputHandle, $config['SALT_SIZE'] + $ivsize + Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
                throw new Ex\CannotPerformOperation(
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
            $result = null;
            while (!$breakW) {
                /**
                 * Get the current position
                 */
                $pos = \ftell($inputHandle);
                if ($pos === false) {
                    throw new Ex\CannotPerformOperation(
                        'Could not get current position in input file during decryption'
                    );
                }

                /**
                 * Would a full BUFFER read put it past the end of the
                 * ciphertext? If so, only return a portion of the file.
                 */
                if ($pos + $config['BUFFER'] >= $cipher_end) {
                    $breakW = true;
                    $read = \fread($inputHandle, $cipher_end - $pos + 1);
                } else {
                    $read = \fread($inputHandle, $config['BUFFER']);
                }
                if ($read === false) {
                    throw new Ex\CannotPerformOperation(
                        'Could not read input file during decryption'
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
                    throw new Ex\CannotPerformOperation(
                        'Cannot duplicate a hash context'
                    );
                }
                $calc = \hash_final($calcMAC);

                if (empty($macs)) {
                    throw new Ex\InvalidCiphertext(
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
                    $config['CIPHER_METHOD'],
                    $ekey,
                    OPENSSL_RAW_DATA,
                    $thisIv
                );

                /**
                 * Test for decryption faulure
                 */
                if ($decrypted === false) {
                    throw new Ex\CannotPerformOperation(
                        'OpenSSL decryption error'
                    );
                }

                /**
                 * Write the plaintext out to the output file
                 */
                $result = \fwrite(
                    $outputHandle, 
                    $decrypted, 
                    Core::ourStrlen($decrypted)
                );

                /**
                 * Check result
                 */
                if ($result === false) {
                    throw new Ex\CannotPerformOperation(
                        'Could not write to output file during decryption.'
                    );
                }
            }
        // This should be an integer
        return $result;
    }

    /**
     * Take a 4-byte header and get meaningful version information out of it
     *
     * @param string $header
     */
    private static function getFileVersionConfigFromHeader($header)
    {
        $valid = 0;
        $valid |= ord($header[0]) ^ ord(Core::CURRENT_FILE_VERSION[0]);
        $valid |= ord($header[1]) ^ ord(Core::CURRENT_FILE_VERSION[1]);
        $major = \ord($header[2]);
        $minor = \ord($header[3]);
        $config = self::getFileVersionConfigFromMajorMinor($major, $minor, $valid);
        if ($valid !== 0) {
            throw new Ex\InvalidCiphertextException('Unknown ciphertext version');
        }
        return $config;
    }

    private static function getFileVersionConfigFromMajorMinor($major, $minor, &$valid)
    {
        if ($major === 2) {
            switch ($minor) {
            case 0:
                return [
                    'CIPHER_METHOD' => 'aes-128-ctr',
                    'BLOCK_SIZE' => 16,
                    'KEY_BYTE_SIZE' => 16,
                    'SALT_SIZE' => 16,
                    'HASH_FUNCTION' => 'sha256',
                    'MAC_BYTE_SIZE' => 32,
                    'ENCRYPTION_INFO' => 'DefusePHP|V2File|KeyForEncryption',
                    'AUTHENTICATION_INFO' => 'DefusePHP|V2File|KeyForAuthentication',
                    'BUFFER' => 1048576
                ];
            default:
                $valid |= 0xFF;
            }
        } else {
            $valid |= 0xFF;
        }
    }
}
