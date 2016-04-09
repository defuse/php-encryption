<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class File implements StreamInterface
{
    // File ciphertext format: [____VERSION____][____SALT____][____IV____][____CIPHERTEXT____][____HMAC____].

    /**
     * Encrypt the contents at $inputFilename, storing the result in
     * $outputFilename using HKDF of $key to perform authenticated encryption
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param Key    $key
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \Defuse\Crypto\Exception\CryptoException
     *
     * @return bool
     */
    public static function encryptFile($inputFilename, $outputFilename, Key $key)
    {
        return self::encryptFileInternal(
            $inputFilename,
            $outputFilename,
            KeyOrPassword::createFromKey($key)
        );
    }

    public static function encryptFileWithPassword($inputFilename, $outputFilename, $password)
    {
        return self::encryptFileInternal(
            $inputFilename,
            $outputFilename,
            KeyOrPassword::createFromPassword($password)
        );
    }

    private static function encryptFileInternal($inputFilename, $outputFilename, KeyOrPassword $secret)
    {
        if (! \is_string($inputFilename)) {
            throw new Ex\IOException(
                'Input filename must be a string!'
            );
        }
        if (! \is_string($outputFilename)) {
            throw new Ex\IOException(
                'Output filename must be a string!'
            );
        }

            /** Open the file handles **/

            /**
             * Input file handle
             */
            $if = @\fopen($inputFilename, 'rb');
        if ($if === false) {
            throw new Ex\IOException(
                'Cannot open input file for encrypting: ' .
                self::getLastErrorMessage()
            );
        }
        \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = @\fopen($outputFilename, 'wb');
        if ($of === false) {
            \fclose($if);
            throw new Ex\IOException(
                'Cannot open output file for encrypting: ' .
                self::getLastErrorMessage()
            );
        }
        \stream_set_write_buffer($of, 0);

        /**
         * Use encryptResource() to actually write the encrypted data to $of
         */
        try {
            $encrypted = self::encryptResourceInternal($if, $of, $secret);
        } catch (Ex\CryptoException $ex) {
            \fclose($if);
            \fclose($of);
            throw $ex;
        }

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\IOException(
                'Cannot close input file for encrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\IOException(
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
     * @param Key    $key
     *
     * @return bool
     */
    public static function decryptFile($inputFilename, $outputFilename, Key $key)
    {
        return self::decryptFileInternal(
            $inputFilename,
            $outputFilename,
            KeyOrPassword::createFromKey($key)
        );
    }

    public static function decryptFileWithPassword($inputFilename, $outputFilename, $password)
    {
        return self::decryptFileInternal(
            $inputFilename,
            $outputFilename,
            KeyOrPassword::createFromPassword($password)
        );
    }

    private static function decryptFileInternal($inputFilename, $outputFilename, KeyOrPassword $secret)
    {
        if (! \is_string($inputFilename)) {
            throw new Ex\IOException(
                'Input filename must be a string!'
            );
        }
        if (! \is_string($outputFilename)) {
            throw new Ex\IOException(
                'Output filename must be a string!'
            );
        }

            /** Open the file handles **/

            /**
             * Input file handle
             */
            $if = @\fopen($inputFilename, 'rb');
        if ($if === false) {
            throw new Ex\IOException(
                'Cannot open input file for decrypting: ' .
                self::getLastErrorMessage()
            );
        }
        \stream_set_read_buffer($if, 0);

            /**
             * Output file handle
             */
            $of = @\fopen($outputFilename, 'wb');
        if ($of === false) {
            \fclose($if);
            throw new Ex\IOException(
                'Cannot open output file for decrypting: ' .
                self::getLastErrorMessage()
            );
        }
        \stream_set_write_buffer($of, 0);

        /**
         * Use decryptResource() to actually write the decrypted data to $of
         */
        try {
            $decrypted = self::decryptResourceInternal($if, $of, $secret);
        } catch (Ex\CryptoException $ex) {
            \fclose($if);
            \fclose($of);
            throw $ex;
        }

        /**
         * Close handles
         */
        if (\fclose($if) === false) {
            throw new Ex\IOException(
                'Cannot close input file for decrypting'
            );
        }
        if (\fclose($of) === false) {
            throw new Ex\IOException(
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
     * @param Key      $key
     *
     * @throws Exception\EnvironmentIsBrokenException
     * @throws Exception\WrongKeyOrModifiedCiphertextException
     *
     * @return bool
     */
    public static function encryptResource($inputHandle, $outputHandle, Key $key)
    {
        return self::encryptResourceInternal(
            $inputHandle,
            $outputHandle,
            KeyOrPassword::createFromKey($key)
        );
    }

    public static function encryptResourceWithPassword($inputHandle, $outputHandle, $password)
    {
        return self::encryptResourceInternal(
            $inputHandle,
            $outputHandle,
            KeyOrPassword::createFromPassword($password)
        );
    }

    private static function encryptResourceInternal($inputHandle, $outputHandle, KeyOrPassword $secret)
    {
        // Because we don't have strict typing in PHP 5
        if (! \is_resource($inputHandle)) {
            throw new Ex\IOException(
                'Input handle must be a resource!'
            );
        }
        if (! \is_resource($outputHandle)) {
            throw new Ex\IOException(
                'Output handle must be a resource!'
            );
        }
        $inputStat = \fstat($inputHandle);
        $inputSize = $inputStat['size'];

        /**
         *  Let's split our keys
         */
        $file_salt = Core::secureRandom(Core::SALT_BYTE_SIZE);
        $keys = $secret->deriveKeys($file_salt);
        $ekey = $keys->getEncryptionKey();
        $akey = $keys->getAuthenticationKey();

        /**
         *  Generate a random initialization vector.
         */
        $ivsize = Core::cipherIvLength(Core::CIPHER_METHOD);
        $iv     = Core::secureRandom($ivsize);

        /**
         * First let's write our header, file salt, and IV to the first N blocks of the output file
         */
        self::writeBytes(
            $outputHandle,
            Core::CURRENT_VERSION . $file_salt . $iv,
            Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + $ivsize
        );

        /**
         * We're going to initialize a HMAC-SHA256 with the given $akey
         * and update it with each ciphertext chunk
         */
        $hmac = \hash_init(Core::HASH_FUNCTION_NAME, HASH_HMAC, $akey);
        if ($hmac === false) {
            throw new Ex\EnvironmentIsBrokenException(
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
        $inc = Core::BUFFER_BYTE_SIZE / Core::BLOCK_BYTE_SIZE;

        /**
         * Let's MAC our salt and IV/nonce
         */
        \hash_update($hmac, Core::CURRENT_VERSION);
        \hash_update($hmac, $file_salt);
        \hash_update($hmac, $iv);

        /**
         * Iterate until we reach the end of the input file
         */
        $breakR = false;
        while (! \feof($inputHandle)) {
            $pos = \ftell($inputHandle);
            if ($pos + Core::BUFFER_BYTE_SIZE >= $inputSize) {
                $breakR = true;
                // We need to break after this loop iteration
                $read = self::readBytes(
                    $inputHandle,
                    $inputSize - $pos
                );
            } else {
                $read = self::readBytes(
                    $inputHandle,
                    Core::BUFFER_BYTE_SIZE
                );
            }

            /**
             * Perform the AES encryption. Encrypts the plaintext.
             */
            $encrypted = \openssl_encrypt(
                $read,
                Core::CIPHER_METHOD,
                $ekey,
                OPENSSL_RAW_DATA,
                $thisIv
            );

            $thisIv = Core::incrementCounter($thisIv, $inc, Core::CIPHER_METHOD);

            /**
             * Check that the encryption was performed successfully
             */
            if ($encrypted === false) {
                throw new Ex\EnvironmentIsBrokenException(
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

        self::writeBytes($outputHandle, $finalHMAC, CORE::MAC_BYTE_SIZE);
        return true;
    }

    /**
     * Decrypt the contents of a file handle $inputHandle and store the results
     * in $outputHandle using HKDF of $key to decrypt then verify
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param Key      $key
     *
     * @throws Exception\EnvironmentIsBrokenException
     * @throws Exception\WrongKeyOrModifiedCiphertextException
     *
     * @return bool
     */
    public static function decryptResource($inputHandle, $outputHandle, Key $key)
    {
        return self::decryptResourceInternal(
            $inputHandle,
            $outputHandle,
            KeyOrPassword::createFromKey($key)
        );
    }

    public static function decryptResourceWithPassword($inputHandle, $outputHandle, $password)
    {
        return self::decryptResourceInternal(
            $inputHandle,
            $outputHandle,
            KeyOrPassword::createFromPassword($password)
        );
    }

    public static function decryptResourceInternal($inputHandle, $outputHandle, KeyOrPassword $secret)
    {
        // Because we don't have strict typing in PHP 5
        if (! \is_resource($inputHandle)) {
            throw new Ex\IOException(
                'Input handle must be a resource!'
            );
        }
        if (! \is_resource($outputHandle)) {
            throw new Ex\IOException(
                'Output handle must be a resource!'
            );
        }
        $stat = \fstat($inputHandle);
        if ($stat['size'] < Core::MINIMUM_CIPHERTEXT_SIZE) {
            throw new Ex\WrongKeyOrModifiedCiphertextException(
                'Input file is too small to have been created by this library.'
            );
        }

        // Parse the header.
        $header = self::readBytes($inputHandle, Core::HEADER_VERSION_SIZE);
        if ($header !== Core::CURRENT_VERSION) {
            throw new Ex\WrongKeyOrModifiedCiphertextException(
                'Bad version header.'
            );
        }

        // Let's grab the file salt.
        $file_salt = self::readBytes($inputHandle, Core::SALT_BYTE_SIZE);

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
        $keys = $secret->deriveKeys($file_salt);
        $ekey = $keys->getEncryptionKey();
        $akey = $keys->getAuthenticationKey();

        /**
         * Grab our IV from the encrypted message
         *
         * It should be the first N blocks of the file (N = 16)
         */
        $ivsize = Core::cipherIvLength(Core::CIPHER_METHOD);
        $iv     = self::readBytes($inputHandle, $ivsize);

        // How much do we increase the counter after each buffered encryption to prevent nonce reuse
        $inc = Core::BUFFER_BYTE_SIZE / Core::BLOCK_BYTE_SIZE;

        $thisIv = $iv;

        /**
         * Let's grab our MAC
         *
         * It should be the last N blocks of the file (N = 32)
         */
        if (\fseek($inputHandle, (-1 * Core::MAC_BYTE_SIZE), SEEK_END) === false) {
            throw new Ex\IOException(
                'Cannot seek to beginning of MAC within input file'
            );
        }

        // Grab our last position of ciphertext before we read the MAC
        $cipher_end = \ftell($inputHandle);
        if ($cipher_end === false) {
            throw new Ex\IOException(
                'Cannot read input file'
            );
        }
        --$cipher_end; // We need to subtract one

        // We keep our MAC stored in this variable
        $stored_mac = self::readBytes($inputHandle, Core::MAC_BYTE_SIZE);

        /**
         * We begin recalculating the HMAC for the entire file...
         */
        $hmac = \hash_init(Core::HASH_FUNCTION_NAME, HASH_HMAC, $akey);
        if ($hmac === false) {
            throw new Ex\EnvironmentIsBrokenException(
                'Cannot initialize a hash context'
            );
        }

        /**
         * Reset file pointer to the beginning of the file after the header
         */
        if (\fseek($inputHandle, Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
            throw new Ex\IOException(
                'Cannot read seek within input file'
            );
        }

        /**
         * Set it to the first non-salt and non-IV byte
         */
        if (\fseek($inputHandle, Core::SALT_BYTE_SIZE + $ivsize, SEEK_CUR) === false) {
            throw new Ex\IOException(
                'Cannot seek input file to beginning of ciphertext'
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
        while (! $break) {
            /**
             * First, grab the current position
             */
            $pos = \ftell($inputHandle);
            if ($pos === false) {
                throw new Ex\IOException(
                    'Could not get current position in input file during decryption'
                );
            }

            /**
             * Would a full DBUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($pos + Core::BUFFER_BYTE_SIZE >= $cipher_end) {
                $break = true;
                $read  = self::readBytes(
                    $inputHandle,
                    $cipher_end - $pos + 1
                );
            } else {
                $read = self::readBytes(
                    $inputHandle,
                    Core::BUFFER_BYTE_SIZE
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
                throw new Ex\EnvironmentIsBrokenException(
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
        if (! Core::hashEquals($finalHMAC, $stored_mac)) {
            throw new Ex\WrongKeyOrModifiedCiphertextException(
                'Message Authentication failure; tampering detected.'
            );
        }
        /**
         * 4. Okay, let's begin decrypting
         */
        /**
         * Return file pointer to the first non-header, non-IV byte in the file
         */
        if (\fseek($inputHandle, Core::SALT_BYTE_SIZE + $ivsize + Core::HEADER_VERSION_SIZE, SEEK_SET) === false) {
            throw new Ex\IOException(
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
        while (! $breakW) {
            /**
             * Get the current position
             */
            $pos = \ftell($inputHandle);
            if ($pos === false) {
                throw new Ex\IOException(
                    'Could not get current position in input file during decryption'
                );
            }

            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($pos + Core::BUFFER_BYTE_SIZE >= $cipher_end) {
                $breakW = true;
                $read   = self::readBytes(
                    $inputHandle,
                    $cipher_end - $pos + 1
                );
            } else {
                $read = self::readBytes(
                    $inputHandle,
                    Core::BUFFER_BYTE_SIZE
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
                throw new Ex\EnvironmentIsBrokenException(
                    'Cannot duplicate a hash context'
                );
            }
            $calc = \hash_final($calcMAC);

            if (empty($macs)) {
                throw new Ex\WrongKeyOrModifiedCiphertextException(
                    'File was modified after MAC verification'
                );
            } elseif (! Core::hashEquals(\array_shift($macs), $calc)) {
                throw new Ex\WrongKeyOrModifiedCiphertextException(
                    'File was modified after MAC verification'
                );
            }

            /**
             * Perform the AES decryption. Decrypts the message.
             */
            $decrypted = \openssl_decrypt(
                $read,
                Core::CIPHER_METHOD,
                $ekey,
                OPENSSL_RAW_DATA,
                $thisIv
            );

            $thisIv = Core::incrementCounter($thisIv, $inc, Core::CIPHER_METHOD);

            /**
             * Test for decryption faulure
             */
            if ($decrypted === false) {
                throw new Ex\EnvironmentIsBrokenException(
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
     * Read from a stream; prevent partial reads
     *
     * @param resource $stream
     * @param int      $num
     *
     * @throws \RangeException
     * @throws Ex\IOException
     *
     * @return string
     */
    final public static function readBytes($stream, $num)
    {
        if ($num < 0) {
            throw new \RangeException(
                'Tried to read less than 0 bytes'
            );
        } elseif ($num === 0) {
            return '';
        }
        $buf       = '';
        $remaining = $num;
        while ($remaining > 0 && ! \feof($stream)) {
            $read = \fread($stream, $remaining);

            if ($read === false) {
                throw new Ex\IOException(
                    'Could not read from the file'
                );
            }
            $buf .= $read;
            $remaining -= Core::ourStrlen($read);
        }
        if (Core::ourStrlen($buf) !== $num) {
            throw new Ex\IOException(
                'Tried to read past the end of the file'
            );
        }
        return $buf;
    }

    /**
     * Write to a stream; prevent partial writes
     *
     * @param resource $stream
     * @param string   $buf
     * @param int      $num    (number of bytes)
     *
     * @throws Ex\IOException
     *
     * @return string
     */
    final public static function writeBytes($stream, $buf, $num = null)
    {
        $bufSize = Core::ourStrlen($buf);
        if ($num === null) {
            $num = $bufSize;
        }
        if ($num > $bufSize) {
            throw new Ex\IOException(
                'Trying to write more bytes than the buffer contains.'
            );
        }
        if ($num < 0) {
            throw new Ex\IOException(
                'Tried to write less than 0 bytes'
            );
        }
        $remaining = $num;
        while ($remaining > 0) {
            $written = \fwrite($stream, $buf, $remaining);
            if ($written === false) {
                throw new Ex\IOException(
                    'Could not write to the file'
                );
            }
            $buf = Core::ourSubstr($buf, $written, null);
            $remaining -= $written;
        }
        return $num;
    }

    private static function getLastErrorMessage()
    {
        $error = error_get_last();
        if ($error === NULL) {
            return "[no PHP error]";
        } else {
            return $error['message'];
        }
    }
}
