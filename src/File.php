<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

final class File extends Core implements StreamInterface
{
    const BUFFER = 1048576;
    const CIPHER_MODE = 'ctr';
    
    /**
     * Encrypt the contents at $inputFilename, storing the result in $outputFilename
     * using HKDF of $key to perform authenticated encryption
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
        
        /**
         * Open the file handles
         */
        
        /**
         * Input file handle
         */
        $if = \fopen($inputFilename, 'rb');
        if ($if === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot open input file for encrypting'
            );
        }
        \stream_set_read_buffer($if, self::BUFFER);
        
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
        if(\fclose($if) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot close input file for encrypting'
            );
        }
        if(\fclose($of) === false) {
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
        /**
         * Open the file handles
         */
        
        /**
         * Input file handle
         */
        $if = \fopen($inputFilename, 'rb');
        if ($if === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot open input file for decrypting'
            );
        }
        \stream_set_read_buffer($if, self::BUFFER);
        
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
        if(\fclose($if) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot close input file for decrypting'
            );
        }
        if(\fclose($of) === false) {
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
        
        // Let's add this check before anything
        if (!\in_array(self::HASH_FUNCTION, \hash_algos())) {
            throw new Ex\CannotPerformOperation(
                'The specified hash function does not exist'
            );
        }
        
        // Sanity check; key must be the appropriate length!
        if (self::ourStrlen($key) !== self::KEY_BYTE_SIZE) {
            throw new Ex\InvalidInput(
                'Invalid key length. Keys should be '.self::KEY_BYTE_SIZE.' bytes long.'
            );
        }
        
        // 'aes-128-ctr' unless someone mucked with the config in Core.php
        $method = self::CIPHER.'-'.self::CIPHER_MODE;
        
        /**
         *  Let's split our keys
         */
        
        // $ekey -- Encryption Key -- used for AES
        $ekey = self::HKDF(
            self::HASH_FUNCTION,
            $key,
            self::KEY_BYTE_SIZE,
            self::ENCRYPTION_INFO
        );
        
        // $akey -- Authentication Key -- used for HMAC
        $akey = self::HKDF(
            self::HASH_FUNCTION,
            $key,
            self::KEY_BYTE_SIZE,
            self::AUTHENTICATION_INFO
        );
        
        /**
         *  Generate a random initialization vector.
         */
        self::ensureFunctionExists("openssl_cipher_iv_length");
        $ivsize = \openssl_cipher_iv_length($method);
        if ($ivsize === FALSE || $ivsize <= 0) {
            throw new Ex\CannotPerformOperation(
                'Improper IV size'
            );
        }
        $iv = self::secureRandom($ivsize);
        
        /**
         * First let's write our IV to the first N blocks of the output file
         */
        if (\fwrite($outputHandle, $iv, $ivsize) === false) {
            throw new Ex\CannotPerformOperation(
                'Cannot write to output file'
            );
        }
        
        /**
         * We're going to initialize a HMAC-SHA256 with the given $akey
         * and update it with each ciphertext chunk
         */
        $hmac = \hash_init(self::HASH_FUNCTION, HASH_HMAC, $akey);
        
        /**
         * We operate on $thisIv using a hash-based PRF derived from the initial
         * IV for the first block
         */
        $thisIv = $iv;
        
        /**
         * How much do we increase the counter after each buffered encryption to
         * prevent nonce reuse?
         */
        $inc = self::BUFFER / self::BLOCK_SIZE;
        
        /**
         * Let's MAC our IV/nonce
         */
        \hash_update($hmac, $iv);
        
        /**
         * Iterate until we reach the end of the input file
         */
        while (!\feof($inputHandle)) {
            $read = \fread($inputHandle, self::BUFFER);
            if ($read === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }
            $thisIv = self::incrementCounter($thisIv, $inc);
            
            /**
             * Perform the AES encryption. Encrypts the plaintext.
             */
            $encrypted = \openssl_encrypt(
                $read,
                $method,
                $ekey,
                OPENSSL_RAW_DATA,
                $thisIv
            );
            if ($encrypted === false) {
                throw new Ex\CannotPerformOperation(
                    'OpenSSL encryption error'
                );
            }
            
            /**
             * Write the ciphertext to the output file
             */
            if (\fwrite($outputHandle, $encrypted, self::ourStrlen($encrypted)) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot write to output file'
                );
            }
            
            /**
             * Update the HMAC for the entire file with the data from this block
             */
            \hash_update($hmac, $encrypted);
        }
        
        // Now let's get our HMAC and append it
        $finalHMAC = \hash_final($hmac, true);
        
        $appended = \fwrite($outputHandle, $finalHMAC, self::MAC_BYTE_SIZE);
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
        // Let's add this check before anything
        if (!\in_array(self::HASH_FUNCTION, \hash_algos())) {
            throw new Ex\CannotPerformOperation(
                'The specified hash function does not exist'
            );
        }
        
        // Sanity check; key must be the appropriate length!
        if (self::ourStrlen($key) !== self::KEY_BYTE_SIZE) {
            throw new Ex\InvalidInput(
                'Invalid key length. Keys should be '.self::KEY_BYTE_SIZE.' bytes long.'
            );
        }
        // For storing MACs of each buffer chunk
        $macs = [];
        
        /**
         * 1. We need to decode some values from our files
         */
        
        // 'aes-128-ctr' unless someone mucked with the config in Core.php
        $method = self::CIPHER.'-'.self::CIPHER_MODE;
            /**
             * Let's split our keys
             * 
             * $ekey -- Encryption Key -- used for AES
             */
            $ekey = self::HKDF(
                self::HASH_FUNCTION,
                $key,
                self::KEY_BYTE_SIZE,
                self::ENCRYPTION_INFO
            );

            /**
             * $akey -- Authentication Key -- used for HMAC
             */
            $akey = self::HKDF(
                self::HASH_FUNCTION,
                $key,
                self::KEY_BYTE_SIZE,
                self::AUTHENTICATION_INFO
            );

            /**
             * Grab our IV from the encrypted message
             * 
             * It should be the first N blocks of the file (N = 16)
             */
            $ivsize = \openssl_cipher_iv_length($method);
            $iv = \fread($inputHandle, $ivsize);
            if ($iv === false ) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }
            
            // How much do we increase the counter after each buffered encryption to prevent nonce reuse
            $inc = self::BUFFER / self::BLOCK_SIZE;
            
            $thisIv = $iv;

            /**
             * Let's grab our MAC
             * 
             * It should be the last N blocks of the file (N = 32)
             */
            if(\fseek($inputHandle, (-1 * self::MAC_BYTE_SIZE), SEEK_END) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot seek to beginning of MAC within input file'
                );
            }
            
            // Grab our last position of ciphertext before we read the MAC
            $cipher_end = \ftell($inputHandle) - 1;
            if ($cipher_end === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }
            
            // We keep our MAC stored in this variable
            $stored_mac = \fread($inputHandle, self::MAC_BYTE_SIZE);
            if ($stored_mac === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read input file'
                );
            }

            /**
             * We begin recalculating the HMAC for the entire file...
             */
            $hmac = \hash_init(self::HASH_FUNCTION, HASH_HMAC, $akey);
            
            /**
             * Reset file pointer to the beginning of the file.
             */
            if (\fseek($inputHandle, 0, SEEK_SET) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read seek within input file'
                );
            }

            /**
             * Set it to the first non-IV byte
             */
            if (\fseek($inputHandle, $ivsize, SEEK_CUR) === false) {
                throw new Ex\CannotPerformOperation(
                    'Cannot read seek input file to beginning of ciphertext'
                );
            }
        /**
         * 2. Let's recalculate the MAC
         */
            /**
             * Let's initialize our $hmac hasher with our IV
             */
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
                if ($pos + self::BUFFER >= $cipher_end) {
                    $break = true;
                    $read = \fread($inputHandle, $cipher_end - $pos + 1);
                } else {
                    $read = \fread($inputHandle, self::BUFFER);
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
                $macs []= \hash_final($chunkMAC);
            }
            /**
             * We should now have enough data to generate an identical HMAC
             */
            $finalHMAC = \hash_final($hmac, true);
        /**
         * 3. Did we match?
         */
            if (!self::hashEquals($finalHMAC, $stored_mac)) {
                throw new Ex\InvalidCiphertext();
            }
        /**
         * 4. Okay, let's begin decrypting
         */
            /**
             * Return file pointer to the first non-IV byte in the file
             */
            if (\fseek($inputHandle, $ivsize, SEEK_SET) === false) {
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
                if ($pos + self::BUFFER >= $cipher_end) {
                    $breakW = true;
                    $read = \fread($inputHandle, $cipher_end - $pos + 1);
                } else {
                    $read = \fread($inputHandle, self::BUFFER);
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
                $calc = \hash_final($calcMAC);
                
                if (!self::hashEquals(\array_shift($macs), $calc)) {
                    throw new Ex\InvalidCiphertext(
                        'File was modified after MAC verification'
                    );
                }
                
                $thisIv = self::incrementCounter($thisIv, $inc);
                
                /**
                 * Perform the AES decryption. Decrypts the message.
                 */
                $decrypted = \openssl_decrypt(
                    $read,
                    $method,
                    $ekey,
                    OPENSSL_RAW_DATA,
                    $thisIv
                );
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
                    self::ourStrlen($decrypted)
                );
                
                /**
                 * Check result
                 */
                if ($result === false) {
                    throw new Ex\CannotPerformOperation(
                        'Could not write to output file durind decryption.'
                    );
                }
                ++$block;
            }
        return $result;
    }
    
    /**
     * Increment a counter (prevent nonce reuse)
     * 
     * @param string $ctr - raw binary
     * @param int $inc - how much?
     * 
     * @return string (raw binary)
     */
    protected static function incrementCounter($ctr, $inc = 1)
    {
        static $ivsize = null;
        if ($ivsize === null) {
            $ivsize = \openssl_cipher_iv_length(self::CIPHER.'-'.self::CIPHER_MODE);
        }
        
        /**
         * We start at the rightmost byte (big-endian)
         * So, too, does OpenSSL: http://stackoverflow.com/a/3146214/2224584
         */
        
        for ($i = $ivsize - 1; $i >= 0; --$i) {
            $c = \ord($ctr[$i]);
            
            $ctr[$i] = \chr(($c + $inc) & 0xFF);
            if (($c + $inc) <= 255) {
                // We don't need to keep incrementing to the left unless we exceed 255
                break;
            }
            $inc = ($inc >> 8) & (PHP_INT_MAX - 1);
        }
        return $ctr;
    }
}
