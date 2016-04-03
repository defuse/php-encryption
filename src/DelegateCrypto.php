<?php
namespace Defuse\Crypto;

/*
 * PHP Encryption Library
 * Copyright (c) 2014-2015, Taylor Hornby
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

/**
 * A delegate pass-thru that provides a default implementation of the
 * CryptoInterface to allow for keeping BC of the original Crypto class
 * 
 * Proposed by @Rican7 (Trevor N. Suarez)
 */
final class DelegateCrypto implements CryptoInterface
{
    /**
     * Punt to Crypto::createNewRandomKey()
     * 
     * @return string
     */
    public function createNewRandomKey()
    {
        return Crypto::createNewRandomKey();
    }
    
    /**
     * Punt to Crypto::binToHex()
     * 
     * @param string $bin_string
     * @return string
     */
    public function binToHex($bin_string)
    {
        return Crypto::binToHex($bin_string);
    }

    /**
     * Punt to Crypto::encrypt
     * 
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    public function encrypt($plaintext, $key)
    {
        return Crypto::encrypt($plaintext, $key);
    }

    /**
     * Punt to Crypto::decrypt
     * 
     * @param string $ciphertext
     * @param string $key
     * @return string
     */
    public function decrypt($ciphertext, $key)
    {
        return Crypto::decrypt($ciphertext, $key);
    }
    
    /**
     * Punt to Crypto::hexToBin()
     * 
     * @param string $hex_string
     * @return string
     */
    public function hexToBin($hex_string)
    {
        return Crypto::hexToBin($hex_string);
    }
}
