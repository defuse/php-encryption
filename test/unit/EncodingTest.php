<?php

use \Defuse\Crypto\Encoding;

class EncodingTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecodeEquivalency()
    {
        for ($length = 0; $length < 50; $length++) {
            for ($i = 0; $i < 50; $i++) {
                $random = \openssl_random_pseudo_bytes($length);

                $encode_a = Encoding::binToHex($random);
                $encode_b = \bin2hex($random);

                $this->assertEquals($encode_b, $encode_a);

                $decode_a = Encoding::hexToBin($encode_a);
                $decode_b = \hex2bin($encode_b);

                $this->assertEquals($decode_b, $decode_a);
                // Just in case.
                $this->assertEquals($random, $decode_b);
            }
        }
    }
}
