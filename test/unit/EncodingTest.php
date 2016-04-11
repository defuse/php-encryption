<?php

use Defuse\Crypto\Core;
use \Defuse\Crypto\Encoding;

class EncodingTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecodeEquivalency()
    {
        for ($length = 0; $length < 50; $length++) {
            for ($i = 0; $i < 50; $i++) {
                $random = $length > 0 ? \openssl_random_pseudo_bytes($length) : '';

                $encode_a = Encoding::binToHex($random);
                $encode_b = \bin2hex($random);

                $this->assertSame($encode_b, $encode_a);

                $decode_a = Encoding::hexToBin($encode_a);
                $decode_b = \hex2bin($encode_b);

                $this->assertSame($decode_b, $decode_a);
                // Just in case.
                $this->assertSame($random, $decode_b);
            }
        }
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\BadFormatException
     * @expectedExceptionMessage checksum doesn't match
     */
    public function testIncorrectChecksum()
    {
        $header = Core::secureRandom(Core::HEADER_VERSION_SIZE);
        $str = Encoding::saveBytesToChecksummedAsciiSafeString(
            $header,
            Core::secureRandom(Core::KEY_BYTE_SIZE)
        );
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 0] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 1] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 3] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 4] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 5] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 6] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 7] = 'f';
        $str[2*Encoding::SERIALIZE_HEADER_BYTES + 8] = 'f';
        Encoding::loadBytesFromChecksummedAsciiSafeString($header, $str);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\BadFormatException
     * @expectedExceptionMessage not a hex string
     */
    public function testBadHexEncoding()
    {
        $header = Core::secureRandom(Core::HEADER_VERSION_SIZE);
        $str = Encoding::saveBytesToChecksummedAsciiSafeString(
            $header,
            Core::secureRandom(Core::KEY_BYTE_SIZE)
        );
        $str[0] = 'Z';
        Encoding::loadBytesFromChecksummedAsciiSafeString($header, $str);
    }

}
