<?php

use \Defuse\Crypto\Encoding;
use \Defuse\Crypto\Core;

class EncodingTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecodeEquivalency()
    {
        for ($length = 0; $length < 50; $length++) {
            for ($i = 0; $i < 50; $i++) {
                $random = $length > 0 ? Core::secureRandom($length) : '';

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

    public function testEncodeDecodeEquivalencyTwoBytes()
    {
        for ($b1 = 0; $b1 < 256; $b1++) {
            for ($b2 = 0; $b2 < 256; $b2++) {
                $str = \pack('C', $b1) . \pack('C', $b2);

                $encode_a = Encoding::binToHex($str);
                $encode_b = \bin2hex($str);

                $this->assertSame($encode_b, $encode_a);

                $decode_a = Encoding::hexToBin($encode_a);
                $decode_b = \hex2bin($encode_b);

                $this->assertSame($decode_b, $decode_a);
                $this->assertSame($str, $decode_b);
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

    /**
     * This shouldn't throw an exception.
     */
    public function testPaddedHexEncoding()
    {
        /* We're just ensuring that an empty string doesn't produce an error. */
        $this->assertSame('', Encoding::trimTrailingWhitespace(''));

        $header = Core::secureRandom(Core::HEADER_VERSION_SIZE);
        $str = Encoding::saveBytesToChecksummedAsciiSafeString(
            $header,
            Core::secureRandom(Core::KEY_BYTE_SIZE)
        );
        $orig = $str;
        $noise = ["\r", "\n", "\t", "\0"];
        for ($i = 0; $i < 1000; ++$i) {
            $c = $noise[\random_int(0, 3)];
            $str .= $c;
            $this->assertSame(
                Encoding::binToHex($orig),
                Encoding::binToHex(Encoding::trimTrailingWhitespace($str)),
                'Pass #' . $i . ' (' . \dechex(\ord($c)) . ')'
            );
        }
    }
}
