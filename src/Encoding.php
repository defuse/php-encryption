<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class Encoding
{
    const CHECKSUM_BYTE_SIZE     = 32;
    const CHECKSUM_HASH_ALGO     = 'sha256';
    const SERIALIZE_HEADER_BYTES = 4;

    /**
     * Convert a binary string into a hexadecimal string without cache-timing
     * leaks
     *
     * @param string $bin_string (raw binary)
     *
     * @return string
     */
    public static function binToHex($bin_string)
    {
        $hex = '';
        $len = Core::ourStrlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($bin_string[$i]) & 0xf;
            $b = \ord($bin_string[$i]) >> 4;
            $hex .= \pack(
                'CC',
                87 + $b + ((($b - 10) >> 8) & ~38),
                87 + $c + ((($c - 10) >> 8) & ~38)
            );
        }
        return $hex;
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing
     * leaks
     *
     * @param string $hex_string
     *
     * @return string (raw binary)
     */
    public static function hexToBin($hex_string)
    {
        $hex_pos = 0;
        $bin     = '';
        $hex_len = Core::ourStrlen($hex_string);
        $state   = 0;
        $c_acc   = 0;

        while ($hex_pos < $hex_len) {
            $c        = \ord($hex_string[$hex_pos]);
            $c_num    = $c ^ 48;
            $c_num0   = ($c_num - 10) >> 8;
            $c_alpha  = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                throw new \RangeException(
                    'Encoding::hexToBin() only expects hexadecimal characters'
                );
            }
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= \pack('C', $c_acc | $c_val);
            }
            $state ^= 1;
            ++$hex_pos;
        }
        return $bin;
    }

    /**
     * Save bytes to check summed ascii safe string.
     *
     * @param $header
     * @param $bytes
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     *
     * @return string
     */
    public static function saveBytesToChecksummedAsciiSafeString($header, $bytes)
    {
        // Headers must be a constant length to prevent one type's header from
        // being a prefix of another type's header, leading to ambiguity.
        if (Core::ourStrlen($header) !== self::SERIALIZE_HEADER_BYTES) {
            throw new Ex\EnvironmentIsBrokenException(
                'Header must be 4 bytes.'
            );
        }

        return Encoding::binToHex(
            $header .
            $bytes .
            \hash(
                self::CHECKSUM_HASH_ALGO,
                $header . $bytes,
                true
            )
        );
    }

    /**
     * Load bytes from checksummed ascii safe string.
     *
     * @param $expected_header
     * @param $string
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \Defuse\Crypto\Exception\BadFormatException
     *
     * @return string
     */
    public static function loadBytesFromChecksummedAsciiSafeString($expected_header, $string)
    {
        // Headers must be a constant length to prevent one type's header from
        // being a prefix of another type's header, leading to ambiguity.
        if (Core::ourStrlen($expected_header) !== self::SERIALIZE_HEADER_BYTES) {
            throw new Ex\EnvironmentIsBrokenException(
                'Header must be 4 bytes.'
            );
        }

        try {
            $bytes = Encoding::hexToBin($string);
        } catch (\RangeException $ex) {
            throw new Ex\BadFormatException(
                'String has invalid hex encoding.'
            );
        }

        /* Make sure we have enough bytes to get the version header and checksum. */
        if (Core::ourStrlen($bytes) < self::SERIALIZE_HEADER_BYTES + self::CHECKSUM_BYTE_SIZE) {
            throw new Ex\BadFormatException(
                'Encoded data is shorter than expected.'
            );
        }

        /* Grab the version header. */
        $actual_header = Core::ourSubstr($bytes, 0, self::SERIALIZE_HEADER_BYTES);

        if ($actual_header !== $expected_header) {
            throw new Ex\BadFormatException(
                'Invalid header.'
            );
        }

        /* Grab the bytes that are part of the checksum. */
        $checked_bytes = Core::ourSubstr(
            $bytes,
            0,
            Core::ourStrlen($bytes) - self::CHECKSUM_BYTE_SIZE
        );

        /* Grab the included checksum. */
        $checksum_a = Core::ourSubstr(
            $bytes,
            Core::ourStrlen($bytes) - self::CHECKSUM_BYTE_SIZE,
            self::CHECKSUM_BYTE_SIZE
        );

        /* Re-compute the checksum. */
        $checksum_b = \hash(self::CHECKSUM_HASH_ALGO, $checked_bytes, true);

        /* Validate it. It *is* important for this to be constant time. */
        if (! Core::hashEquals($checksum_a, $checksum_b)) {
            throw new Ex\BadFormatException(
                "Data is corrupted, the checksum doesn't match"
            );
        }

        return Core::ourSubstr(
            $bytes,
            self::SERIALIZE_HEADER_BYTES,
            Core::ourStrlen($bytes) - self::SERIALIZE_HEADER_BYTES - self::CHECKSUM_BYTE_SIZE
        );
    }
}
