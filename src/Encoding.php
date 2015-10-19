<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;
use \Defuse\Crypto\Core;

final class Encoding {

    /**
     * Convert a binary string into a hexadecimal string without cache-timing 
     * leaks
     *
     * @param string $bin_string (raw binary)
     * @return string
     */
    public static function binToHex($bin_string)
    {
        $hex = '';
        $len = Core::ourStrlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($bin_string[$i]) & 0xf;
            $b = \ord($bin_string[$i]) >> 4;
            $hex .= \chr(87 + $b + ((($b - 10) >> 8) & ~38));
            $hex .= \chr(87 + $c + ((($c - 10) >> 8) & ~38));
        }
        return $hex;
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing 
     * leaks
     *
     * @param string $hex_string
     * @return string (raw binary)
     */
    public static function hexToBin($hex_string)
    {
        $hex_pos = 0;
        $bin = '';
        $hex_len = Core::ourStrlen($hex_string);
        $state = 0;
        $c_acc = 0;

        while ($hex_pos < $hex_len) {
            $c = \ord($hex_string[$hex_pos]);
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
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
                $bin .= \chr($c_acc | $c_val);
            }
            $state = $state ? 0 : 1;
            ++$hex_pos;
        }
        return $bin;
    }

}
