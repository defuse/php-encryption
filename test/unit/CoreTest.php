<?php

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Encoding;

class CoreTest extends PHPUnit_Framework_TestCase
{
    /**
     * @throws \Exception
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    public function testAes256Ctr()
    {
        $key = \random_bytes(32);
        $nonce = \random_bytes(16);
        for ($i = 0; $i < 10; ++$i) {
            $message = \random_bytes(16 << $i);
            $expected = \openssl_encrypt(
                $message,
                'aes-256-ctr',
                $key,
                OPENSSL_RAW_DATA,
                $nonce
            );
            $actual = Core::aes256ctr($message, $key, $nonce);
            $this->assertSame(
                Encoding::binToHex($expected),
                Encoding::binToHex($actual)
            );
        }
    }

    /**
     * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
     *
     * Key
     * 603deb1015ca71be2b73aef0857d7781
     * 1f352c073b6108d72d9810a30914dff4
     *
     * Init. Counter
     * f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
     *
     * Block #1
     * Plaintext  6bc1bee22e409f96e93d7e117393172a
     * Ciphertext 601ec313775789a5b7a7f504bbf3d228
     *
     * Block #2
     * Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51
     * Ciphertext f443e3ca4d62b59aca84e990cacaf5c5
     *
     * Block #3
     * Plaintext  30c81c46a35ce411e5fbc1191a0a52ef
     * Ciphertext 2b0930daa23de94ce87017ba2d84988d
     *
     * Block #4
     * Plaintext  f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext dfc9c58db67aada613c2dd08457941a6
     *
     * @throws \Defuse\Crypto\Exception\BadFormatException
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    public function testPolyfillAes256CtrTestVectors()
    {
        $key = Encoding::hexToBin('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
        $nonce = Encoding::hexToBin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        $plaintext = Encoding::hexToBin(
            "6bc1bee22e409f96e93d7e117393172a" .
            "ae2d8a571e03ac9c9eb76fac45af8e51" .
            "30c81c46a35ce411e5fbc1191a0a52ef" .
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        $expected = "601ec313775789a5b7a7f504bbf3d228" .
            "f443e3ca4d62b59aca84e990cacaf5c5" .
            "2b0930daa23de94ce87017ba2d84988d" .
            "dfc9c58db67aada613c2dd08457941a6";

        $ciphertext = Core::polyfillAes256Ctr($plaintext, $key, $nonce);
        $this->assertSame(
            $expected,
            Encoding::binToHex($ciphertext),
            'Test Vector from NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt'
        );
    }

    /**
     * @throws \Exception
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    public function testPolyfillAes256Ctr()
    {
        if (!\in_array('aes-256-ctr', \openssl_get_cipher_methods(), true)) {
            $this->markTestSkipped('AES-256-CTR is not in the list of OpenSSL cipher methods.');
        }
        $key = \random_bytes(32);
        $nonce = \random_bytes(16);
        for ($i = 0; $i < 10; ++$i) {
            $message = \random_bytes(16 << $i);
            $expected = Core::aes256ctr($message, $key, $nonce);
            $actual = Core::polyfillAes256Ctr($message, $key, $nonce);
            $this->assertSame(
                Encoding::binToHex($expected),
                Encoding::binToHex($actual)
            );
        }
    }

    // The specific bug the following two tests check for did not fail when
    // mbstring.func_overload=0 so it is crucial to run these tests with
    // mbstring.func_overload=7 as well.

    public function testOurSubstrTrailingEmptyStringBugWeird()
    {
        $str = hex2bin('4d8ab774261977e13049c42b4996f2c4');
        $this->assertSame(16, Core::ourStrlen($str));

        if (ini_get('mbstring.func_overload') == 7) {
            // This checks that the above hex string is indeed "weird."
            // Edit: Er... at least, on PHP 5.6.0 and above it's weird.
            //  I DON'T KNOW WHY THE LENGTH OF A STRING DEPENDS ON THE VERSION
            //  OF PHP BUT APPARENTLY IT DOES ¯\_(ツ)_/¯
            if (version_compare(phpversion(), '5.6.0', '>=')) {
                $this->assertSame(12, strlen($str));
            } else {
                $this->assertSame(16, strlen($str));
            }
        } else {
            $this->assertSame(16, strlen($str));

            // We want ourSubstr to behave identically to substr() in PHP 7 in
            // the non-mbstring case. This double checks what that behavior is.
            if (version_compare(phpversion(), '7.0.0', '>=')) {
                $this->assertSame(
                    '',
                    substr('ABC', 3, 0)
                );
                $this->assertSame(
                    '',
                    substr('ABC', 3)
                );
            } else {
                // The behavior was changed for PHP 7. It used to be...
                $this->assertSame(
                    false,
                    substr('ABC', 3, 0)
                );
                $this->assertSame(
                    false,
                    substr('ABC', 3)
                );
            }
            // Seriously, fuck this shit. Don't use PHP. ╯‵Д′)╯彡┻━┻
        }

        // This checks that the behavior is indeed the same.
        $this->assertSame(
            '',
            Core::ourSubstr($str, 16)
        );
    }

    public function testOurSubstrTrailingEmptyStringBugNormal()
    {
        // Same as above but with a non-weird string.
        $str = 'AAAAAAAAAAAAAAAA';
        if (ini_get('mbstring.func_overload') == 7) {
            $this->assertSame(16, strlen($str));
        } else {
            $this->assertSame(16, strlen($str));
        }
        $this->assertSame(16, Core::ourStrlen($str));
        $this->assertSame(
            '',
            Core::ourSubstr($str, 16)
        );
    }

    public function testOurSubstrOutOfBorders()
    {
        // See: https://secure.php.net/manual/en/function.mb-substr.php#50275

        // We want to be like substr, so confirm that behavior.
        $this->assertSame(
            false,
            substr('abc', 5, 2)
        );

        // Confirm that mb_substr does not have that behavior.
        if (function_exists('mb_substr')) {
            if (ini_get('mbstring.func_overload') == 0) {
                $this->assertSame(
                    '',
                    \mb_substr('abc', 5, 2)
                );
            } else {
                $this->assertSame(
                    false,
                    \mb_substr('abc', 5, 2)
                );
            }
            // YES, THE BEHAVIOR OF mb_substr IS REALLY THIS INSANE!!!!
        }

        // Check if we actually have that behavior.
        $this->assertSame(
            false,
            Core::ourSubstr('abc', 5, 2)
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testOurSubstrNegativeLength()
    {
        Core::ourSubstr('abc', 0, -1);
    }

    public function testOurSubstrNegativeStart()
    {
        $this->assertSame('c', Core::ourSubstr('abc', -1, 1));
    }

    public function testOurSubstrLengthIsMax()
    {
        $this->assertSame('bc', Core::ourSubstr('abc', 1, 500));
    }
}
