<?php

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Encoding;
use \Defuse\Crypto\Key;

class BackwardsCompatibilityTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @expectedExceptionMessage insecure fallback
     */
    function testDecryptLegacyWithWrongMethodWithHacks()
    {
        /* Hack the legacy ciphertext to be in the new hex format and to even
         * start with the legacy version header.*/
        $cipher = Encoding::binToHex(Core::LEGACY_VERSION) .
            'cfdad83ebd506d2c9ada8d48030d0bca'.
            '2ff94760e6d39c186adb1290d6c47e35'.
            '821e262673c5631c42ebbaf70774d6ef'.
            '29aa5eee0e412d646ae380e08189c85d'.
            '024b5e2009106870f1db25d8b85fd01f';

        /* Give it the best chance of succeeding by even using the correct key. */
        $plain = Crypto::decrypt(
            $cipher,
            /* You should NEVER use 'Key' this way, except for testing */
            Key::LoadFromRawBytesForTestingPurposesOnlyInsecure(
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            )
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @expectedExceptionMessage invalid hex encoding
     */
    function testDecryptLegacyWithWrongMethodStraightUpHex()
    {
        $cipher = Encoding::hexToBin(
            'cfdad83ebd506d2c9ada8d48030d0bca'.
            '2ff94760e6d39c186adb1290d6c47e35'.
            '821e262673c5631c42ebbaf70774d6ef'.
            '29aa5eee0e412d646ae380e08189c85d'.
            '024b5e2009106870f1db25d8b85fd01f'
        );

        /* Make it try to parse the binary as hex. */
        $plain = Crypto::decrypt(
            $cipher,
            Key::LoadFromRawBytesForTestingPurposesOnlyInsecure(
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            ),
            false
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @expectedExceptionMessage bad magic number
     */
    function testDecryptLegacyWithWrongMethodStraightUpBinary()
    {
        $cipher = Encoding::hexToBin(
            'cfdad83ebd506d2c9ada8d48030d0bca'.
            '2ff94760e6d39c186adb1290d6c47e35'.
            '821e262673c5631c42ebbaf70774d6ef'.
            '29aa5eee0e412d646ae380e08189c85d'.
            '024b5e2009106870f1db25d8b85fd01f'
        );

        /* This time, treat the binary as binary. */
        $plain = Crypto::decrypt(
            $cipher,
            Key::LoadFromRawBytesForTestingPurposesOnlyInsecure(
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            ),
            true
        );
    }

    function tooSmallVersionNumberProvider()
    {
        /* We produce pairs where (major, minor) is a lesser version than
            (min_major, min_minor). */
        $badpairs = array();

        for ($major = 0; $major <= 10; $major++) {
            for ($minor = 0; $minor <= 10; $minor++) {

                /* All versions smaller, by major version number (same minor). */
                for ($min_major = 0; $min_major < $major; $min_major++) {
                    $badpairs[] = array(
                        $min_major,
                        $minor,
                        $major,
                        $minor
                    );
                }

                /* All versions smaller, by major version number (bigger minor). */
                for ($min_major = 0; $min_major < $major; $min_major++) {
                    $badpairs[] = array(
                        $min_major,
                        $minor+1,
                        $major,
                        $minor
                    );
                }

                /* All versions smaller, by minor, within the same major. */
                for ($min_minor = 0; $min_minor < $minor; $min_minor++) {
                    $badpairs[] = array(
                        $major,
                        $min_minor,
                        $major,
                        $minor
                    );
                }
            }
        }

        return $badpairs;
    }

    /**
     * @dataProvider tooSmallVersionNumberProvider
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @expectedExceptionMessage insecure fallback
     */
    function testVersionNumberComparisonTooSmall($major, $minor, $min_major, $min_minor)
    {
        /* $h2 is a smaller version than $h1, so it should fail. */
        $h1 = Core::HEADER_MAGIC . chr($major) . chr($minor);
        $h2 = Core::HEADER_MAGIC . chr($min_major) . chr($min_minor);
        Crypto::getVersionConfigFromHeader($h1, $h2);
    }

    function unsupportedVersionProvider()
    {
        /* We currently only support: (1, 0), and (2, 0). */
        return array(
            array(0, 0),
            array(0, 1),
            array(1, 1),
            array(1, 2),
            array(2, 1),
            array(2, 2),
            array(3, 0),
            array(4, 0),
            array(255, 0),
            array(255, 255)
        );
    }

    /**
     * @dataProvider unsupportedVersionProvider
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @expectedExceptionMessage Unsupported ciphertext version
     */
    function testUnsupportedVersion($major, $minor)
    {
        $header = Core::HEADER_MAGIC . chr($major) . chr($minor);
        Crypto::getVersionConfigFromHeader($header, $header);
    }

}
