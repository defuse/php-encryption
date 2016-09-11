<?php

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Encoding;
use \Defuse\Crypto\Key;

class BackwardsCompatibilityTest extends PHPUnit_Framework_TestCase
{

	/* helper function to create a key with raw bytes */
	public function keyHelper($rawkey) {
		$key = Key::createNewRandomKey();
		$func = function ($bytes) {
				$this->key_bytes = $bytes;
		};
		$helper = $func->bindTo($key,$key);
		$helper($rawkey);
		return $key;
	}

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     * @expectedExceptionMessage invalid hex encoding
     */
    public function testDecryptLegacyWithWrongMethodStraightUpHex()
    {
        $cipher = Encoding::hexToBin(
            'cfdad83ebd506d2c9ada8d48030d0bca' .
            '2ff94760e6d39c186adb1290d6c47e35' .
            '821e262673c5631c42ebbaf70774d6ef' .
            '29aa5eee0e412d646ae380e08189c85d' .
            '024b5e2009106870f1db25d8b85fd01f' .
            /* Make it longer than the minimum length. */
            '00000000000000000000000000000000'
        );

        /* Make it try to parse the binary as hex. */
        $plain = Crypto::decrypt(
            $cipher,
            $this->keyHelper (
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" .
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            ),
            false
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     * @expectedExceptionMessage Bad version header
     */
    public function testDecryptLegacyWithWrongMethodStraightUpBinary()
    {
        $cipher = Encoding::hexToBin(
            'cfdad83ebd506d2c9ada8d48030d0bca' .
            '2ff94760e6d39c186adb1290d6c47e35' .
            '821e262673c5631c42ebbaf70774d6ef' .
            '29aa5eee0e412d646ae380e08189c85d' .
            '024b5e2009106870f1db25d8b85fd01f' .
            /* Make it longer than the minimum length. */
            '00000000000000000000000000000000'
        );

        /* This time, treat the binary as binary. */
        $plain = Crypto::decrypt(
            $cipher,
            $this->keyHelper (
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" .
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            ),
            true
        );
    }
}
