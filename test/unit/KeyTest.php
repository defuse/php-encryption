<?php

use \Defuse\Crypto\Key;
use \Defuse\Crypto\Core;

class KeyTest extends PHPUnit_Framework_TestCase
{
    function testCreateNewRandomKey()
    {
        $key = Key::CreateNewRandomKey();
        $this->assertEquals(32, Core::ourStrlen($key->getRawBytes()));
    }

    function testSaveAndLoadKey()
    {
        $key1 = Key::CreateNewRandomKey();
        $str = $key1->saveToAsciiSafeString();
        $key2 = Key::LoadFromAsciiSafeString($str);
        $this->assertEquals($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\CannotPerformOperationException
     * @excpectedExceptionMessage key version header
     */
    function testIncorrectHeader()
    {
        $key = Key::CreateNewRandomKey();
        $str = $key->saveToAsciiSafeString();
        $str[0] = 'f';
        Key::LoadFromAsciiSafeString($str);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\CannotPerformOperationException
     * @expectedExceptionMessage  checksums don't match
     */
    function testIncorrectChecksum()
    {
        $key = Key::CreateNewRandomKey();
        $str = $key->saveToAsciiSafeString();
        $str[2*Key::KEY_HEADER_SIZE + 0] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 1] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 3] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 4] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 5] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 6] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 7] = 'f';
        $str[2*Key::KEY_HEADER_SIZE + 8] = 'f';
        Key::LoadFromAsciiSafeString($str);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\CannotPerformOperationException
     * @expectedExceptionMessage invalid hex encoding
     */
    function testBadHexEncoding()
    {
        $key = Key::CreateNewRandomKey();
        $str = $key->saveToAsciiSafeString();
        $str[0] = "Z";
        Key::LoadFromAsciiSafeString($str);
    }
}
