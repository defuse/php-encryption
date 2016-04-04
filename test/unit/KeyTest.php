<?php

use \Defuse\Crypto\Key;
use \Defuse\Crypto\Core;

class KeyTest extends PHPUnit_Framework_TestCase
{
    function testCreateNewRandomKey()
    {
        $key = Key::CreateNewRandomKey();
        $this->assertSame(32, Core::ourStrlen($key->getRawBytes()));
    }

    function testSaveAndLoadKey()
    {
        $key1 = Key::CreateNewRandomKey();
        $str = $key1->saveToAsciiSafeString();
        $key2 = Key::LoadFromAsciiSafeString($str);
        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
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
        $str[2*Core::SERIALIZE_HEADER_BYTES + 0] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 1] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 3] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 4] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 5] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 6] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 7] = 'f';
        $str[2*Core::SERIALIZE_HEADER_BYTES + 8] = 'f';
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
