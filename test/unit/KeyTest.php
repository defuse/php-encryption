<?php

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Key;

class KeyTest extends PHPUnit_Framework_TestCase
{
    public function testCreateNewRandomKey()
    {
        $key = Key::createNewRandomKey();
        $this->assertSame(32, Core::ourStrlen($key->getRawBytes()));
    }

    public function testSaveAndLoadKey()
    {
        $key1 = Key::createNewRandomKey();
        $str  = $key1->saveToAsciiSafeString();
        $key2 = Key::loadFromAsciiSafeString($str);
        $this->assertSame($key1->getRawBytes(), $key2->getRawBytes());
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\BadFormatException
     * @excpectedExceptionMessage key version header
     */
    public function testIncorrectHeader()
    {
        $key    = Key::createNewRandomKey();
        $str    = $key->saveToAsciiSafeString();
        $str[0] = 'f';
        Key::loadFromAsciiSafeString($str);
    }
}
