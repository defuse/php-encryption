<?php

use \Defuse\Crypto\Core;
use \Defuse\Crypto\Key;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class KeyTest extends TestCase
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

    public function testIncorrectHeader()
    {
        $key    = Key::createNewRandomKey();
        $str    = $key->saveToAsciiSafeString();
        $str[0] = 'f';
        $this->expectException(\Defuse\Crypto\Exception\BadFormatException::class);
        $this->expectExceptionMessage('Invalid header.');
        Key::loadFromAsciiSafeString($str);
    }
}
