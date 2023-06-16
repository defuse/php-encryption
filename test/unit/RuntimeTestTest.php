<?php

use \Defuse\Crypto\RuntimeTests;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class RuntimeTestTest extends TestCase
{
    public function testRuntimeTest()
    {
        RuntimeTests::runtimeTest();
    }
}
