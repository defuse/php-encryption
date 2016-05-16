<?php

use \Defuse\Crypto\Core;

class CoreTest extends PHPUnit_Framework_TestCase
{
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
}
