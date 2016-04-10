Information for Developers of php-encryption
=============================================

Status
-------

This library is currently frozen under a long-term support release. We do not
plan to add any new features. We will maintain the library by fixing any bugs
that are reported, or security vulnerabilities that are found.

Development Environment
------------------------

Development is done on Linux. To run the tests, you will need to have the
following tools installed:

- `php` (with OpenSSL enabled, if you're compiling from source).
- `gpg`

Running the Tests
------------------

Simply run `./test.sh`. This will download a PHPUnit PHAR, verify its
cryptographic signatures, and then use it to run the tests in `test/unit`.

Reporting Bugs
---------------

Please report bugs, even critical security vulnerabilities, by opening an issue
on GitHub. We recommend disclosing security vulnerabilities found in this
library *publicly* as soon as possible.

Philosophy
-----------

This library is developed around several core values:

- Rule #1: Security is prioritized over everything else.

    > Whenever there is a conflict between security and some other property,
    > security will be favored. For example, the library has runtime tests,
    > which make it slower, but will hopefully stop it from encrypting stuff
    > if the platform it's running on is broken.

- Rule #2: It should be difficult to misuse the library.

    > We assume the developers using this library have no experience with
    > cryptography. We only assume that they know that the "key" is something
    > you need to encrypt and decrypt the messages, and that it must be kept
    > secret. Whenever possible, the library should refuse to encrypt or decrypt
    > messages when it is not being used correctly.

- Rule #3: The library aims only to be compatible with itself.

    > Other PHP encryption libraries try to support every possible type of
    > encryption, even the insecure ones (e.g. ECB mode). Because there are so
    > many options, inexperienced developers must decide whether to use "CBC
    > mode" or "ECB mode" when both are meaningless terms to them. This
    > inevitably leads to vulnerabilities.

    > This library will only support one secure mode. A developer using this
    > library will call "encrypt" and "decrypt" methods without worrying about
    > how they are implemented.

- Rule #4: The library should require no special installation.

    > Some PHP encryption libraries, like libsodium-php, are not straightforward
    > to install and cannot packaged with "just download and extract"
    > applications. This library will always be just a handful of PHP files that
    > you can copy to your source tree and require().

Publishing Releases
--------------------

TODO: add those steps here
