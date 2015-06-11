php-encryption
===============

[![Build Status](https://travis-ci.org/defuse/php-encryption.svg?branch=master)](https://travis-ci.org/defuse/php-encryption)

This is a class for doing symmetric encryption in PHP. **Requires PHP 5.4 or newer.**

Implementation
--------------

Messages are encrypted with AES-128 in CBC mode and are authenticated with
HMAC-SHA256 (Encrypt-then-Mac). PKCS7 padding is used to pad the message to
a multiple of the block size. HKDF is used to split the user-provided key into
two keys: one for encryption, and the other for authentication. It is
implemented using the `openssl_` and `hash_hmac` functions.

Audit Status
-------------

This code has not been subjected to a formal, paid, security audit. However, it
has received some informal review from members of the PHP security community.

As the author of this library, I take security very seriously and always opt to
not implement a feature unless I am confident that I can do so without
introducing security bugs. I take particular care to ensure the library is hard
to use in an insecure way, even by someone who is not experienced in
cryptography.

This library considers many edge cases that most PHP encryption libraries do not
handle correctly. In all likelihood, you are safer using this library than
almost any other encryption library for PHP.

If you use this library as a part of your business and would like to fund (or
help fund) a formal audit, I would be very grateful.

Philosophy
-----------

This library was created after noticing how much insecure PHP encryption code
there is. I once did a Google search for "php encryption" and found insecure
code or advice on 9 of the top 10 results.

Encryption is becoming an essential component of modern websites. This library
aims to fulfil a subset of that need: Authenticated symmetric encryption of
short strings, given a random key.

This library is developed around several core values:

- Rule #1: Security is prioritized over everything else.

    > Whenever there is a conflict between security and some other property,
    > security will be favored. For example, the library has runtime tests,
    > which make it slower, but will hopefully stop it from encrypting stuff
    > if the platform it's running on is broken.

- Rule #2: It should be difficult to misuse the library.

    > We assume the developers using this library have no experience with
    > cryptography. We only assume that they know that the "key" is something
    > you need to encrypt and decrypt the messages, and that it must be
    > protected. Whenever possible, the library should refuse to encrypt or
    > decrypt messages when it is not being used correctly.

- Rule #3: The library aims only to be compatible with itself.

    > Other PHP encryption libraries try to support every possible type of
    > encryption, even the insecure ones (e.g. ECB mode). Because there are so
    > many options, inexperienced developers must make decisions between
    > things like "CBC" mode and "ECB" mode, knowing nothing about either one,
    > which inevitably creates vulnerabilities.

    > This library will only support one secure mode. A developer using this
    > library will call "encrypt" and "decrypt" not caring about how they are
    > implemented.

- Rule #4: The library should require no special installation.

    > Some PHP encryption libraries, like libsodium-php [1], are not
    > straightforward to install and cannot packaged with "just download and
    > extract" applications. This library will always be just a handful of PHP
    > files that you can copy to your source tree and require().

References:

    [1] https://github.com/jedisct1/libsodium-php

Authors
---------

This library is authored by Taylor Hornby and Scott Arciszewski.
