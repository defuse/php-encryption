This library was created after noticing how much insecure PHP encryption code
there is. I once did a Google search for "php encryption" and found insecure
code or advice on 9 of the top 10 results.

Encryption is becoming an essential component of modern websites. This library
aims to fulfil a subset of that need: Authenticated symmetric encryption of
short strings, given a random key.

This library is developed around several core values:

    Rule #1: Security is prioritized over everything else.

        Whenever there is a conflict between security and some other property,
        security will be favored. For example, the library has mandatory runtime
        tests, which make it slower, but increase security.

    Rule #2: It should be extremely difficult to misuse the library.

        We assume the developers using this library have no experience with
        cryptography. We only assume that they know that the "key" is something
        you need to encrypt and decrypt the messages, and that it must be
        protected. Whenever possible, the library should refuse to encrypt or
        decrypt messages when it is not being used correctly.

    Rule #3: The library aims only to be compatible with itself.

        Other PHP encryption libraries try to support every possible type of
        encryption, even the insecure ones (e.g. ECB mode). Because there are so
        many options, inexperienced developers must make decisions between
        things like "CBC" mode and "ECB" mode, knowing nothing about either one,
        which inevitably creates to vulnerabilities.

        This library will only support one secure mode. A developer using this
        library will call "encrypt" and "decrypt" not caring about how they are
        implemented.

    Rule #4: The library should consist of a single PHP file and nothing more.

        Some PHP encryption libraries, like libsodium [1], are not
        straightforward to install and cannot packaged with "just download and
        extract" applications. This library will always be one PHP file that you
        can place in your source tree and require().

References:

    [1] https://github.com/jedisct1/libsodium-php
