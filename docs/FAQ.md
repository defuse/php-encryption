Frequently Asked Questions
===========================

How do I use this library to encrypt passwords?
------------------------------------------------

Passwords should not be encrypted, they should be hashed with a *slow* password
hashing function that's designed to slow down password guessing attacks. See
[How to Safely Store Your Users' Passwords in
2016](https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016).

How do I give it the same key every time instead of a new random key?
----------------------------------------------------------------------

A `Key` object can be saved to a string by calling its `saveToAsciiSafeString()`
method. You will have to save that string somewhere safe, and then load it back
into a `Key` object using `Key`'s `loadFromAsciiSafeString` static method.

Where you store the string depends on your application. For example if you are
using `KeyProtectedByPassword` to encrypt files with a user's login password,
then you should not store the `Key` at all. If you are protecting sensitive data
on a server that may be compromised, then you should store it in a hardware
security module. When in doubt, consult a security expert.

Why is an EnvironmentIsBrokenException getting thrown?
-------------------------------------------------------

Either you've encountered a bug in this library, or your system doesn't support
the use of this library. For example, if your system does not have a secure
random number generator, this library will refuse to run, by throwing that
exception, instead of falling back to an insecure random number generator.

Why am I getting a BadFormatException when loading a Key from a string?
------------------------------------------------------------------------

If you're getting this exception, then the string you're giving to
`loadFromAsciiSafeString()` is *not* the same as the string you got from
`saveToAsciiSafeString()`. Perhaps your database column isn't wide enough and
it's truncating the string as you insert it?
