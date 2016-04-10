Tutorial
=========

Hello! If you're reading this file, it's because you want to add encryption to
one of your PHP projects. My job, as the person writing this documentation, is
to help you make sure you're doing the right thing and then show you how to use
this library to do it. To help me help you, please read the documentation
*carefully* and *deliberately*.

A Word of Caution
------------------

Encryption is not like a magic dust you can sprinkle on a system to make it more
secure. The way encryption is incorporated into a system's design needs to be
carefully thought through. Sometimes, encryption is the wrong thing to use.
Other times, encryption needs to be used in a very specific way in order for it
to work as intended. Even if you are sure of what you are doing, we strongly
recommend seeking advice from an expert.

**This isn't for storing passwords:** The most common thing web applications do
is protect their users passwords. If you're trying to use this library to
"encrypt" your users' passwords, you're in the wrong place. Passwords shouldn't
be *encrypted*, they should be *hashed* with a slow computation-heavy function
that makes password guessing attacks more expensive. See [How to Safely Store
Your Users' Passwords in
2016](https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016).

**This isn't for encrypting network communication:** Likewise, if you're trying
to encrypt messages sent between two parties over the internet, you don't want
to be using this library. For that, set up a TLS connection between the two
points, or, if it's a chat app, use the [Signal
Protocol](https://whispersystems.org/blog/advanced-ratcheting/).

This library provides symmetric encryption for "data at rest." This means it is
not suitable for use in building protocols where "data is in motion" (i.e. over
a network) except in a very restricted set of cases.

Getting the Code
-----------------

There are several different ways to obtain this library's code and to add it to
your project. Even if you've already cloned the code from GitHub, you should
take steps to verify the cryptographic signatures, to make sure the code you got
was not intercepted and modified by an attacker.

See the [Installing and Verifying](docs/InstallingAndVerifying.md)
documentation.

Using the Library
------------------

### Encryption 101



The following "stereotypes" are example scenarios where this library can be
used.

### Formal Documentation

The following classes are available for you to use:

- [Crypto](docs/classes/Crypto.md)
- [File](docs/classes/File.md)
- [Key](docs/classes/Key.md)
- [KeyProtectedByPassword](docs/classes/KeyProtectedByPassword.md)

### Stereotype #1: Encrypting data in a remote database

### Stereotype #2: A tool for encrypting files with a password

### Stereotype #3: Encrypting account data with the user's login password

TODO: note the fact that they have to re-encrypt all data upon a password change

Getting Help
-------------

If you're having difficulty using the library, see if your problem has already
been solved in the [Troubleshooting](docs/Troubleshooting.md) answers.
