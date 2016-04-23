php-encryption
===============

[![Build Status](https://travis-ci.org/defuse/php-encryption.svg?branch=master)](https://travis-ci.org/defuse/php-encryption)

This is a class for doing symmetric encryption in PHP. **Requires PHP 5.4 or newer.**

Implementation
--------------

Messages are encrypted with AES-256 in CTR mode and are authenticated with
HMAC-SHA256 (Encrypt-then-Mac). HKDF is used to split the user-provided key into
two keys: one for encryption, and the other for authentication. It is
implemented using the `openssl_` and `hash_hmac` functions.

## Installing this Library

### Using Composer

```sh
composer require defuse/php-encryption
```

### Direct Installation (Phar)

Download the PHP Archive and public key. Place both of them in the same directory (e.g. `vendor/defuse/php-encryption.phar` and `vendor/defuse/php-encryption.phar.pubkey`).

Then, just add this line and you're golden:

```php
require_once "vendor/defuse/php-encryption.phar";
```

### Direct Installation (Manual)

Download the [latest release](https://github.com/defuse/php-encryption/releases). Extract all of the files into a directory on your webserver (e.g. `/var/www/lib/defuse/php-encryption`).

Then add this to your PHP scripts:

```php
require '/var/www/lib/defuse/php-encryption/autoload.php';
```

## Using this Library

1. Generate and store an encryption key.
2. Encrypt plaintext strings with your key to obtain ciphertext, using `Crypto`.
3. Decrypt ciphertext strings with your key to obtain plaintext, using `Crypto`.
4. Encrypt/decrypt files with your key, using `File`.

### Generate and Store an Encryption Key

Generate a new key:

```php
$key = \Defuse\Crypto\Key::createNewRandomKey();
````

The above command will generate a random encryption key, using a 
cryptographically secure pseudorandom number generator. This will generally only
need to be done *once* if you need to reuse this key for multiple messages.

```php
$encryptionKeyDataForStorage = $key->saveToAsciiSafeString()
```

This returns an encoded string that you can use to persist a key across multiple
runs of the application. You might decide to copy it to a configuration file
not tracked by Git, for example. To load it again on the next script execution,
just do this:

```php
$key = \Defuse\Crypto\Key::LoadFromAsciiSafeString($storedKeyData);
```

### Encrypting Strings

Once you have a `Key` object, you're ready to encrypt data. All you have to do
is pass your desired string and the `Key` object to `Crypto::encrypt()`.

```php
try {
    $ciphertext = \Defuse\Crypto\Crypto::encrypt("Test message", $key);
} catch (\Defuse\Crypto\Exception\CryptoTestFailedException $ex) {
    die("Our platform is not secure enough to use this cryptography library.");
}
```

### Decrypting Strings

If encryption made sense, then the decryption API should be intuitive and
precisely what you expect it to be:

```php
try {
    $plaintext = \Defuse\Crypto\Crypto::decrypt($ciphertext, $key);
} catch (\Defuse\Crypto\Exception\CryptoTestFailedException $ex) {
    die("Our platform is not secure enough to use this cryptography library.");
} catch (\Defuse\Crypto\Exception\InvalidCiphertextException $ex) {
    die("Ciphertext was modified in transit.");
}
```

### Interlude: A Complete Example

First, generate a key and store it:

```php
<?php
require_once "/path/to/defuse/php-encryption/autoload.php';
$key = \Defuse\Crypto\Key::createNewRandomKey();
file_put_contents('shared_key.txt', $key->saveToAsciiSafeString());
```

The two scripts below, `encrypt_msg.php` and `decrypt_msg.php` are command-line
PHP scripts meant to encrypt/decrypt messages using a pre-shared-key.

Sender:

```php
<?php
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
require_once "/path/to/defuse/php-encryption/autoload.php';

$keyData = file_get_contents('shared_key.txt');
$key = Key::LoadFromAsciiSafeString($keyData);

$encrypted = Crypto::encrypt($argv[1], $key);
echo $encrypted, "\n";
```

Receiver:

```php
<?php
use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
require_once "/path/to/defuse/php-encryption/autoload.php';

$keyData = file_get_contents('shared_key.txt');
$key = Key::LoadFromAsciiSafeString();

$decrypted = Crypto::decrypt($argv[1], $key);
echo $decrypted, "\n";
```

If you run this command:

    php decrypt_msg.php `php encrypt_msg.php It\ Works\!`

It will print "It works!" into your console. Now, assuming you and your 
recipient have the same `shared-key.txt`, you can send messages to/from them and
only they should be able to decrypt them.

### Encrypting and Decrypting Files

In addition to our standard `Crypto::encrypt()` and `Crypto::decrypt()` 
interface, this library has a separate class for encrypting/decrypting files.

This is mostly useful for encrypting large files (say, 1.5 GB) on a machine with
very low memory usage (say, a maximum of 64 MB of RAM).

```php
\Defuse\Crypto\File::encryptFile($inputFilename, $outputFilename, $key);
\Defuse\Crypto\File::decryptFile($encryptedFile, $plaintextFile, $key);
```

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

    > Some PHP encryption libraries, like [libsodium-php](https://github.com/jedisct1/libsodium-php),
    > are not straightforward to install and cannot packaged with "just download
    > and extract" applications. This library will always be just a handful of
    > PHP files that you can copy to your source tree and require().

Authors
---------

This library is authored by [Taylor Hornby](https://bqp.io) and [Scott Arciszewski](https://paragonie.com/blog/author/scott-arciszewski).
