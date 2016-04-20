Class: Crypto
==============

**Purpose:** The `Crypto` class provides encryption and decryption of *strings*
either using a secret key or secret password.

Static Methods
---------------

## encrypt($plaintext, Key $key, $raw\_binary = false)

**Description:** Encrypts a plaintext string using a secret key.

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects:**

**Cautions:**

## decrypt($ciphertext, Key $key, $raw\_binary = false)

**Description:** Decrypts a ciphertext string using a secret key.

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects:**

**Cautions:**

## encryptWithPassword($plaintext, $password, $raw\_binary = false)

**Description:** Encrypts a plaintext string using a secret password.

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects:**

This function is intentionally slow. It applies key stretching to the password
in order to make password guessing attacks more computationally expensive. If
you need a faster way to encrypt multiple ciphertexts under the same password,
see the `KeyProtectedByPassword` class.

**Cautions:**

TODO: stack trace will leak password

## decryptWithPassword($ciphertext, $password, $raw\_binary = false)

**Description:** Decrypts a ciphertext string using a secret password.

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects:**

This function is intentionally slow. It applies key stretching to the password
in order to make password guessing attacks more computationally expensive. If
you need a faster way to encrypt multiple ciphertexts under the same password,
see the `KeyProtectedByPassword` class.

**Cautions:**

TODO: stack trace will leak password
    (make sure this caution goes in File too)

## legacyDecrypt($ciphertext, $key)

**Description:** Decrypts a ciphertext produced by version 1 of this library so
that the plaintext can be re-encrypted into a version 2 ciphertext. See
[Upgrading from v1.2](docs/UpgradingFromV1.2.md).

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects:**

**Cautions:**

Instance Methods
-----------------

This class has no instance methods, it only provides the static methods above.

Where's the Code?
------------------

`src/Crypto.php`
