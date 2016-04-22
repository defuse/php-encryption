Class: Defuse\Crypto\Crypto
============================

**Purpose:** The `Crypto` class provides encryption and decryption of *strings*
either using a secret key or secret password.

Static Methods
---------------

## Crypto::encrypt($plaintext, Key $key, $raw\_binary = false)

**Description:** Encrypts a plaintext string using a secret key.

**Parameters:**

1. `$plaintext` is the string to encrypt.
2. `$key` is an instance of `Key` containing the secret key for encryption.
3. `$raw\_binary` determines whether the output will be a byte string (true) or
  hex encoded (false, the default).

**Return value:**

Returns a ciphertext string representing `$plaintext` encrypted with the key
`$key`. Knowledge of `$key` is required in order to decrypt the ciphertext.

**Exceptions:**

- `Defuse\Crypto\Exception\EnvironmentIsBrokenException` is thrown either when
  the platform the code is running on cannot safely perform encryption for some
  reason (e.g. it lacks a secure random number generator), or the runtime tests
  detected a bug in this library.

**Side-effects and performance:**

This function has no externally-visible side-effects. It runs a fast set of
self-tests the very first time it is called, but the performance overhead is
negligible and can be safely ignored.

**Cautions:**

The ciphertext returned by this function is decryptable by anyone with knowledge
of the key `$key`. It is the caller's responsibility to keep `$key` secret.
Where `$key` should be stored is up to the caller and depends on the threat
model the caller is designing their application under. If you are unsure where
to store `$key`, consult with a professional cryptographer to get help designing
your application.

## Crypto::decrypt($ciphertext, Key $key, $raw\_binary = false)

**Description:** Decrypts a ciphertext string using a secret key.

**Parameters:**

1. `$ciphertext` is the ciphertext to be decrypted.
2. `$key` is an instance of `Key` containing the secret key for decryption.
3. `$raw\_binary` must have the same value as the `$raw\_binary` given to the
   call to `encrypt()` that generated `$ciphertext`.

**Return value:**

If the decryption succeeds, returns a string containing the same value as the
string that was passed to `encrypt()` when `$ciphertext` was produced. Upon
a successful return, the caller can be assured that `$ciphertext` could not have
been produced except by someone with knowledge of `$key`.

**Exceptions:**

- `Defuse\Crypto\Exception\EnvironmentIsBrokenException` is thrown either when
  the platform the code is running on cannot safely perform encryption for some
  reason (e.g. it lacks a secure random number generator), or the runtime tests
  detected a bug in this library.

- `Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException` is thrown if
  either the given `$key` is not the correct key for the given `$ciphertext` or
  if `$ciphertext` is not the same string as that returned by `encrypt()`, i.e.
  it was accidentally corrupted or intentionally corrupted by an attacker. There
  is no way for the caller to distinguish between these two cases.

**Side-effects and performance:**

This function has no externally-visible side-effects. It runs a fast set of
self-tests the very first time it is called, but the performance overhead is
negligible and can be safely ignored.

**Cautions:**

It is impossible in principle to distinguish between the case where you attempt
to decrypt with the wrong key and the case where you attempt to decrypt
a modified (corrupted) ciphertext. It is up to the caller how to best deal with
this ambiguity, as it depends on the application this library is being used in.
If in doubt, consult with a professional cryptographer.

## Crypto::encryptWithPassword($plaintext, $password, $raw\_binary = false)

**Description:** Encrypts a plaintext string using a secret password.

**Parameters:**

**Return value:**

**Exceptions:**

**Side-effects and performance:**

This function is intentionally slow, using a lot of CPU resources for a fraction
of a second. It applies key stretching to the password in order to make password
guessing attacks more computationally expensive. If you need a faster way to
encrypt multiple ciphertexts under the same password, see the
`KeyProtectedByPassword` class.

**Cautions:**

TODO: stack trace will leak password

## Crypto::decryptWithPassword($ciphertext, $password, $raw\_binary = false)

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

## Crypto::legacyDecrypt($ciphertext, $key)

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
