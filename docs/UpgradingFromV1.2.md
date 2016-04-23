Upgrading From Version 1.2
===========================

With version 2.0.0 of this library came major changes to the ciphertext format
and algorithms used for encryption. In order to decrypt ciphertexts made by
version 1.2 of this library, you need call the special `legacyDecrypt()`
method and then re-encrypt the data to get a version 2.0.0 ciphertext. Your
upgrade code would look something like this:

```php
<?php

    // ...

    $legacy_ciphertext = // ... get the ciphertext you want to upgrade ...
    $legacy_key = // ... get the key to decrypt this ciphertext ...

    // Generate the new key that we'll re-encrypt the ciphertext with.
    $new_key = Key::createNewRandomKey();
    // ... save it somewhere ...

    // Decrypt it.
    $plaintext = Crypto::legacyDecrypt($legacy_ciphertext, $legacy_key);

    // Re-encrypt it.
    $new_ciphertext = Crypto::encrypt($plaintext, $new_key);

    // ... replace the old $legacy_ciphertext with the new $new_ciphertext

    // ...
```
