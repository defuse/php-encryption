# Cryptographic Message Formats

## `\Defuse\Crypto\Crypto`
 
`[____VERSION____][____HMAC____][____HKDF_SALT____][____IV____][____CIPHERTEXT____]`


### Legacy Encryption format (can only be decrypted with `legacyDecrypt()`
 
`[____HMAC____][____IV____][____CIPHERTEXT____]`

## `\Defuse\Crypto\File`

`[____VERSION____][____HKDF_SALT____][____FIRST_NONCE____][____CIPHERTEXT____][____HMAC____]`
