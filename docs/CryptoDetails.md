Cryptography Details
=====================

Here is a high-level description of how this library works. Any discrepancy
between this documentation and the actual implementation will be considered
a security bug.

Let's start with the following definitions:

- HKDF-SHA256(*k*, *n*, *info*, *salt*) is the key derivation function specified
  in RFC 5869 (using SHA256 as the hash function) where *k* is the initial
  keying material, *n* is the number of output bytes, *info* is the info string,
  and *salt* is the salt.
- AES-256-CTR(*m*, *key*, *iv*) is the encryption of *m* with AES-256 in CTR
  mode using key *key* and initialization vector *iv*.
- PBKDF2-SHA256(*p*, *s*, *i*, *n*) is PBKDF2 using *i* iterations of the
  hash function SHA256 on the password *p* and salt *s*, outputting *n* bytes.
- VERSION is the string `"\xDE\xF5\x02\x00"`.
- AUTHINFO is the string `"DefusePHP|V2|KeyForAuthentication"`.
- ENCRINFO is the string `"DefusePHP|V2|KeyForEncryption"`.

To encrypt a message *m* using a 32-byte key *k*, the following steps are taken:

1. Generate a random 32-byte string *salt*.
2. Derive the 32-byte authentication key *akey* = HKDF-SHA256(*k*, 32, AUTHINFO, *salt*).
3. Derive the 32-byte encryption key *ekey* = HKDF-SHA256(*k*, 32, ENCRINFO, *salt*).
4. Generate a random 16-byte initialization vector *iv*.
5. Compute *c* = AES-256-CTR(*m*, *ekey*, *iv*).
6. Combine *ctxt* = VERSION || *salt* || *iv* || *c*.
7. Compute *h* = HMAC-SHA256(*ctxt*, *akey*).
8. Output *ctxt* || *h*.

Decryption is roughly the reverse process (see the code for details). The HMAC
is verified before *c* is decrypted.

For encryption using a password *p*, steps 1-3 above are replaced with:

1. Generate a random 32-byte string *salt*.
2. Compute *k* = PBKDF2-SHA256(*p*, *salt*, 100000, 32).
3. Derive the 32-byte authentication key *akey* =
   HKDF-SHA256(*k*, 32, "DefusePHP|V2|KeyForAuthentication", *salt*).
4. Derive the 32-byte encryption key *ekey* =
   HKDF-SHA256(*k*, 32, "DefusePHP|V2|KeyForEncryption", *salt*).

The remainder of the process is the same. Notice the reuse of the same *salt*
for PBKDF2 and HKDF-SHA256.

