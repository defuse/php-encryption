Getting The Code
=================

There are two ways to use this library in your applications. You can either:

1. Use [Composer](https://getcomposer.org/), or
2. `require_once()` a single `.phar` file in your application.

Option 1: Using Composer
-------------------------

Run this inside the directory of your composer-enabled project:

```sh
composer require defuse/php-encryption
```

Unfortunately, composer doesn't provide a way for you to verify that the code
you're getting was signed by this library's authors. If you want a more secure
option, use the `.phar` method described below.

Option 2: Including a PHAR
----------------------------

The `.phar` option lets you include this library into your project simply by
calling `require_once()` on a single file. Simply check out the tag with the
version you want, for example for version 2.0.0 you would do:

```
git checkout v2.0.0
```

You'll find the `.phar` file for that release in `dist/defuse-crypto.phar`.
Install it to somewhere on your filesystem, e.g.
`/var/www/lib/defuse-crypto.phar`. You can now use it in your code like this:

```php
<?php

    require_once('/var/www/lib/defuse-crypto.phar');

    // ... the Crypto, File, Key, and KeyProtectedByPassword classes are now
    // available ...

    // ...
```

You should verify the integrity of the `.phar`. It is signed with Taylor
Hornby's PGP key. The signature file is `dist/defuse-crypto.phar.sig`. You can
find Taylor's public key in `other/signingkey.asc.

You can verify the public key's fingerprint against the Taylor Hornby's [contact
page](https://defuse.ca/contact.htm) and
[twitter](https://twitter.com/DefuseSec/status/723741424253059074).
