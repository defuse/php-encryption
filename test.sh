#!/bin/sh
set -e

BIG_GENERATED_FILE=./test/unit/File/big-generated-file
if [ ! -e $BIG_GENERATED_FILE ] || [ $(wc -c < $BIG_GENERATED_FILE) -ne "209715200" ]; then
    echo "Please wait while I create a large random test plaintext file..."
    dd if=/dev/urandom "of=$BIG_GENERATED_FILE" bs=1M count=200
fi

if [ -n "$1" ]; then
    BOOTSTRAP="$1"
else
    # You need to run `composer install` to generate this file.
    BOOTSTRAP="vendor/autoload.php"
fi

# loading bootstrap should output nothing
load=$(php -r "require '$BOOTSTRAP';")
test -z "$load"

./test/phpunit.sh "$BOOTSTRAP"
echo ""
