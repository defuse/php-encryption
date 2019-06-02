#!/bin/sh
set -e

BIG_GENERATED_FILE=./test/unit/File/big-generated-file
if [ ! -e $BIG_GENERATED_FILE ] || [ $(wc -c < $BIG_GENERATED_FILE) -ne "209715200" ]; then
    echo "Please wait while I create a large random test plaintext file..."
    dd if=/dev/urandom "of=$BIG_GENERATED_FILE" bs=1M count=200
fi

if [ -f "$1" ]; then
    BOOTSTRAP="$1"
    MEASURECOVERAGE="0"
else
    # You need to run `composer install` to generate this file.
    BOOTSTRAP="vendor/autoload.php"
    MEASURECOVERAGE="1"
fi

if [ "$2" == "fast" ]; then
    EXCLUDE_SLOW="1"
else
    EXCLUDE_SLOW="0"
fi

# loading bootstrap should output nothing
load=$(php -r "require '$BOOTSTRAP';")
test -z "$load"

./test/phpunit.sh "$BOOTSTRAP" "$MEASURECOVERAGE" "$EXCLUDE_SLOW"
echo ""
