#!/bin/bash
set -e

BIG_GENERATED_FILE=./test/unit/File/big-generated-file
if [ ! -e $BIG_GENERATED_FILE ] || [ $(wc -c < $BIG_GENERATED_FILE) -ne "209715200" ]; then
    echo "Please wait while I create a large random test plaintext file..."
    dd if=/dev/urandom "of=$BIG_GENERATED_FILE" bs=1M count=200
fi

if [ -n "$1" ]; then
    BOOTSTRAP="$1"
else
    BOOTSTRAP="autoload.php"
fi

./test/phpunit.sh "$BOOTSTRAP"
echo ""
