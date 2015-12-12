#!/bin/bash
set -e
echo "Please wait while I create a large random test plaintext file..."
dd if=/dev/urandom of=./test/unit/File/big-generated-file bs=1M count=200
echo "Now running the tests..."
./test/phpunit.sh
echo ""
