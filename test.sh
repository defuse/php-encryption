#!/bin/bash
set -e
./test/phpunit.sh
echo ""
ORIGDIR=`pwd`
cd test/stream
php keygen.php
php encrypt.php
php decrypt.php
cd $ORIGDIR
