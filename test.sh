#!/bin/bash

echo "Normal"
echo "--------------------------------------------------"
php -d mbstring.func_overload=0 tests/runtime.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi
echo "--------------------------------------------------"

echo ""

echo "Multibyte"
echo "--------------------------------------------------"
php -d mbstring.func_overload=7 tests/runtime.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi
echo "--------------------------------------------------"

echo ""

if [ -z "$(php tests/empty.php)" ]; then
    echo "PASS: Crypto.php output is empty."
else
    echo "FAIL: Crypto.php output is not empty."
    exit 1
fi

echo "--------------------------------------------------"

echo ""

echo "Hex Encoding"
echo "--------------------------------------------------"
php tests/encode.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
else
    echo "PASS: Hex encoding is working correctly"
fi

echo "--------------------------------------------------"

echo ""

echo "Legacy Decryption"
echo "--------------------------------------------------"
php tests/legacy.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
else
    echo "PASS: Legacy decryption is working correctly"
fi

echo "--------------------------------------------------"

echo ""

echo "AES COUNTER MODE"
echo "--------------------------------------------------"
php tests/ctr.php
if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
else
    echo "PASS: Counter incrementing is working correctly"
fi

echo "--------------------------------------------------"

echo ""
ORIGDIR=`pwd`
cd tests/stream
php keygen.php
php encrypt.php
php decrypt.php
cd $ORIGDIR