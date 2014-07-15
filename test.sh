#!/bin/bash

echo "Normal"
echo "--------------------------------------------------"
php tests/runtime.php
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
