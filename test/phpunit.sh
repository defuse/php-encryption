#!/usr/bin/env bash

# This was written by Scott Arciszewski. I copied it from his Halite project:
# https://github.com/paragonie/halite

origdir=`pwd`
cdir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $origdir
parentdir="$(dirname $cdir)"
PHP_VERSION=$(php -r "echo PHP_VERSION_ID;");

clean=0 # Clean up?
gpg --fingerprint D8406D0D82947747293778314AA394086372C20A
if [ $? -ne 0 ]; then
    echo -e "\033[33mDownloading PGP Public Key...\033[0m"
    gpg --import test/phpunit-pubkey.asc
    # Sebastian Bergmann <sb@sebastian-bergmann.de>
    gpg --fingerprint D8406D0D82947747293778314AA394086372C20A
    if [ $? -ne 0 ]; then
        echo -e "\033[31mCould not download PGP public key for verification\033[0m"
        exit 1
    fi
fi

if [ "$clean" -eq 1 ]; then
    # Let's clean them up, if they exist
    if [ -f phpunit.phar ]; then
        rm -f phpunit.phar
    fi
    if [ -f phpunit.phar.asc ]; then
        rm -f phpunit.phar.asc
    fi
fi

# Let's grab the latest release and its signature
phpunitversion=$([ $PHP_VERSION -ge 80100 ] && echo "10" || ([ $PHP_VERSION -ge 70200 ] && echo "8" || echo "5"))
if [ ! -f phpunit.phar ]; then
    wget -O phpunit.phar https://phar.phpunit.de/phpunit-$phpunitversion.phar
fi
if [ ! -f phpunit.phar.asc ]; then
    wget -O phpunit.phar.asc https://phar.phpunit.de/phpunit-$phpunitversion.phar.asc
fi

# What are the major/minor versions?
# php -r "var_dump([\Sodium\library_version_major(), \Sodium\library_version_minor()]);"

# Verify before running
gpg --verify phpunit.phar.asc phpunit.phar
if [ $? -eq 0 ]; then
    echo
    if [ "$2" -eq "1" ]; then
        COVERAGE1_ARGS="--coverage-clover=$parentdir/coverage1.xml"
        COVERAGE2_ARGS="--coverage-clover=$parentdir/coverage2.xml"
    else
        COVERAGE1_ARGS=""
        COVERAGE2_ARGS=""
    fi
    echo -e "\033[33mBegin Unit Testing\033[0m"
    # Run the test suite with normal func_overload.
    php -d mbstring.func_overload=0 phpunit.phar -c "$parentdir/test/phpunit-$phpunitversion.xml" $COVERAGE1_ARGS --bootstrap "$parentdir/$1" "$parentdir/test/unit" && \
    # Run the test suite again with funky func_overload.
    # This is deprecated in PHP 7 and PHPUnit is no longer compatible with the options.
    if [[ $PHP_VERSION -le 50600 ]]; then
        php -d mbstring.func_overload=7 phpunit.phar -c "$parentdir/test/phpunit-$phpunitversion.xml" $COVERAGE2_ARGS --bootstrap "$parentdir/$1"  "$parentdir/test/unit"
    fi
    EXITCODE=$?
    # Cleanup
    if [ "$clean" -eq 1 ]; then
        echo -e "\033[32mCleaning Up!\033[0m"
        rm -f phpunit.phar
        rm -f phpunit.phar.asc
    fi
    exit $EXITCODE
else
    echo
    chmod -x phpunit.phar
    mv phpunit.phar /tmp/bad-phpunit.phar
    mv phpunit.phar.asc /tmp/bad-phpunit.phar.asc
    echo -e "\033[31mSignature did not match! Check /tmp/bad-phpunit.phar for trojans\033[0m"
    exit 1
fi
