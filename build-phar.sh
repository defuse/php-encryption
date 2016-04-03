#!/usr/bin/env bash

basedir=$( dirname $( readlink -f ${BASH_SOURCE[0]} ) )

cp ./autoload.php ./src/index.php
sed -i "s/__DIR__.'\/src\/'/'phar:\/\/defuse-crypto.phar\/'/" ./src/index.php

php -dphar.readonly=0 "$basedir/other/build_phar.php" $*

rm ./src/index.php
