#!/bin/bash

set -e

current_repo_has_unsaved_changes () {
    if git diff --exit-code && ! [[ $(git clean -dfx --dry-run) ]]; then
        return 1
    else
        return 0
    fi
}

if current_repo_has_unsaved_changes; then
    echo "It's best to run this from a fresh clone."
    exit 1
fi

./other/build-phar.sh
./test.sh dist/defuse-crypto.phar
gpg -u 7B4B2D98 --armor --output dist/defuse-crypto.phar.sig --detach-sig dist/defuse-crypto.phar

git add dist
git commit -m "Automatic commit of dist/"

git -c user.signingkey=7B4B2D98 tag -s "$1" -m "$2"
