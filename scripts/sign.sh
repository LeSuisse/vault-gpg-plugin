#! /usr/bin/env nix-shell
#! nix-shell --pure ../shell.nix -i bash

set -euxo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
cd -P "$( dirname "$SOURCE" )/../pkg"

gpg -u FFCBD29F3AFED453AE4B9E321D40FBA29EB39616 --armor  --export --export-options export-minimal > public.key
find . -name '*.zip' -exec gpg --armor --detach-sign {} \;
find . -name '*.zip' -exec rekor-cli upload --artifact {} --signature {}.asc --public-key public.key \;
