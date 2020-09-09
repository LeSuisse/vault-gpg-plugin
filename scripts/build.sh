#!/usr/bin/env bash

set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
cd -P "$( dirname "$SOURCE" )/.."

SUPPORTED_ARCHES=( "linux/386" "linux/amd64" "linux/arm" "linux/arm64"
                   "darwin/amd64"
                   "windows/386" "windows/amd64"
                   "freebsd/386" "freebsd/amd64" "freebsd/arm"
                   "openbsd/386" "openbsd/amd64" "openbsd/arm"
                   "netbsd/386" "netbsd/amd64" "netbsd/arm"
                   "solaris/amd64"
                 )

for supported_arch in "${SUPPORTED_ARCHES[@]}"
do
    IFS="/" read -r -a os_arch_split <<< "$supported_arch"
    os="${os_arch_split[0]}"
    arch="${os_arch_split[1]}"
    binary_extension=""
    if [ "$os" == "windows" ]; then
        binary_extension=".exe"
    fi
    echo "Building ${supported_arch}…"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
        -ldflags="-X github.com/trishankatdatadog/vault-gpg-plugin/version.GitCommit='$(git rev-parse HEAD)'" \
        -o "pkg/${os}_${arch}/vault-gpg-plugin${binary_extension}"
done

while IFS= read -r -d '' platform
do
    osarch=$(basename "$platform")

    pushd "$platform" >/dev/null 2>&1
    sha256sum -- * > "$osarch".sha256sum
    zip ../"$osarch".zip ./*
    popd >/dev/null 2>&1
done <   <(find ./pkg -mindepth 1 -maxdepth 1 -type d -print0)