#!/usr/bin/env bash

set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
cd -P "$( dirname "$SOURCE" )/.."

OSARCH="linux/386 linux/amd64 linux/arm linux/arm64 darwin/386 darwin/amd64 windows/386 windows/amd64 freebsd/386 freebsd/amd64 freebsd/arm openbsd/386 openbsd/amd64 openbsd/arm netbsd/386 netbsd/amd64 netbsd/arm solaris/amd64"

gox -osarch="$OSARCH" \
    -ldflags="-X github.com/LeSuisse/vault-gpg-plugin/version.GitCommit='$(git rev-parse HEAD)'" \
    -output="pkg/{{.OS}}_{{.Arch}}/vault-gpg-plugin" \
    .

while IFS= read -r -d '' platform
do
    osarch=$(basename "$platform")

    pushd "$platform" >/dev/null 2>&1
    zip ../"$osarch".zip ./*
    popd >/dev/null 2>&1
done <   <(find ./pkg -mindepth 1 -maxdepth 1 -type d -print0)