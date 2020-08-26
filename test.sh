#!/bin/bash

set -x

go build -o vault/plugins/vault-gpg-plugin main.go
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=root
vault server -dev -dev-root-token-id=$VAULT_TOKEN -dev-plugin-dir=./vault/plugins &
VAULT_PID=$!
vault login root
vault secrets enable vault-gpg-plugin
tox
TOX_RETCODE=$?
kill -2 $VAULT_PID
echo "Return code: $TOX_RETCODE"
exit $TOX_RETCODE
