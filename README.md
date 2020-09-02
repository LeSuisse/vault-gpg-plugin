# Vault Plugin: GPG Secret Backend [![Build Status](https://github.com/LeSuisse/vault-gpg-plugin/workflows/CI/badge.svg)](https://github.com/LeSuisse/vault-gpg-plugin/actions?query=workflow%3ACI) [![Code coverage](https://codecov.io/gh/LeSuisse/vault-gpg-plugin/branch/master/graph/badge.svg)](https://codecov.io/gh/LeSuisse/vault-gpg-plugin)

This is a standalone plugin for [HashiCorp Vault](https://www.github.com/hashicorp/vault).
This plugin handles GPG operations on data-in-transit in a similar fashion to what the
[transit secret backend](https://www.vaultproject.io/docs/secrets/transit) proposes.
Data sent to the backend are not stored.

As of today, the backend does not support encrypting data.

This backend has similar use cases with the [transit secret backend](https://www.vaultproject.io/docs/secrets/transit)
and the latter should be preferred if you do not need to interact with existing tools that are only GPG-aware.

## Usage & setup

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html), you need to have a working installation
of Vault to use it.

To learn how to use plugins with Vault, see the [documentation on plugin backends](https://www.vaultproject.io/docs/plugin)
on the official Vault website. You can download and decompress the pre-compiled plugin binary for your architecture
from the [latest release on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases). SHA256 checksum for the
pre-compiled plugin binary is also provided in the archive so it can be registered to your Vault plugin catalog.

All archives available from the [release tab on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases) come with
a GPG signature made with the GPG key [`FFCB D29F 3AFE D453 AE4B 9E32 1D40 FBA2 9EB3 9616`](https://sks-keyservers.net/pks/lookup?op=get&search=0xFFCBD29F3AFED453AE4B9E321D40FBA29EB39616).

Once mounted in Vault, this plugin exposes [this HTTP API](docs/http-api.md).
