  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API module."""

from hvac import exceptions, utils
from hvac.api.secrets_engines.transit import Transit
from .constants import ALLOWED_KEY_TYPES
from .exceptions import UnsupportedParam

DEFAULT_MOUNT_POINT = 'vault-gpg-plugin'

class OpenPGP(Transit):
    """Transit-Secrets-Engine-like (API).
    Reference: https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html
    """

    # TODO: Name, comment, email.
    def create_key(self, name, convergent_encryption=None, derived=None, exportable=None, allow_plaintext_backup=None,
                   key_type=None, mount_point=DEFAULT_MOUNT_POINT):
        # Unsupported parameters. 
        if convergent_encryption:
            raise UnsupportedParam('convergent encryption not supported')
        if derived:
            raise UnsupportedParam('key derivation not supported')
        if exportable:
            raise UnsupportedParam('exportable keys not supported')
        if allow_plaintext_backup:
            raise UnsupportedParam('plaintext key backups not supported')

        # Allowed key types: only particular sizes of RSA.
        if key_type is None or key_type not in ALLOWED_KEY_TYPES:
            error_msg = 'invalid key_type argument provided "{arg}", supported types: "{allowed_types}"'
            raise exceptions.ParamValidationError(error_msg.format(
                arg=key_type,
                allowed_types=', '.join(ALLOWED_KEY_TYPES),
            ))

        # JSON parameters to the plugin.
        # Note: we ignore the key-type, as we assume only RSA keys.
        _, key_bits = key_type.split('-')
        params = {
            'comment': '',
            'email': '',
            'exportable': False,
            'generate': True,
            'key_bits': key_bits,
            'name': name,
            'real_name': '',
        }

        # The actual call to the plugin.
        api_path = utils.format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def list_keys(self, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def delete_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def update_key_configuration(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                                 exportable=None, allow_plaintext_backup=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def rotate_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def export_key(self, name, key_type, version=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def encrypt_data(self, name, plaintext, context=None, key_version=None, nonce=None, batch_input=None, type=None,
                     convergent_encryption=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def decrypt_data(self, name, ciphertext, context=None, nonce=None, batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def rewrap_data(self, name, ciphertext, context=None, key_version=None, nonce=None, batch_input=None,
                    mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_data_key(self, name, key_type, context=None, nonce=None, bits=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_random_bytes(self, n_bytes=None, output_format=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def hash_data(self, hash_input, algorithm=None, output_format=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_hmac(self, name, hash_input, key_version=None, algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def sign_data(self, name, hash_input, key_version=None, hash_algorithm=None, context=None, prehashed=None,
                  signature_algorithm=None, marshaling_algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def verify_signed_data(self, name, hash_input, signature=None, hmac=None, hash_algorithm=None, context=None,
                           prehashed=None, signature_algorithm=None, marshaling_algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def backup_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def restore_key(self, backup, name=None, force=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def trim_key(self, name, min_version, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError
