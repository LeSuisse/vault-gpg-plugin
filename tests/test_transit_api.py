  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API test module."""

import os
import unittest

from hvac.exceptions import ParamValidationError
from vault_gpg_transit import Client
from vault_gpg_transit.constants import ALLOWED_KEY_TYPES
from vault_gpg_transit.exceptions import UnsupportedParam

class TestOpenPGP(unittest.TestCase):

  def setUp(self):
    self.c = Client(os.environ['VAULT_ADDR'], os.environ['VAULT_TOKEN'])

  def test_create_key(self):
    name = 'test-key'

    # Unsupported parameters.
    self.assertRaises(UnsupportedParam, self.c.secrets.openpgp.create_key, name, allow_plaintext_backup=True)
    self.assertRaises(UnsupportedParam, self.c.secrets.openpgp.create_key, name, convergent_encryption=True)
    self.assertRaises(UnsupportedParam, self.c.secrets.openpgp.create_key, name, derived=True)
    self.assertRaises(UnsupportedParam, self.c.secrets.openpgp.create_key, name, exportable=True)

    # No key type.
    self.assertRaises(ParamValidationError, self.c.secrets.openpgp.create_key, name)

    # Allowed key types.
    for key_type in ALLOWED_KEY_TYPES:
      r = self.c.secrets.openpgp.create_key(name, key_type=key_type)
      r.raise_for_status()

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()