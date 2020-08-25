from hvac import adapters
from hvac import Client as VaultClient
from hvac.api.secrets_engines import SecretsEngines as VaultSecretsEngines

from .api import OpenPGP

class SecretsEngines(VaultSecretsEngines):

    implemented_classes = VaultSecretsEngines.implemented_classes + [OpenPGP]

class Client(VaultClient):

    def __init__(self, url=None, token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, adapter=adapters.JSONAdapter,
                 namespace=None, **kwargs):
        super().__init__(url=url, token=token, cert=cert, verify=verify,
            timeout=timeout, proxies=proxies, allow_redirects=allow_redirects,
            session=session, adapter=adapter, namespace=namespace, **kwargs)

        self._secrets = SecretsEngines(adapter=self._adapter)

    @property
    def secrets(self):
        return self._secrets

__all__ = (
    'Client',
)
