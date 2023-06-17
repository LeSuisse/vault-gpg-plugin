package gpg

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/locksutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory gives a configured logical.Backend for the GPG plugin
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns an instance of the backend for the GPG plugin
func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,
		Paths: []*framework.Path{
			pathKeys(&b),
			pathListKeys(&b),
			pathExportKeys(&b),
			pathSign(&b),
			pathVerify(&b),
			pathDecrypt(&b),
			pathShowSessionKey(&b),
			pathConfig(&b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"key/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	b.keyLocks = locksutil.CreateLocks()
	b.transparencyLogClient = &RekorClient{}
	return &b
}

type backend struct {
	*framework.Backend
	keyLocks              []*locksutil.LockEntry
	transparencyLogClient TransparencyLogClient
}

const backendHelp = `
The GPG backend handles GPG operations on data in-transit.
Data sent to the backend are not stored.
`
