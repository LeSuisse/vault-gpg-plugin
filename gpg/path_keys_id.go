package gpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// pathKeysByFingerprint allows a key to be queried by its fingerprint as querying keys by
// fingerprint is a common way of uniquely identifying gpg keys.
func pathKeysByFingerprint(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/id/" + framework.GenericNameRegex("ID"),
		Fields: map[string]*framework.FieldSchema{
			"ID": {
				Type:        framework.TypeString,
				Description: "Fingerprint of the key.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyByIDRead,
			},
		},
		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeyByIDRead(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	// Verify and sanitize parameters.
	id := data.Get("ID").(string)

	keyIDToNameMap, err := b.readKeyIDToNameMap(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	name, ok := keyIDToNameMap[id]
	if !ok {
		err = fmt.Errorf("Key with ID %s was not found", id)
		return logical.ErrorResponse(err.Error()), err
	}
	entity, exportable, err := b.readKeyByName(ctx, req, name)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	err = entity.Serialize(w)
	w.Close()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"fingerprint": hex.EncodeToString(entity.PrimaryKey.Fingerprint[:]),
			"name":        name,
			"public_key":  buf.String(),
			"exportable":  exportable,
		},
	}, nil
}
