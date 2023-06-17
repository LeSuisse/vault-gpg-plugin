package gpg

import (
	"bytes"
	"context"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathExportKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "export/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathExportKeyRead,
			},
		},
		HelpSynopsis:    pathExportHelpSyn,
		HelpDescription: pathExportHelpDesc,
	}
}

func (b *backend) pathExportKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := b.key(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	if !entry.Exportable {
		return logical.ErrorResponse("key is not exportable"), nil
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	w.Write(entry.SerializedKey)
	if w.Close() != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name": name,
			"key":  buf.String(),
		},
	}, nil
}

const pathExportHelpSyn = "Export named GPG key"
const pathExportHelpDesc = "This path is used to export the keys that are configured as exportable."
