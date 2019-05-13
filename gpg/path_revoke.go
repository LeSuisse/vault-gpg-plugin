package gpg

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
)

type revocationParameters struct {
	name       string
	subkeyID   string
	reasonCode uint8
	reasonText string
}

func (rp *revocationParameters) parseInput(input *framework.FieldData) error {
	var data interface{}
	var ok bool
	data, ok = input.GetOk("name")
	if ok {
		rp.name = data.(string)
	}

	data, ok = input.GetOk("subkeyID")
	if ok {
		rp.subkeyID = data.(string)
	}

	data, ok = input.GetOk("reasonCode")
	if ok {
		id, ok := data.(int)
		if !ok {
			return parameterTypeError("reasonCode", "int")
		}
		rp.reasonCode = uint8(id)
	} else {
		return fmt.Errorf("reasonCode cannot be empty")
	}

	data, ok = input.GetOk("reasonText")
	if ok {
		rp.reasonText = data.(string)
	} else {
		return fmt.Errorf("reasonText cannot be empty")
	}

	return nil
}

func pathRevoke(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "revoke/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("subkeyID"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
			},
			"subkeyID": {
				Type:        framework.TypeString,
				Description: "Fingerprint of the subkey.",
			},
			"reasonCode": {
				Type:        framework.TypeInt,
				Description: "Reason code for key revocation.",
			},
			"reasonText": {
				Type:        framework.TypeString,
				Description: "Textual description of reason for key revocation.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRevokeKey,
			},
		},
		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func (b *backend) revokeKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var rp revocationParameters
	err := rp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a write lock before modifying the entity.
	b.lock.Lock()
	defer b.lock.Unlock()

	entity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, rp.name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	err = entity.RevokeKey(rp.reasonCode, rp.reasonText, nil)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	err = b.writeEntityToStorage(ctx, req.Storage, rp.name, entity, exportable)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	return nil, nil
}

func (b *backend) revokeSubkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var rp revocationParameters
	err := rp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a write lock before modifying the entity.
	b.lock.Lock()
	defer b.lock.Unlock()

	entity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, rp.name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	var subkey *openpgp.Subkey
	idx := 0
	for i, sk := range entity.Subkeys {
		if rp.subkeyID == hex.EncodeToString(sk.PublicKey.Fingerprint[:]) {
			subkey = &sk
			idx = i
			break
		}
	}

	if subkey == nil {
		err = fmt.Errorf("Subkey with fingerprint %s for key %s was not found", rp.subkeyID, rp.name)
		return logical.ErrorResponse(err.Error()), err
	}

	err = entity.RevokeSubkey(subkey, rp.reasonCode, rp.reasonText, nil)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	entity.Subkeys[idx] = *subkey

	err = b.writeEntityToStorage(ctx, req.Storage, rp.name, entity, exportable)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	return nil, nil
}

func (b *backend) pathRevokeKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	subkeyID := data.Get("subkeyID").(string)
	if subkeyID == "" {
		return b.revokeKey(ctx, req, data)
	} else {
		return b.revokeSubkey(ctx, req, data)
	}
}

const pathRevokeHelpSyn = "Revoke GPG keys and subkeys"
const pathRevokeHelpDesc = `
This path is used to revoke GPG keys and subkeys that are available.
The updated keyring is stored back into vault.
`
