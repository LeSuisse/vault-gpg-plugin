package gpg

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type signKeyParameters struct {
	name      string
	signedKey string
}

func (skp *signKeyParameters) parseInput(input *framework.FieldData) error {
	var data interface{}
	var ok bool
	data, ok = input.GetOk("name")
	if ok {
		skp.name, ok = data.(string)
		if !ok {
			return parameterTypeError("name", "string")
		}
	}

	data, ok = input.GetOk("signedKey")
	if ok {
		skp.signedKey, ok = data.(string)
		if !ok {
			return parameterTypeError("signedKey", "string")
		}
	}
	return nil
}

func pathSignKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "signkey/" + framework.GenericNameRegex("signedKey"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key that will be used for signing.",
			},
			"signedKey": {
				Type:        framework.TypeString,
				Description: "Name of the key that needs to be signed.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignKey,
			},
		},
		HelpSynopsis:    pathSignKeyHelpSyn,
		HelpDescription: pathSignKeyHelpDesc,
	}
}

func (b *backend) pathSignKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var skp signKeyParameters
	err := skp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a write lock before modifying the entity.
	b.lock.Lock()
	defer b.lock.Unlock()

	signerEntity, _, err := b.readEntityFromStorage(ctx, req.Storage, skp.name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	signedEntity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, skp.signedKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	for _, id := range signedEntity.Identities {
		err = signedEntity.SignIdentity(id.Name, signerEntity, nil)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}
	}

	err = b.writeEntityToStorage(ctx, req.Storage, skp.signedKey, signedEntity, exportable)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	return nil, nil
}

const pathSignKeyHelpSyn = "Sign GPG keys"
const pathSignKeyHelpDesc = `
This path is used to sign named GPG keys to show trust in the key.
The updated keyring is stored back into vault.
`
