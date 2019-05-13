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
	"golang.org/x/crypto/openpgp/packet"
)

func parameterTypeError(name, expectedType string) error {
	return fmt.Errorf("Type of paramater %s is not %s", name, expectedType)
}

type subkeyParameters struct {
	name       string
	subkeyID   string
	canSign    bool
	canEncrypt bool
	keyBits    int
}

func (sp *subkeyParameters) parseInput(input *framework.FieldData) error {
	var data interface{}
	var ok bool
	data, ok = input.GetOk("name")
	if ok {
		sp.name, ok = data.(string)
		if !ok {
			return parameterTypeError("name", "string")
		}
	}

	data, ok = input.GetOk("subkeyID")
	if ok {
		sp.subkeyID, ok = data.(string)
		if !ok {
			return parameterTypeError("subkeyID", "string")
		}
	}

	data = input.Get("key_bits")
	sp.keyBits, ok = data.(int)
	if !ok {
		return parameterTypeError("key_bits", "int")
	}

	data = input.Get("canSign")
	sp.canSign, ok = data.(bool)
	if !ok {
		return parameterTypeError("canSign", "bool")
	}

	data = input.Get("canEncrypt")
	sp.canEncrypt, ok = data.(bool)
	if !ok {
		return parameterTypeError("canEncrypt", "bool")
	}

	return nil
}

func pathListSubkeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "subkeys/" + "(?P<name>.+)?/$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSubkeyList,
			},
		},
		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func pathSubkeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "subkeys/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("subkeyID"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
			},
			"subkeyID": {
				Type:        framework.TypeString,
				Description: "Fingerprint of the subkey.",
			},
			"canSign": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Allows the subkey to support signing.",
			},
			"canEncrypt": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Allows the subkey to support encryption.",
			},
			"key_bits": {
				Type:        framework.TypeInt,
				Default:     2048,
				Description: "The number of bits to use. Only used if generate is true.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSubkeyRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSubkeyCreate,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathSubkeyDelete,
			},
		},
		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathSubkeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var sp subkeyParameters
	err := sp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a read lock before the read operation.
	b.lock.RLock()
	entity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, sp.name)
	b.lock.RUnlock()
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	var subkey *openpgp.Subkey
	for _, sk := range entity.Subkeys {
		if sp.subkeyID == hex.EncodeToString(sk.PublicKey.Fingerprint[:]) {
			subkey = &sk
			break
		}
	}

	if subkey == nil {
		err = fmt.Errorf("Subkey with fingerprint %s for key %s was not found", sp.subkeyID, sp.name)
		return logical.ErrorResponse(err.Error()), err
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	err = serializePublicSubkey(w, entity, subkey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	w.Close()

	return &logical.Response{
		Data: map[string]interface{}{
			"subkey":     buf.String(),
			"exportable": exportable,
		},
	}, nil
}

func (b *backend) pathSubkeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var sp subkeyParameters
	err := sp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a write lock before modifying the entity.
	b.lock.Lock()
	defer b.lock.Unlock()

	entity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, sp.name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	if sp.keyBits < 2048 {
		return logical.ErrorResponse("Keys < 2048 bits are unsafe and not supported"), nil
	}
	config := packet.Config{
		RSABits: sp.keyBits,
	}

	err = entity.AddSubkey(sp.canSign, sp.canEncrypt, &config)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	err = b.writeEntityToStorage(ctx, req.Storage, sp.name, entity, exportable)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"subkey-id": hex.EncodeToString(entity.Subkeys[len(entity.Subkeys)-1].PublicKey.Fingerprint[:]),
			"name":      sp.name,
		},
	}, nil
}

func (b *backend) pathSubkeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var name string
	d, ok := data.GetOk("name")
	if ok {
		name, ok = d.(string)
		if !ok {
			err := parameterTypeError("name", "string")
			return logical.ErrorResponse(err.Error()), err
		}
	}

	// Acquire a read lock before the read operation.
	b.lock.RLock()
	entity, _, err := b.readEntityFromStorage(ctx, req.Storage, name)
	b.lock.RUnlock()
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	var subkeys []string
	for _, sk := range entity.Subkeys {
		subkeys = append(subkeys, hex.EncodeToString(sk.PublicKey.Fingerprint[:]))
	}

	return logical.ListResponse(subkeys), nil
}

func (b *backend) pathSubkeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var sp subkeyParameters
	err := sp.parseInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Acquire a write lock before modifying the entity.
	b.lock.Lock()
	defer b.lock.Unlock()

	entity, exportable, err := b.readEntityFromStorage(ctx, req.Storage, sp.name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	var subkeys []openpgp.Subkey
	found := false
	for _, sk := range entity.Subkeys {
		if hex.EncodeToString(sk.PublicKey.Fingerprint[:]) == sp.subkeyID {
			found = true
			continue
		}
		subkeys = append(subkeys, sk)
	}
	if !found {
		err = fmt.Errorf("Subkey with fingerprint %s for key %s was not found", sp.subkeyID, sp.name)
		return logical.ErrorResponse(err.Error()), err
	}
	entity.Subkeys = subkeys

	err = b.writeEntityToStorage(ctx, req.Storage, sp.name, entity, exportable)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	return nil, nil
}
