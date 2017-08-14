package gpg

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/crypto/openpgp"
	"strings"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSignWrite,
		},
	}
}

func pathVerify(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data to verify",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The ASCII-armored signature",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathVerifyWrite,
		},
	}
}

func (b *backend) pathSignWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

	entity, err := b.entity(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, nil
	}

	message := bytes.NewReader(input)
	var w bytes.Buffer
	err = openpgp.ArmoredDetachSign(&w, entity, message, nil)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": w.String(),
		},
	}, nil
}

func (b *backend) pathVerifyWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

	keyEntry, err := b.key(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return nil, nil
	}

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	message := bytes.NewReader(input)
	signature := strings.NewReader(data.Get("signature").(string))
	_, err = openpgp.CheckArmoredDetachedSignature(keyring, message, signature)

	resp := &logical.Response{
		Data: map[string]interface{}{
			"valid": err == nil,
		},
	}

	return resp, nil
}
