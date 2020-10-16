package gpg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"urlalgorithm": {
				Type:        framework.TypeString,
				Description: "Hash algorithm to use (POST URL parameter)",
			},
			"algorithm": {
				Type:    framework.TypeString,
				Default: "sha2-256",
				Description: `Hash algorithm to use (POST body parameter). Valid values are:

* sha2-224
* sha2-256
* sha2-384
* sha2-512

Defaults to "sha2-256".`,
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format to use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
			"expires": {
				Type:        framework.TypeInt,
				Default:     365 * 24 * 60 * 60,
				Description: "The number of seconds from the creation time (now) after which the subkey expires. If the number is zero, then the subkey never expires.",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignWrite,
			},
		},
		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func pathVerify(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),
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
				Description: "The signature",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the signature use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVerifyWrite,
			},
		},
		HelpSynopsis:    pathVerifyHelpSyn,
		HelpDescription: pathVerifyHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entity, _, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}
	message := bytes.NewReader(input)

	config := packet.Config{}
	algorithm := data.Get("urlalgorithm").(string)
	if algorithm == "" {
		algorithm = data.Get("algorithm").(string)
	}
	switch algorithm {
	case "sha2-224":
		config.DefaultHash = crypto.SHA224
	case "sha2-256":
		config.DefaultHash = crypto.SHA256
	case "sha2-384":
		config.DefaultHash = crypto.SHA384
	case "sha2-512":
		config.DefaultHash = crypto.SHA512
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported algorithm %s", algorithm)), nil
	}

	expires := uint32(data.Get("expires").(int))
	config.SigLifetimeSecs = expires

	var signature bytes.Buffer
	format := data.Get("format").(string)
	switch format {
	case "ascii-armor":
		err = openpgp.ArmoredDetachSign(&signature, entity, message, &config)
		if err != nil {
			return nil, err
		}
	case "base64":
		encoder := base64.NewEncoder(base64.StdEncoding, &signature)
		err = openpgp.DetachSign(encoder, entity, message, &config)
		if err != nil {
			return nil, err
		}
		err = encoder.Close()
		if err != nil {
			return nil, err
		}
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"base64\" or \"ascii-armor\"", format)), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": signature.String(),
		},
	}, nil
}

func (b *backend) pathVerifyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyEntry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	signature := strings.NewReader(data.Get("signature").(string))
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}
	message := bytes.NewReader(input)

	config := packet.Config{}
	format := data.Get("format").(string)
	switch format {
	case "base64":
		decoder := base64.NewDecoder(base64.StdEncoding, signature)
		_, err = openpgp.CheckDetachedSignature(keyring, message, decoder, &config)
	case "ascii-armor":
		_, err = openpgp.CheckArmoredDetachedSignature(keyring, message, signature, &config)
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"base64\" or \"ascii-armor\"", format)), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"valid": err == nil,
			"error": err,
		},
	}, nil
}

const pathSignHelpSyn = "Generate a signature for input data using the named GPG key"
const pathSignHelpDesc = "Generates a signature of the input data using the named GPG key."
const pathVerifyHelpSyn = "Verify a signature for input data created using the named GPG key"
const pathVerifyHelpDesc = "Verifies a signature of the input data using the named GPG key."
