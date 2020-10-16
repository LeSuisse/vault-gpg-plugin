package gpg

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func pathSubkeysRD(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/subkeys/" + framework.GenericNameRegex("key_id"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the master key with which to associate the new subkey.",
			},
			"key_id": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "The Key ID of the subkey.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathSubkeyDelete,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSubkeyRead,
			},
		},
		HelpSynopsis:    "Read and delete the given subkey under the given master key",
		HelpDescription: "This path is used to read and delete the given subkey under the given master key.",
	}
}

func pathSubkeysCL(b *backend) *framework.Path {
	return &framework.Path{
		// The "/?" is there at the end to handle libraries that may add it.
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/subkeys/?$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the master key with which to associate the new subkey.",
			},
			"key_type": {
				Type:        framework.TypeLowerCaseString,
				Default:     "rsa",
				Description: "The subkey type.",
			},
			"capabilities": {
				Type:        framework.TypeCommaStringSlice,
				Default:     []string{"sign"},
				Description: "The capabilities of the subkey.",
			},
			"key_bits": {
				Type:        framework.TypeInt,
				Default:     4096,
				Description: "The number of bits of the generated subkey.",
			},
			"expires": {
				Type:        framework.TypeInt,
				Default:     365 * 24 * 60 * 60,
				Description: "The number of seconds from the creation time (now) after which the subkey expires. If the number is zero, then the subkey never expires.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSubkeyList,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSubkeyCreate,
			},
		},
		HelpSynopsis: "Create and list subkeys under the given master key",
		HelpDescription: `This path is used to create and list subkeys under the given master key.
Doing a write with no value against an existing master key will create by default a new, randomly-generated signing subkey.`,
	}
}

func (b *backend) pathSubkeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	keyBits := data.Get("key_bits").(int)
	keyType := data.Get("key_type").(string)
	capabilities := data.Get("capabilities").([]string)
	expires := uint32(data.Get("expires").(int))

	config := packet.Config{}
	if keyBits < 2048 {
		return logical.ErrorResponse("asymmetric subkeys < 2048 bits are unsafe"), nil
	}
	config.RSABits = keyBits
	if keyType != "rsa" {
		return logical.ErrorResponse("non-RSA subkeys are not yet supported"), nil
	}
	config.Algorithm = packet.PubKeyAlgoRSA
	if !reflect.DeepEqual(capabilities, []string{"sign"}) {
		return logical.ErrorResponse("capabilities other than signing are not yet supported: " + fmt.Sprintf("%v", capabilities)), nil
	}
	config.KeyLifetimeSecs = expires

	entity, exportable, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	err = entity.AddSigningSubkey(&config)
	if err != nil {
		return logical.ErrorResponse("could not add signing subkey"), err
	}
	subkey := entity.Subkeys[len(entity.Subkeys)-1]

	var buf bytes.Buffer
	err = entity.SerializePrivate(&buf, nil)
	if err != nil {
		return nil, err
	}
	currStorageEntry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
		Exportable:    exportable,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, currStorageEntry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_id": subkey.PublicKey.KeyIdString(),
		},
	}, nil
}

func (b *backend) pathSubkeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	fingerprintHex := data.Get("key_id").(string)

	entity, exportable, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	subkeys := []openpgp.Subkey{}
	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey.KeyIdString() != fingerprintHex {
			subkeys = append(subkeys, subkey)
		}
	}
	entity.Subkeys = subkeys

	var buf bytes.Buffer
	err = entity.SerializePrivate(&buf, nil)
	if err != nil {
		return nil, err
	}
	currStorageEntry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
		Exportable:    exportable,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, currStorageEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathSubkeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	entity, _, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	keyIDs := []string{}
	for _, subkey := range entity.Subkeys {
		keyIDs = append(keyIDs, subkey.PublicKey.KeyIdString())
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_ids": keyIDs,
		},
	}, nil
}

func (b *backend) pathSubkeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	fingerprintHex := data.Get("key_id").(string)
	fingerprint, err := hex.DecodeString(fingerprintHex)
	if err != nil {
		return logical.ErrorResponse("could not hex decode KeyID %s", fingerprintHex), err
	}
	keyID := binary.BigEndian.Uint64(fingerprint)

	entity, _, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	var el openpgp.EntityList
	el = append(el, entity)
	keys := el.KeysById(keyID)
	if len(keys) != 1 {
		return logical.ErrorResponse("there are %v != 1 subkeys", len(keys)), nil
	}
	subkey := keys[0]
	if !subkey.PrivateKey.IsSubkey || !subkey.PublicKey.IsSubkey {
		return logical.ErrorResponse("KeyID %v does not correspond to a subkey", keyID), nil
	}

	var keyType string
	var keyBits uint16
	switch subkey.PublicKey.PubKeyAlgo {
	case packet.PubKeyAlgoRSA:
		keyType = "rsa"
		keyBits, err = subkey.PublicKey.BitLength()
		if err != nil {
			return nil, err
		}
	default:
		return logical.ErrorResponse("unknown subkey type: %v", subkey.PublicKey.PubKeyAlgo), nil
	}

	capabilities := []string{}
	if subkey.SelfSignature.FlagsValid {
		if subkey.SelfSignature.FlagSign {
			capabilities = append(capabilities, "sign")
		}
		if subkey.SelfSignature.FlagEncryptCommunications || subkey.SelfSignature.FlagEncryptStorage {
			capabilities = append(capabilities, "encrypt")
		}
	}
	expires := uint32(0)
	if subkey.SelfSignature.KeyLifetimeSecs != nil {
		expires = *subkey.SelfSignature.KeyLifetimeSecs
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_type":     keyType,
			"capabilities": capabilities,
			"key_bits":     keyBits,
			"expires":      expires,
		},
	}, nil
}
