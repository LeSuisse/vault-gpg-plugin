package gpg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func pathListKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathKeyList,
		},
	}
}

func pathKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"real_name": {
				Type:        framework.TypeString,
				Description: "The real name of the identity associated with the generated GPG key.",
			},
			"email": {
				Type:        framework.TypeString,
				Description: "The email of the identity associated with the generated GPG key.",
			},
			"comment": {
				Type:        framework.TypeString,
				Description: "The comment of the identity associated with the generated GPG key.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathKeyRead,
			logical.UpdateOperation: b.pathKeyCreate,
			logical.DeleteOperation: b.pathKeyDelete,
		},
	}
}

func (b *backend) key(s logical.Storage, name string) (*keyEntry, error) {
	entry, err := s.Get("key/" + name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result keyEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) entity(s logical.Storage, name string) (*openpgp.Entity, error) {
	entry, err := b.key(s, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	r := bytes.NewReader(entry.SerializedKey)
	el, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}
	if len(el) == 0 {
		return nil, fmt.Errorf("PGP key does not contain an entity")
	}

	return el[0], nil
}

func (b *backend) pathKeyRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entity, err := b.entity(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, nil
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
			"public_key":  buf.String(),
		},
	}, nil
}

func (b *backend) pathKeyCreate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	realName := data.Get("real_name").(string)
	email := data.Get("email").(string)
	comment := data.Get("comment").(string)

	entity, err := openpgp.NewEntity(realName, comment, email, nil)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = entity.SerializePrivate(&buf, nil)
	if err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathKeyDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete("key/" + data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathKeyList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List("key/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

type keyEntry struct {
	SerializedKey []byte
}
