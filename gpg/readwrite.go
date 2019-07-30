package gpg

import (
	"bytes"
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
)

func (b *backend) readEntityFromStorage(ctx context.Context, storage logical.Storage, name string) (*openpgp.Entity, bool, error) {
	entry, err := b.key(ctx, storage, name)
	if err != nil {
		return nil, false, err
	}
	if entry == nil {
		return nil, false, fmt.Errorf("Key with name %s was not found", name)
	}
	entity, err := b.entity(entry)
	if err != nil {
		return nil, false, err
	}
	return entity, entry.Exportable, nil
}

func (b *backend) writeEntityToStorage(ctx context.Context, storage logical.Storage, name string, entity *openpgp.Entity,
	exportable bool) error {
	var buf bytes.Buffer
	err := serializeEntityWithAllSignatures(&buf, entity)
	if err != nil {
		return err
	}

	updatedEntry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
		Exportable:    exportable,
	})
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, updatedEntry); err != nil {
		return err
	}

	return nil
}

func (b *backend) readKeyIDToNameMap(ctx context.Context, storage logical.Storage) (map[string]string, error) {
	// Acquire a read lock before the read operation.
	b.lock.RLock()
	entry, err := storage.Get(ctx, "keyIDToNameMap")
	b.lock.RUnlock()
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var keyIDToNameMap map[string]string
	err = entry.DecodeJSON(&keyIDToNameMap)
	if err != nil {
		return nil, err
	}
	return keyIDToNameMap, nil
}

func (b *backend) writeKeyIDToNameMap(ctx context.Context, storage logical.Storage,
	m map[string]string) error {
	entry, err := logical.StorageEntryJSON("keyIDToNameMap", m)
	if err != nil {
		return err
	}

	// Acquire a write lock before writing the map.
	b.lock.Lock()
	defer b.lock.Unlock()
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}
