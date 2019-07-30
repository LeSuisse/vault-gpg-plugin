package gpg

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestGPG_SignKeyNotExistingSignedKeyReturnsNotFound(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "signkey/test",
	}
	_, err := b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("Key does not exist but does not return not found")
	}
}

func TestGPG_SignKeyNotExistingSignerKeyReturnsNotFound(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	err := addKeyToTestStorage(b, storage, "test", false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "signkey/test",
		Data: map[string]interface{}{
			"name": "signerKey",
		},
	}
	_, err = b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("Key does not exist but does not return not found")
	}
}

func TestGPG_SignKey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a new signed key.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/signedKey",
		Data: map[string]interface{}{
			"generate":   true,
			"real_name":  "signedKey",
			"email":      "test@example.com",
			"exportable": true,
		},
	}

	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Add the signerKey to the storage.
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/signerKey",
		Data: map[string]interface{}{
			"generate":   true,
			"real_name":  "signerKey",
			"email":      "test2@example.com",
			"exportable": true,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "signkey/signedKey",
		Data: map[string]interface{}{
			"name": "signerKey",
		},
	}
	_, err = b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("Key signing should have succeeded but it failed: %v", err)
	}

	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "signedKey")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key signing: %v", err)
	}
	for _, id := range entity.Identities {
		if len(id.Signatures) == 0 {
			t.Fatalf("Identity %s was not signed", id.Name)
		}
	}
}
