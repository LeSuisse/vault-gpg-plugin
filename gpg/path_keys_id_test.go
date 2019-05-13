package gpg

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestGPG_KeyIDNotSpecifiedReturnsError(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Key name is not specified.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "keys/id",
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("Key not specified but the API does not return an error")
	}
}

func TestGPG_KeyIDNotExistingReturnsNotFound(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Key does not exist.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "keys/id/FA129324743",
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Key does not exist but does not return not found")
	}
}

func TestGPG_PathKeysByID(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	testKeyName := "test"
	err := addKeyToTestStorage(b, storage, testKeyName, false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	// Get subkey ID of the subkey.
	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key revocation: %v", err)
	}

	keyID := hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("keys/id/%s", keyID),
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to read a valid key by ID: %v", err)
	}

	value, ok := resp.Data["name"]
	if !ok {
		t.Fatalf("no valid key name found in response data %#v", resp.Data)
	}
	if value != testKeyName {
		t.Fatalf("Expected key name: %q, got: %q", testKeyName, value)
	}
}
