package gpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
)

func addKeyToTestStorage(b *backend, storage logical.Storage, name string,
	generate bool, keyString string) error {
	if generate {
		keyString = ""
	}

	// Add the test key to the storage.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("keys/%s", name),
		Data: map[string]interface{}{
			"generate": generate,
			"key":      keyString,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)
	if err != nil || response.IsError() {
		return fmt.Errorf("failed to create key %s", name)
	}
	return nil
}

func TestGPG_SubKeyNotExistingSubkeyReturnsNotFound(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Key does not exist.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "subkeys/test/",
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Key does not exist but does not return not found")
	}

	// Add the test key to the storage.
	err = addKeyToTestStorage(b, storage, "test", false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	// Subkey requested does not exist.
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "subkeys/test/keyDoesNotExist",
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Subkey does not exist but does not return not found")
	}

	// Subkey that is being deleted does not exist.
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      "subkeys/test/keyDoesNotExist",
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Subkey does not exist but does not return not found")
	}
}

func TestGPG_CreateErrorGeneratedSubkeyTooSmallKeyBits(t *testing.T) {
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
		Path:      "subkeys/test",
		Data: map[string]interface{}{
			"key_bits": 1024,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Subkey creation has been accepted but should have denied due to insufficient key size")
	}
}

func TestGPG_CreateErrorGeneratedUnusableSubkey(t *testing.T) {
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
		Path:      "subkeys/test",
		Data: map[string]interface{}{
			"canSign":    false,
			"canEncrypt": false,
			"key_bits":   1024,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Subkey creation has been accepted but it cannot be used for signing or encryption")
	}
}

func TestGPG_CreateSubkey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	err := addKeyToTestStorage(b, storage, "test", false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	// Default subkey.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "subkeys/test",
		Data:      map[string]interface{}{},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatal("Failed to create a default subkey")
	}

	// Custom subkey.
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "subkeys/test",
		Data: map[string]interface{}{
			"canSign":    true,
			"canEncrypt": true,
		},
	}

	response, err = b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatal("Failed to create a custom subkey")
	}
}

func TestGPG_ListSubkeys(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	err := addKeyToTestStorage(b, storage, "test", false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "subkeys/test/",
	}
	response, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatalf("Failed to list subkeys of an valid key: %v", err)
	}

	keys, ok := response.Data["keys"].([]string)
	if !ok {
		t.Fatal("Subkey IDs not found in list response")
	}

	if len(keys) != 1 {
		t.Fatal("Subkeys exist but list response for subkeys is empty")
	}
}

func TestGPG_DeleteSubkey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	err := addKeyToTestStorage(b, storage, "test", false, gpgKey)
	if err != nil {
		t.Fatal(err)
	}

	// Get subkey ID of the subkey.
	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key revocation: %v", err)
	}
	subkeyID := hex.EncodeToString(entity.Subkeys[0].PublicKey.Fingerprint[:])

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("subkeys/test/%s", subkeyID),
	}
	response, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatalf("Failed to delete subkey of an valid key: %v", err)
	}
}

func TestGPG_ReadSubkey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Add the test key to the storage.
	err := addKeyToTestStorage(b, storage, "test", false, gpgSignedAndRevokedTestKey)
	if err != nil {
		t.Fatal(err)
	}

	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key revocation: %v", err)
	}
	subkeyID := hex.EncodeToString(entity.Subkeys[0].PublicKey.Fingerprint[:])
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("subkeys/test/%s", subkeyID),
	}
	response, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatalf("Subkey exists but failed to read: %v", err)
	}
	subkey, ok := response.Data["subkey"].(string)
	if !ok {
		t.Fatalf("no name subkey found in response data %#v", response.Data)
	}
	r := bytes.NewReader([]byte(subkey))
	keyring, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil {
		t.Fatal("Unable to import subkey")
	}
	if len(keyring[0].Revocations) != 1 {
		t.Fatal("Missing revocation from the read subkey")
	}
	if len(keyring[0].Subkeys) != 1 {
		t.Fatalf("Expected 1 subkey, got %d", len(keyring[0].Subkeys))
	}
}

const gpgSignedAndRevokedTestKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
t4mV
=Nbpa
-----END PGP PRIVATE KEY BLOCK-----`
