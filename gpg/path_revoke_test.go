package gpg

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const revocationReasonCode = 1
const revocationReasonText = "Key compromised"

func TestGPG_RevokeKeyNotExistingKeyReturnsNotFound(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "revoke/test",
		Data: map[string]interface{}{
			"reasonCode": revocationReasonCode,
			"reasonText": revocationReasonText,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("Key does not exist but does not return not found")
	}
}
func TestGPG_RevokeKeyReasonMissing(t *testing.T) {
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
		Path:      "revoke/test",
	}
	_, err = b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("Key was revoked without a specified reason")
	}
}

func TestGPG_RevokeKeyRevocationReasonNotInteger(t *testing.T) {
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
		Path:      "revoke/test/1a2frf",
		Data: map[string]interface{}{
			"reasonCode": revocationReasonText,
			"reasonText": revocationReasonText,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("reasonCode is not an integer yet the key was revoked")
	}
}

func TestGPG_RevokeKeyNotExistingSubkeyReturnsNotFound(t *testing.T) {
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
		Path:      "revoke/test/SubkeyDoesNotExist",
		Data: map[string]interface{}{
			"reasonCode": revocationReasonCode,
			"reasonText": revocationReasonText,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)

	if err == nil {
		t.Fatal("Subkey does not exist but does not return not found")
	}
}

func TestGPG_RevokeKey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a new signed key.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate":   true,
			"real_name":  "test",
			"email":      "test@example.com",
			"exportable": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "revoke/test",
		Data: map[string]interface{}{
			"reasonCode": revocationReasonCode,
			"reasonText": revocationReasonText,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("Key revocation should be successful but it failed: %v", err)
	}
	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key revocation: %v", err)
	}
	if len(entity.Revocations) != 1 {
		t.Fatal("Revocation signature missing from key after key revocation")
	}
}

func TestGPG_RevokeSubkey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a new signed key.
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate":   true,
			"real_name":  "test",
			"email":      "test@example.com",
			"exportable": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	entity, _, err := b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key creation: %v", err)
	}
	subkeyID := hex.EncodeToString(entity.Subkeys[0].PublicKey.Fingerprint[:])
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("revoke/test/%s", subkeyID),
		Data: map[string]interface{}{
			"reasonCode": revocationReasonCode,
			"reasonText": revocationReasonText,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("Subkey revocation should be successful but it failed: %v", err)
	}

	entity, _, err = b.readEntityFromStorage(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("Failed to read key from storage after key revocation: %v", err)
	}
	reasonCode := entity.Subkeys[0].Sig.RevocationReason
	reasonText := entity.Subkeys[0].Sig.RevocationReasonText
	if reasonCode == nil {
		t.Fatal("Revocation signature missing from key after key revocation")
	}
	if *reasonCode != uint8(revocationReasonCode) {
		t.Fatalf("Expected revocation reason code: %v, got: %v", revocationReasonCode, *reasonCode)
	}
	if reasonText != revocationReasonText {
		t.Fatalf("Expected revocation reason text: %v, got: %v", revocationReasonText, reasonText)
	}
}
