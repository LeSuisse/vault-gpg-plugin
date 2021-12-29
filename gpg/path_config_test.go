package gpg

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func TestGPG_SetKeyConfig(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault",
			"email":     "vault@example.com",
			"key_bits":  2048,
			"generate":  true,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	updateTransparencyLogAddress := func(keyName string, address string) {
		req := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "keys/" + keyName + "/config",
			Data: map[string]interface{}{
				"transparency_log_address": address,
			},
		}
		_, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
	}

	checkTransparencyLogAddress := func(keyName string, expectedAddress string) {
		req := &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "keys/" + keyName,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		respLogAddress := resp.Data["transparency_log_address"]

		if respLogAddress != expectedAddress {
			t.Errorf("no received the expected address %s, got %s", expectedAddress, respLogAddress)
		}
	}

	checkTransparencyLogAddress("test", "")
	updateTransparencyLogAddress("test", "https://rekor.example.com")
	checkTransparencyLogAddress("test", "https://rekor.example.com")
	updateTransparencyLogAddress("test", "")
	checkTransparencyLogAddress("test", "")
}

func TestGPG_AttemptToSetConfigOfAnUnknownKey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test/config",
		Data: map[string]interface{}{
			"transparency_log_address": "",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected an error because the key does not exist")
	}
	if !resp.IsError() {
		t.Fatal("expected an response error because the key does not exist")
	}
}
