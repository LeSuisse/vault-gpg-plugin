package gpg

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
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
}

func TestGPG_AttemptToSetConfigOfAnUnknownKey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test/config",
		Data:      map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected an error because the key does not exist")
	}
	if !resp.IsError() {
		t.Fatal("expected an response error because the key does not exist")
	}
}
