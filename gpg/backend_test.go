package gpg

import (
	"context"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
)

func TestBackend_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	keyData := map[string]interface{}{
		"real_name":  "Vault",
		"email":      "vault@example.com",
		"comment":    "Comment",
		"key_bits":   4096,
		"exportable": true,
	}

	testAccStepCreateKey(t, b, storage, "test", keyData, false)
	testAccStepCreateKey(t, b, storage, "test2", keyData, false)
	testAccStepCreateKey(t, b, storage, "test3", keyData, false)
	testAccStepReadKey(t, b, storage, "test", keyData, false)
	testAccStepDeleteKey(t, b, storage, "test")
	testAccStepListKey(t, b, storage, []string{"test2", "test3"})
	testAccStepReadKey(t, b, storage, "test", nil, true)
}

func TestBackend_CRUDImportedKey(t *testing.T) {
	b, storage := getTestBackend(t)

	keyData := map[string]interface{}{
		"key":      gpgKey,
		"generate": false,
		"key_bits": 2048,
	}

	testAccStepCreateKey(t, b, storage, "test", keyData, false)
	testAccStepReadKey(t, b, storage, "test", keyData, false)
	testAccStepListKey(t, b, storage, []string{"test"})
	testAccStepDeleteKey(t, b, storage, "test")
	testAccStepListKey(t, b, storage, []string{})
	testAccStepReadKey(t, b, storage, "test", nil, true)
}

func TestBackend_InvalidCharIdentity(t *testing.T) {
	b, storage := getTestBackend(t)

	testAccStepCreateKey(
		t,
		b,
		storage,
		"test",
		map[string]interface{}{
			"real_name": "Vault<>",
			"email":     "vault@example.com",
			"comment":   "Comment",
		},
		true,
	)
	testAccStepCreateKey(
		t,
		b,
		storage,
		"test",
		map[string]interface{}{
			"real_name": "Vault",
			"email":     "vault@example.com()",
			"comment":   "Comment",
		},
		true,
	)
	testAccStepCreateKey(
		t,
		b,
		storage,
		"test",
		map[string]interface{}{
			"real_name": "Vault",
			"email":     "vault@example.com",
			"comment":   "Comment<>",
		},
		true,
	)
}

func testAccStepCreateKey(t *testing.T, b logical.Backend, s logical.Storage, name string, keyData map[string]interface{}, expectFail bool) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/" + name,
		Data:      keyData,
		Storage:   s,
	})
	if !expectFail {
		if err != nil {
			t.Error(err)
		}
		if resp.IsError() {
			t.Error(resp.Error())
		}
	}
}

func testAccStepReadKey(t *testing.T, b logical.Backend, storage logical.Storage, name string, keyData map[string]interface{}, expectFail bool) {
	response, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + name,
		Data:      keyData,
		Storage:   storage,
	})

	if !expectFail {
		if err != nil {
			t.Error(err)
		}
		if response.IsError() {
			t.Error(response.Error())
		}
	} else {
		return
	}

	if response == nil {
		if keyData == nil {
			return
		}
		t.Errorf("response not expected: %#v", response)
		return
	}

	r := strings.NewReader(response.Data["public_key"].(string))
	el, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil {
		t.Fatal(err)
	}

	nb := len(el)
	if nb != 1 {
		t.Errorf("1 entity is expected, %d found", nb)
		return
	}

	e := el[0]

	bitLength, err := e.PrimaryKey.BitLength()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := hex.EncodeToString(e.PrimaryKey.Fingerprint[:])

	switch {
	case e.PrivateKey != nil:
		t.Errorf("private key should not be exported")
	case int(bitLength) != keyData["key_bits"]:
		t.Errorf("key size should be %d, got %d", keyData["key_bits"], bitLength)
	case response.Data["fingerprint"] != fingerprint:
		t.Errorf("fingerprint does not match: %s %s", response.Data["fingerprint"], fingerprint)
	case len(e.Identities) != 1:
		t.Errorf("expected 1 identity, %d found", len(e.Identities))
	}
}

func testAccStepDeleteKey(t *testing.T, b logical.Backend, storage logical.Storage, name string) {
	response, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + name,
		Storage:   storage,
	})

	if err != nil {
		t.Error(err)
	}
	if response.IsError() {
		t.Error(response.Error())
	}
}

func testAccStepListKey(t *testing.T, b logical.Backend, storage logical.Storage, names []string) {
	response, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys/",
		Storage:   storage,
	})

	if err != nil {
		t.Error(err)
	}
	if response.IsError() {
		t.Error(response.Error())
	}

	respKeys := response.Data["keys"]
	if len(names) > 0 {
		respKeysSlice := respKeys.([]string)
		if !reflect.DeepEqual(respKeysSlice, names) {
			t.Errorf("does not match: %#v %#v", respKeys, names)
		}
	} else {
		if respKeys != nil {
			t.Errorf("keys not empty: %#v", respKeys)
		}
	}
}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	return b, config.StorageView
}

const gpgKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=RtIM
-----END PGP PRIVATE KEY BLOCK-----`
