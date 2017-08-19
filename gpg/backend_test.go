package gpg

import (
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/openpgp"
	"reflect"
	"strings"
	"testing"
)

func TestBackend_CRUD(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	keyData := map[string]interface{}{
		"real_name":  "Vault",
		"email":      "vault@example.com",
		"comment":    "Comment",
		"exportable": true,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepCreateKey("test", keyData, false),
			testAccStepCreateKey("test2", keyData, false),
			testAccStepCreateKey("test3", keyData, false),
			testAccStepReadKey("test", keyData),
			testAccStepDeleteKey("test"),
			testAccStepListKey([]string{"test2", "test3"}),
			testAccStepReadKey("test", nil),
		},
	})
}

func TestBackend_InvalidCharIdentity(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepCreateKey(
				"test",
				map[string]interface{}{
					"real_name": "Vault<>",
					"email":     "vault@example.com",
					"comment":   "Comment",
				},
				true),
			testAccStepCreateKey(
				"test",
				map[string]interface{}{
					"real_name": "Vault",
					"email":     "vault@example.com()",
					"comment":   "Comment",
				},
				true),
			testAccStepCreateKey(
				"test",
				map[string]interface{}{
					"real_name": "Vault",
					"email":     "vault@example.com",
					"comment":   "Comment<>",
				},
				true),
		},
	})
}

func testAccStepCreateKey(name string, keyData map[string]interface{}, expectFail bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "keys/" + name,
		Data:      keyData,
		ErrorOk:   expectFail,
	}
}

func testAccStepReadKey(name string, keyData map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "keys/" + name,
		Data:      keyData,
		Check: func(response *logical.Response) error {
			if response == nil {
				if keyData == nil {
					return nil
				}
				return fmt.Errorf("response not expected: %#v", response)
			}

			var s struct {
				Fingerprint string `mapstructure:"fingerprint"`
				PublicKey   string `mapstructure:"public_key"`
			}

			if err := mapstructure.Decode(response.Data, &s); err != nil {
				return err
			}

			r := strings.NewReader(s.PublicKey)
			el, err := openpgp.ReadArmoredKeyRing(r)
			if err != nil {
				return err
			}

			nb := len(el)
			if nb != 1 {
				fmt.Errorf("only 1 entity is expected, %d found", nb)
			}

			e := el[0]

			bitLength, err := e.PrimaryKey.BitLength()
			if err != nil {
				return err
			}
			fingerprint := hex.EncodeToString(e.PrimaryKey.Fingerprint[:])

			identityFullName := keyData["real_name"].(string) + " (" + keyData["comment"].(string) + ") " +
				"<" + keyData["email"].(string) + ">"

			switch {
			case e.PrivateKey != nil:
				return fmt.Errorf("private key should not be exported")
			case bitLength != 2048:
				return fmt.Errorf("key size should be: %d", 2048)
			case s.Fingerprint != fingerprint:
				return fmt.Errorf("fingerprint does not match: %s %s", s.Fingerprint, fingerprint)
			case !func() bool { _, ok := e.Identities[identityFullName]; return ok }():
				return fmt.Errorf("identity %s should be present", identityFullName)
			}
			return nil
		},
	}
}

func testAccStepDeleteKey(name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + name,
	}
}

func testAccStepListKey(names []string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ListOperation,
		Path:      "keys/",
		Check: func(resp *logical.Response) error {
			respKeys := resp.Data["keys"].([]string)
			if !reflect.DeepEqual(respKeys, names) {
				return fmt.Errorf("does not match: %#v %#v", respKeys, names)
			}
			return nil
		},
	}
}
