package gpg

import (
	"github.com/hashicorp/vault/logical"
	"testing"
)

func TestGPG_SignVerify(t *testing.T) {
	var b *backend
	storage := &logical.InmemStorage{}

	b = Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	}
	req2 := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test2",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test2",
			"email":     "vault@example.com",
		},
	}
	_, err := b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(req2)
	if err != nil {
		t.Fatal(err)
	}

	signRequest := func(req *logical.Request, keyName string, errExpected bool) string {
		req.Path = "sign/" + keyName
		response, err := b.HandleRequest(req)
		if err != nil && !errExpected {
			t.Fatal(err)
		}
		if response == nil {
			t.Fatal("expected non-nil response")
		}
		if errExpected {
			if !response.IsError() {
				t.Fatalf("expected error response: %#v", *response)
			}
			return ""
		}
		if response.IsError() {
			t.Fatalf("not expected error response: %#v", *response)
		}
		value, ok := response.Data["signature"]
		if !ok {
			t.Fatalf("no signature found in response data: %#v", response.Data)
		}
		return value.(string)
	}

	verifyRequest := func(req *logical.Request, keyName string, errExpected, validSignature bool, signature string) {
		req.Path = "verify/" + keyName
		req.Data["signature"] = signature
		response, err := b.HandleRequest(req)
		if err != nil && !errExpected {
			t.Fatalf("error: %v, signature was %v", err, signature)
		}
		if errExpected {
			if response != nil && !response.IsError() {
				t.Fatalf("expected error response: %#v", *response)
			}
			return
		}
		if response == nil {
			t.Fatal("expected non-nil response")
		}
		if response.IsError() {
			t.Fatalf("not expected error response: %#v", *response)
		}
		value, ok := response.Data["valid"]
		if !ok {
			t.Fatalf("no valid key found in response data %#v", response.Data)
		}
		if validSignature && !value.(bool) {
			t.Fatalf("not expected failing signature verification %#v %#v", *req, *response)
		}
		if !validSignature && value.(bool) {
			t.Fatalf("expected failing signature verification %#v %#v", *req, *response)
		}
	}

	req.Data = map[string]interface{}{
		"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
	}

	signature := signRequest(req, "test", false)
	verifyRequest(req, "test", false, true, signature)
	verifyRequest(req, "test2", false, false, signature)

	// Test non existent key
	signRequest(req, "notfound", true)
	verifyRequest(req, "notfound", true, false, signature)

	// Test bad input
	req.Data["input"] = "foobar"
	signRequest(req, "test", true)
	verifyRequest(req, "test", true, false, signature)
}
