package gpg

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
)

func TestGPG_SignVerify(t *testing.T) {
	var b *backend
	storage := &logical.InmemStorage{}

	b = Backend()
	mockClient := &ClientMock{
		CreateLogEntryFunc: func(rekorServerUrl string, params *entries.CreateLogEntryParams) (*entries.CreateLogEntryCreated, error) {
			return &entries.CreateLogEntryCreated{
				ETag:     "some-uuid",
				Location: "/path/to/entry",
			}, nil
		},
	}
	b.transparencyLogClient = mockClient

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
			"real_name":                "Vault GPG test2",
			"email":                    "vault@example.com",
			"transparency_log_address": "https://rekor.example.com",
		},
	}
	req3 := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test3",
		Data: map[string]interface{}{
			"real_name":                "Vault GPG test3",
			"email":                    "vault@example.com",
			"transparency_log_address": "/broken_address",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), req3)
	if err != nil {
		t.Fatal(err)
	}

	signRequest := func(req *logical.Request, keyName string, errExpected bool, postpath string) (string, map[string]string) {
		req.Path = "sign/" + keyName + postpath
		response, err := b.HandleRequest(context.Background(), req)
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
			return "", map[string]string{}
		}
		if response.IsError() {
			t.Fatalf("not expected error response: %#v", *response)
		}
		signature, ok := response.Data["signature"]
		if !ok {
			t.Fatalf("no signature found in response data: %#v", response.Data)
		}
		logEntry, ok := response.Data["log_entry"]
		if !ok {
			t.Fatalf("no log_entry found in response data: %#v", response.Data)
		}
		return signature.(string), logEntry.(map[string]string)
	}

	verifyRequest := func(req *logical.Request, keyName string, errExpected, validSignature bool, signature string) {
		req.Path = "verify/" + keyName
		req.Data["signature"] = signature
		response, err := b.HandleRequest(context.Background(), req)
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

	// Test defaults
	signature, logEntry := signRequest(req, "test", false, "")
	if logEntry != nil {
		t.Fatalf("expected no log entry %#v %#v", *req, logEntry)
	}
	verifyRequest(req, "test", false, true, signature)
	verifyRequest(req, "test2", false, false, signature)

	// Test algorithm selection in path
	signature, _ = signRequest(req, "test", false, "/sha2-224")
	verifyRequest(req, "test", false, true, signature)

	// Test algorithm selection in the data
	req.Data["algorithm"] = "sha2-224"
	signature, _ = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "sha2-384"
	signature, _ = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "sha2-512"
	signature, _ = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "notexisting"
	signRequest(req, "test", true, "")
	delete(req.Data, "algorithm")

	// Test format selection
	req.Data["format"] = "ascii-armor"
	signature, _ = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	// Test submission log entry
	req.Data["format"] = "base64"
	_, logEntry = signRequest(req, "test2", false, "")
	if !reflect.DeepEqual(logEntry, map[string]string{"uuid": "some-uuid", "address": "https://rekor.example.com/path/to/entry"}) {
		t.Fatalf("expected a specific log entry %#v %#v", *req, logEntry)
	}

	// Test error when signature cannot be published to the transparency log
	b.transparencyLogClient = &RekorClient{}
	signRequest(req, "test3", true, "")

	// Test validation format mismatch
	req.Data["format"] = "ascii-armor"
	signature, _ = signRequest(req, "test", false, "")
	req.Data["format"] = "base64"
	verifyRequest(req, "test", false, false, signature)

	// Test bad format
	req.Data["format"] = "notexisting"
	signRequest(req, "test", true, "")
	verifyRequest(req, "test", true, true, signature)
	delete(req.Data, "format")

	// Test non existent key
	signRequest(req, "notfound", true, "")
	verifyRequest(req, "notfound", true, false, signature)

	// Test bad input
	req.Data["input"] = "foobar"
	signRequest(req, "test", true, "")
	verifyRequest(req, "test", true, false, signature)
}
