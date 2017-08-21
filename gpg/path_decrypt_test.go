package gpg

import (
	"github.com/hashicorp/vault/logical"
	"testing"
)

func TestGPG_Decrypt(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
			"key":      privateDecryptKey,
		},
	}
	_, err := b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	decrypt := func(keyName, ciphertext, format, expected string) {
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "decrypt/" + keyName,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
			},
		}

		resp, err := b.HandleRequest(reqDecrypt)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("not expected error response: %#v", *resp)
		}

		if resp == nil {
			t.Fatalf("no name key found in response data %#v", resp)
		}
		plaintext, ok := resp.Data["plaintext"]
		if !ok {
			t.Fatalf("no name key found in response data %#v", resp.Data)
		}
		if plaintext != expected {
			t.Fatalf("expected plaintext %s, got: %s", expected, plaintext)
		}
	}

	expected := "QWxwYWNhcwo="
	decrypt("test", encryptedMessageAsciiArmored, "ascii-armor", expected)
	decrypt("test", encryptedMessageBase64Encoded, "base64", expected)
}

func TestGPG_DecryptError(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/testGenerated",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
		},
	}
	_, err := b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
			"key":      privateDecryptKey,
		},
	}
	_, err = b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	decryptMustFail := func(keyName, ciphertext, format string) {
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "decrypt/" + keyName,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
			},
		}

		resp, _ := b.HandleRequest(reqDecrypt)
		if !resp.IsError() {
			t.Fatalf("expected to fail, keyname: %s, format: %s, cipertext: %s", keyName, format, ciphertext)
		}
	}

	decryptMustFail("doNotExist", encryptedMessageAsciiArmored, "ascii-armor")
	decryptMustFail("test", encryptedMessageAsciiArmored, "invalidFormat")

	// Wrong key for the message
	decryptMustFail("testGenerated", encryptedMessageAsciiArmored, "ascii-armored")

	// Wrongly encoded
	decryptMustFail("test", "Not ASCII armored", "ascii-armor")
	decryptMustFail("test", "Not base64 encoded", "base64")
}

const privateDecryptKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
UWauhQ==
=2Rz1
-----END PGP PRIVATE KEY BLOCK-----`

const encryptedMessageAsciiArmored = `-----BEGIN PGP MESSAGE-----

hQEMA923ECy/uCBhAQf8DLagsnoLuM4AyKiTyvZ7uSQTkmOkwXwn1WWsxoKJkzdI
v2XJ7knQ3UR5nnhI8xVbAnZVZjx8wYaBPUvV2VqhA2sTn36mGlGw43ngDOFB1cKW
1VM9JY0xqxuHaIR3mvYFjb/iuoT2BM7SmCuIEJYgxKEM+/R1o9rkCenj2pOj4+XK
ryXv+iHQAar6Ic2G3g9T7Mu7Uw6+n1xBWr/XzPnJRJf4WB4m7sqd/Wm7NkHnvgde
P9kawh1lHYj32WdLUqZpQB3zQRguDHFfQA8vRVEG4Gyz/o7um5PFc4kDES0JYzNc
p6p64MAF+vMpSOsFU2TaixSmraidaWHVPYcao/w2UNJDAQ43l9lh064yz9bCaH41
UyEQpNH+l1EpqnIbu+iIQb3a02GwBB8lfEW7cFku8121H8XapkgKZDsmXD/7v0eW
e8iwFg==
=+yfj
-----END PGP MESSAGE-----`

const encryptedMessageBase64Encoded = `hQEMA923ECy/uCBhAQf/XPUNCcaIUyTDDQ+rII/sj24VtnBUdXDNntOtBX4pxIHzMWr6oCWGgZZV
WTRzRP4nEclUUhWKHDlEd7/1bG/1z3Px3JWXdnSCHYl3AqdFkS4bW26wpO+gcCTbiixo+JE93QoG
84rb5k6gdNGsVEpioDFK1FLGL9pPvyR+kp4JRg8qD1FpDsvow+zhJqgAak87s4Ly/YnYiVYbGjPl
u0pqEkvJwHnIyKThFW5N6OCYjB2pFpVLER7x6RGjuX6tRRYZayzT4sVKGj0Efp6T32EEVPURiJSn
elpIPEd8+8i/7X0Co6iNFEyucgxhaxN+ujqSxx+6ZIFV4UKC0LFgR2iF99JDAQ6ofxvUtoxMGKON
WVtrVMjN8Db3KXQ5rt/tyKbTVGXQot6ocSZ2Ae+rnSTiq0boGrWDnuYZHawc16iJhbcP68ERgg==`
