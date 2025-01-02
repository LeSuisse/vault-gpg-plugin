package gpg

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
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
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	decrypt := func(keyName, ciphertext, format, signerKey, expected string) {
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "decrypt/" + keyName,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
				"signer_key": signerKey,
			},
		}

		resp, err := b.HandleRequest(context.Background(), reqDecrypt)
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
	decrypt("test", encryptedMessageASCIIArmored, "ascii-armor", "", expected)
	decrypt("test", encryptedMessageBase64Encoded, "base64", "", expected)
	decrypt("test", encryptedAndSignedMessageASCIIArmored, "ascii-armor", publicSignerKey, expected)
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
	_, err := b.HandleRequest(context.Background(), req)
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
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	decryptMustFail := func(keyName, ciphertext, format, signerKey string) {
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "decrypt/" + keyName,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
				"signer_key": signerKey,
			},
		}

		resp, _ := b.HandleRequest(context.Background(), reqDecrypt)
		if !resp.IsError() {
			t.Fatalf(
				"expected to fail, keyname: %s, format: %s, cipertext: %s, signer key %s",
				keyName, format, ciphertext, signerKey)
		}
	}

	decryptMustFail("doNotExist", encryptedMessageASCIIArmored, "ascii-armor", "")
	decryptMustFail("test", encryptedMessageASCIIArmored, "invalidFormat", "")

	// Wrong key for the message
	decryptMustFail("testGenerated", encryptedMessageASCIIArmored, "ascii-armor", "")

	// Wrongly encoded
	decryptMustFail("test", "Not ASCII armored", "ascii-armor", "")
	decryptMustFail("test", "Not base64 encoded", "base64", "")

	// Signer key is not properly ASCII-armored
	decryptMustFail("test", encryptedMessageASCIIArmored, "ascii-armor", "Signer key is not ASCII armored")

	// Message is not signed
	decryptMustFail("test", encryptedMessageASCIIArmored, "ascii-armor", publicSignerKey)

	// Message is signed but signature does not match the signer key
	decryptMustFail("test", encryptedAndSignedMessageASCIIArmored, "ascii-armor", privateDecryptKey)
}

//nolint:gosec
const privateDecryptKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
2YDbdwbm17gtImItk0iYTmX7FdFf
=Loke
-----END PGP PRIVATE KEY BLOCK-----`

const publicSignerKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGHLDqgBCAC2QnUcw8FRQPrYOjdTsiflG2ZRZtf4GxmFlia2mPRcQ6BoDLUG
F/ozS4jfYrkoSEJjs2WHqgoev/yKg3fFf+hasK221YuAHOPs3yUe6XP4GVL6Xrto
pEKxwRwCcT9UZrKMYw1ZBf3dJSIqpDCG4tqkfJNH/GTgq1eBWEpCwSylZfCLRTj6
F01YQGNfR40hzfxZHVueIZetSfir3BBKtfnSrqgY41k7JB5aS7fpaWF71th7OD/v
o1/pbUqM4qTXudb5+j0BKGb9B0tEW9uBGiobcYeTP5QndhgYru6sNJmyTJyUVO60
3tUt0FY39h96uVESJL3OWLmsKiluL3SGLTFDABEBAAG0K1ZhdWx0IFNpZ25lciBL
ZXkgPHZhdWx0LXNpZ25lckBleGFtcGxlLmNvbT6JAU4EEwEKADgWIQQChkS+IStG
aZJ7rPfC/1AzTvChkQUCYcsOqAIbAwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAK
CRDC/1AzTvChkQ/kB/4hx5PR9pOc8zZsp2ubSEpACaS3xW21qywIhFn6v2smrfat
pHPR9eX8Eiw9BLAIvnEBagACx2uNhwmdfrX53T95brg5gl923E4LmQa2yfx8FbGm
G5KhOMWkbLEVT27ZH//viZSHxIIFb9hakt2+enmDQdaqJAAcJJ2Kw7yA8PO1kE9B
7Alq0syr1E8LCFOCLsw04MLBxG9i+3EQ8Qc9lTnBYAc/c4bJ1k69iAl/rTmik1JD
qeI5MIfF2nAxojAWR9ZE5xJ/T+Zzi6t+7gcjkOHpQ+hH7qfCF7RbuboLtyh5AI84
N20g1NxMKaa365ZJHXisj8vCi3IhIOJ8BqHjPvSluQENBGHLDqgBCADYO3xF0mPu
Bda/7h4AtSdGCaYLrJ/z81XMZ7m9PG/aIwJY8xAm+IU57fOMFWunoJL0XP35gqKf
p5z3MJn+fwRittrkF/PaS4HY/KohLCZK5+eV+rY50WPdifg72b/nL5W1/9LWI+3q
hVVn7JbILroSJBJpRnIbvyidzLPRUxa5n4Hvvq2qfOXxTwBXj1i5XED6yEVlDApF
1NBtcmBmFqlhtukSVvKJJ9by9Sjm7yYBd3ifBMGqFAAKqqRH57906+YHu2Ernf+k
W2RqUpB8YI1NyB3X43KA6uKz58xDU+5EUGqxWCHIPVnl+vSGSIgEly/on2wKYHr/
mQUtp19WD5aLABEBAAGJATYEGAEKACAWIQQChkS+IStGaZJ7rPfC/1AzTvChkQUC
YcsOqAIbDAAKCRDC/1AzTvChkWODB/4nKABzobWsTQ8cPmgxHtJrF+6QtwwI+ccj
6kaNXFrRK5h1LSusWLkqBepn9CFrIHXxqdttR+RlBmMETOK9FMiKFp9A9ft47Ya3
fNyDUPKG/kcxaoQmm9K8reKI+OUUQtEHYL37dms8xJsedFqlbZq4MmeGJpsCaaH8
IAIrnTKxCZzAVYdC/g82QhhnqiSP4+dCz5yh+cL4+x7PQ5sqmgzPomxTP4liPlO5
R1vIv772vYtCvaKLeZdtvunRyUOZTsyowV0fvzxxo2ic9r58i5BWsdWpVDQFDyVg
NOn4BigCovbwJOvc2lZp3yCbziNQbZ73lnXplkzttOBHrxCWEraa
=z6Xe
-----END PGP PUBLIC KEY BLOCK-----`

const encryptedMessageASCIIArmored = `-----BEGIN PGP MESSAGE-----

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

const encryptedAndSignedMessageASCIIArmored = `-----BEGIN PGP MESSAGE-----

hQEMA923ECy/uCBhAQf8Dl9qT0wQYKV/HnkTOlX082PfrM15llh7hKKKzjKNZY6W
oBXrGLb9PYyQDY8YuL0ao8xxzrk/3wcbRLjaD+4N9Mhb3fiyInKUsBdVoTyRDG31
O4yic0FTG2gPoLAgDpRVMG2PsZIoke978g2pGDmSIqne+Plvw1rk8iviFAeoiYKp
L+UQGbwT88JHjgG9DLJFnKgxTXCyFu4whsSyrbFafiKczcgY8Wk3EXWpUk7oUbWC
FWYKNAMx7tpjAHXxp9Ua4CdlGEPUBB10ytkZJFnStW9sG52ODQWBvAnudUcAEr88
8ez1jAY5N1hzdbcpe6HUSfkC+prdKAQHEKUfO+5xNtLAyQFAWDg+HcYQDCKY2713
KUzbyZQAPedXvZ1golbvzD4NL+0/mQDmD+mdSLIlATQkqW6m8lATuqu35v+AfmBq
BbzOLWlMc6BC0ownza6buggC6q1Xr7TgcarlnTbxkikFd3spbWMqFU1Dr4IKIBpe
q//ijmLTRELqot59Ucfy9Dhm0n0pwuNjiPBRjZ4LxYM1N70uvKV4R74UoumErBXn
2uzzYLSM/D5pBoFet5AVlWkwIMOqlC1Zx42xrnJhSSLvF0+eUBxaxXrEO4yN2nCU
NgSpMemH61FIoT/bWpaq0wG/X0EQgnRsjoy0uZqp/dxLUUxLm46vq2uq44tZ5Gu+
fSxDoJ8zTa5e+MEbyEIS5WI3VW8T46Qa3Rg1IsfOhBPeQBdtPcvad1nsuNVkieMp
+3ltaF3p5fbFcm4bCZdw6sqc6wkkrF5IY+X6FfqfzK3u+d4675TVQuMkWlrsVpCq
S4KHrrIA2G+eVRFHdFyX0rCImsjynuzqOqWLfmD7J32I77xQgYVsnqFE1Q==
=bD+C
-----END PGP MESSAGE-----`
