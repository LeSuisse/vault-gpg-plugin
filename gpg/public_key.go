package gpg

import (
	"bytes"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func extractPublicKey(entity *openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	err = entity.Serialize(w)
	if err != nil || w.Close() != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
