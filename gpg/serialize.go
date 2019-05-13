package gpg

import (
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
)

// openpgp.Serialize does not serialize the revocation signature packets. This method
// implements exporting a public key along with it's corresponding revocations.
func serializeWithRevocations(w io.Writer, e *openpgp.Entity) (err error) {
	err = e.PrimaryKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, rev := range e.Revocations {
		err = rev.Serialize(w)
		if err != nil {
			return err
		}
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return err
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

// openpgp.SerializePrivate resigns the subkeys and drops the signature on identity
// done by other users which shows trust in a key. This method implements a clean export of
// the key preserving the aformentioned signatures.
func serializeEntityWithAllSignatures(w io.Writer, e *openpgp.Entity) error {
	var err error

	if e.PrivateKey != nil {
		err = e.PrivateKey.Serialize(w)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("No private key has been found")
	}

	for _, r := range e.Revocations {
		err = r.Serialize(w)
		if err != nil {
			return err
		}
	}

	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	for _, subkey := range e.Subkeys {
		if subkey.PrivateKey != nil {
			err = subkey.PrivateKey.Serialize(w)
			if err != nil {
				return err
			}
		}

		err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, nil)
		if err != nil {
			return err
		}
		// Re-sign the embedded signature as well if it exists.
		if subkey.Sig.EmbeddedSignature != nil {
			err = subkey.Sig.EmbeddedSignature.CrossSignKey(subkey.PublicKey, e.PrimaryKey,
				subkey.PrivateKey, nil)
			if err != nil {
				return err
			}
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// serializePublicSubkey serializes the public primary key, associated revocations and identities
// with signatures along with the specified subkey. This method will be used to export a single
// subkey associated with a primary key.
func serializePublicSubkey(w io.Writer, e *openpgp.Entity, subkey *openpgp.Subkey) error {
	err := e.PrimaryKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, rev := range e.Revocations {
		err = rev.Serialize(w)
		if err != nil {
			return err
		}
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	if subkey.PublicKey != nil {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return err
		}
	}
	err = subkey.Sig.Serialize(w)
	if err != nil {
		return err
	}
	return nil
}
