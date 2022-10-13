package gpg

import (
	"context"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/types"
	rekordTypeEntry "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

type TransparencyLogClient interface {
	CreateLogEntry(rekorServerURL string, params *entries.CreateLogEntryParams) (*entries.CreateLogEntryCreated, error)
}

type RekorClient struct {
}

func (c RekorClient) CreateLogEntry(rekorServerURL string, params *entries.CreateLogEntryParams) (*entries.CreateLogEntryCreated, error) {
	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return nil, err
	}

	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b backend) uploadToTransparencyLog(ctx context.Context, rekorServerURL string, artifactBytes []byte, sigBytes []byte, publicKeyBytes []byte) (*entries.CreateLogEntryCreated, error) {
	params := entries.NewCreateLogEntryParams()

	props := types.ArtifactProperties{
		PKIFormat:      "pgp",
		ArtifactBytes:  artifactBytes,
		PublicKeyBytes: [][]byte{publicKeyBytes},
		SignatureBytes: sigBytes,
	}

	typeEntry := rekordTypeEntry.NewEntry()
	proposedEntry, err := typeEntry.CreateFromArtifactProperties(ctx, props)
	if err != nil {
		return nil, err
	}
	params.SetProposedEntry(proposedEntry)

	return b.transparencyLogClient.CreateLogEntry(rekorServerURL, params)
}
