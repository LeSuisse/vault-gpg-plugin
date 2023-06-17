package gpg

import (
	"context"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
)

type ClientMock struct {
	CreateLogEntryFunc func(rekorServerUrl string, params *entries.CreateLogEntryParams) (*entries.CreateLogEntryCreated, error)
}

func (mock *ClientMock) CreateLogEntry(rekorServerURL string, params *entries.CreateLogEntryParams) (*entries.CreateLogEntryCreated, error) {
	return mock.CreateLogEntryFunc(rekorServerURL, params)
}

func TestGPG_RejectsUploadWithNoData(t *testing.T) {
	b := Backend()

	_, err := b.uploadToTransparencyLog(context.Background(), "https://rekor.example.com", []byte(""), []byte(""), []byte(""))
	if err == nil {
		t.Fatalf("expected an error")
	}
}
