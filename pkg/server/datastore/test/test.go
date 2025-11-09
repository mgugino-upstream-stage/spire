// Package dstest contains the refactored test logic for datastore CRUD operations.
// This package is located at .../datastore/test/dstest.
package dstest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	ctx = context.Background()
)

// TestCountAttestedNodes tests counting attested nodes
func TestCountAttestedNodes(t *testing.T, ds datastore.DataStore) {
	// Count empty attested nodes
	count, err := ds.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create attested nodes
	node := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/foo",
		AttestationDataType: "t1",
		CertSerialNumber:    "1234",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)

	node2 := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/bar",
		AttestationDataType: "t2",
		CertSerialNumber:    "5678",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = ds.CreateAttestedNode(ctx, node2)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(2), count)
}

// TestCountRegistrationEntries tests counting registration entries
func TestCountRegistrationEntries(t *testing.T, ds datastore.DataStore) {
	// Count empty registration entries
	count, err := ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create entries
	entry := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "a", Value: "1"}},
	}
	_, err = ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)

	entry2 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "a", Value: "2"}},
	}
	_, err = ds.CreateRegistrationEntry(ctx, entry2)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(2), count)
}
