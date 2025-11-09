package dstest

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/stretchr/testify/require"
)

// TestCreateJoinToken tests creating join tokens using the provided datastore
func TestCreateJoinToken(t *testing.T, ds datastore.DataStore) {
	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: time.Now().Truncate(time.Second),
	}
	err := ds.CreateJoinToken(ctx, req)
	require.NoError(t, err)

	// Make sure we can't re-register
	err = ds.CreateJoinToken(ctx, req)
	require.NotNil(t, err)
}

// TestCreateAndFetchJoinToken tests creating and fetching a join token
func TestCreateAndFetchJoinToken(t *testing.T, ds datastore.DataStore) {
	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken)
	require.NoError(t, err)

	res, err := ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	require.Equal(t, "foobar", res.Token)
	require.True(t, now.Equal(res.Expiry))
}

// TestDeleteJoinToken tests deleting join tokens
func TestDeleteJoinToken(t *testing.T, ds datastore.DataStore) {
	now := time.Now().Truncate(time.Second)
	joinToken1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken1)
	require.NoError(t, err)

	joinToken2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}

	err = ds.CreateJoinToken(ctx, joinToken2)
	require.NoError(t, err)

	err = ds.DeleteJoinToken(ctx, joinToken1.Token)
	require.NoError(t, err)

	// Should not be able to fetch after delete
	resp, err := ds.FetchJoinToken(ctx, joinToken1.Token)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Second token should still be present
	resp, err = ds.FetchJoinToken(ctx, joinToken2.Token)
	require.NoError(t, err)
	require.Equal(t, joinToken2, resp)
}

// TestPruneJoinTokens tests pruning of expired join tokens
func TestPruneJoinTokens(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken)
	require.NoError(t, err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	err = ds.PruneJoinTokens(ctx, now.Add(-time.Second*10))
	require.NoError(t, err)

	resp, err := ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.Token)

	// Ensure we don't prune on the exact ExpiresBefore
	err = ds.PruneJoinTokens(ctx, now)
	require.NoError(t, err)

	resp, err = ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	require.NotNil(t, resp, "token was unexpectedly pruned")
	require.Equal(t, "foobar", resp.Token)

	// Ensure we prune old tokens
	err = ds.PruneJoinTokens(ctx, now.Add(time.Second*10))
	require.NoError(t, err)

	resp, err = ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	require.Nil(t, resp)
}
