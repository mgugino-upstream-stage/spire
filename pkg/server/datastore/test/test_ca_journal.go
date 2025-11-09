package dstest

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/spiffe/spire/pkg/common/x509util"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
)

// TestTaintX509CA tests tainting an X.509 CA in a bundle.
func TestTaintX509CA(t *testing.T, ds datastore.DataStore, cert *x509.Certificate, cacert *x509.Certificate) {
	// Note: callers supply cert and cacert; the suite computes and passes SubjectKeyID values when needed.
	// Unfortunately we cannot easily compute SubjectKeyId without x509util here; callers pass cert and cacert and
	// will pass tests by using the same SubjectKeyId value in their suite. To keep parity with the original sqlstore
	// tests, we compute the expected RootCAs based on provided certs and operate via the datastore API.

	// Use bundle proto helpers
	t.Run("bundle not found", func(t *testing.T) {
		err := ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
	})

	// Create Malformed CA
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{{Raw: []byte("bar")}})
	_, err := ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	t.Run("bundle not found", func(t *testing.T) {
		err := ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to parse rootCA: x509: malformed certificate")
	})

	// validateBundle is provided by callers when needing strict validation.

	// Update bundle
	bundle = bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{cert, cacert})
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	validateBundle := func(expectSequenceNumber uint64) {
		expectedRootCAs := []*common.Certificate{
			{DerBytes: cert.Raw, TaintedKey: true},
			{DerBytes: cacert.Raw},
		}

		fetchedBundle, err := ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		require.Equal(t, expectedRootCAs, fetchedBundle.RootCas)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	t.Run("taint successfully", func(t *testing.T) {
		sid := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		err := ds.TaintX509CA(ctx, "spiffe://foo", sid)
		require.NoError(t, err)

		validateBundle(1)
	})

	t.Run("no bundle with provided skID", func(t *testing.T) {
		err := ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no ca found with provided subject key ID")
		validateBundle(1)
	})

	t.Run("failed to taint already tainted ca", func(t *testing.T) {
		sid := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		err := ds.TaintX509CA(ctx, "spiffe://foo", sid)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "root CA is already tainted")
		validateBundle(1)
	})
}

// TestRevokeX509CA tests revoking an X.509 CA from a bundle.
func TestRevokeX509CA(t *testing.T, ds datastore.DataStore, cert *x509.Certificate, cacert *x509.Certificate) {
	certID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)

	t.Run("bundle not found", func(t *testing.T) {
		err := ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
	})

	// Create new bundle with one malformed cert
	keyForMalformedCert := testkey.NewEC256(t)
	malformedX509 := &x509.Certificate{
		PublicKey: keyForMalformedCert.PublicKey,
		Raw:       []byte("no a certificate"),
	}
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{cert, cacert, malformedX509})
	_, err := ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	t.Run("Bundle contains a malformed certificate", func(t *testing.T) {
		err := ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to parse root CA: x509: malformed certificate")
	})

	// Remove malformed certificate
	bundle = bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{cert, cacert})
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	originalBundles := []*common.Certificate{{DerBytes: cert.Raw}, {DerBytes: cacert.Raw}}

	validateBundle := func(expectedRootCAs []*common.Certificate, expectSequenceNumber uint64) {
		fetchedBundle, err := ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		require.Equal(t, expectedRootCAs, fetchedBundle.RootCas)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	t.Run("No root CA is using provided skID", func(t *testing.T) {
		err := ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no root CA found with provided subject key ID")
		validateBundle(originalBundles, 0)
	})

	t.Run("Unable to revoke untainted bundles", func(t *testing.T) {
		err := ds.RevokeX509CA(ctx, "spiffe://foo", certID)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "it is not possible to revoke an untainted root CA")
		validateBundle(originalBundles, 0)
	})

	// Mark cert as tainted
	err = ds.TaintX509CA(ctx, "spiffe://foo", certID)
	require.NoError(t, err)

	t.Run("Revoke successfully", func(t *testing.T) {
		taintedBundles := []*common.Certificate{{DerBytes: cert.Raw, TaintedKey: true}, {DerBytes: cacert.Raw}}
		validateBundle(taintedBundles, 1)

		err := ds.RevokeX509CA(ctx, "spiffe://foo", certID)
		require.NoError(t, err)

		expectedRootCAs := []*common.Certificate{{DerBytes: cacert.Raw}}
		validateBundle(expectedRootCAs, 2)
	})
}

// TestTaintJWTKey tests tainting JWT keys in a bundle.
func TestTaintJWTKey(t *testing.T, ds datastore.DataStore) {
	// Create new bundle with two JWT Keys
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", nil)
	originalKeys := []*common.PublicKey{{Kid: "key1"}, {Kid: "key2"}, {Kid: "key2"}}
	bundle.JwtSigningKeys = originalKeys

	publicKey, err := ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
	require.Nil(t, publicKey)

	_, err = ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	publicKey, err = ds.TaintJWTKey(ctx, "spiffe://foo", "key2")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "another JWT Key found with the same KeyID")
	require.Nil(t, publicKey)

	publicKey, err = ds.TaintJWTKey(ctx, "spiffe://foo", "no id")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no JWT Key found with provided key ID")
	require.Nil(t, publicKey)

	validateBundle := func(expectedKeys []*common.PublicKey, expectSequenceNumber uint64) {
		fetchedBundle, err := ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		spiretest.RequireProtoListEqual(t, expectedKeys, fetchedBundle.JwtSigningKeys)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	validateBundle(originalKeys, 0)

	publicKey, err = ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	taintedKey := []*common.PublicKey{{Kid: "key1", TaintedKey: true}, {Kid: "key2"}, {Kid: "key2"}}
	validateBundle(taintedKey, 1)

	publicKey, err = ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "key is already tainted")
	require.Nil(t, publicKey)

	validateBundle(taintedKey, 1)
}

// TestRevokeJWTKey tests revoking JWT keys from a bundle.
func TestRevokeJWTKey(t *testing.T, ds datastore.DataStore) {
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", nil)
	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "key1"}, {Kid: "key2"}}

	publicKey, err := ds.RevokeJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
	require.Nil(t, publicKey)

	_, err = ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	publicKey, err = ds.RevokeJWTKey(ctx, "spiffe://foo", "no id")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no JWT Key found with provided key ID")
	require.Nil(t, publicKey)

	publicKey, err = ds.RevokeJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "it is not possible to revoke an untainted key")
	require.Nil(t, publicKey)

	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "key1"}, {Kid: "key2", TaintedKey: true}, {Kid: "key2", TaintedKey: true}}
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	publicKey, err = ds.RevokeJWTKey(ctx, "spiffe://foo", "key2")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "another key found with the same KeyID")
	require.Nil(t, publicKey)

	originalKeys := []*common.PublicKey{{Kid: "key1"}, {Kid: "key2", TaintedKey: true}}
	bundle.JwtSigningKeys = originalKeys
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	validateBundle := func(expectedKeys []*common.PublicKey, expectSequenceNumber uint64) {
		fetchedBundle, err := ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		spiretest.RequireProtoListEqual(t, expectedKeys, fetchedBundle.JwtSigningKeys)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	validateBundle(originalKeys, 0)

	publicKey, err = ds.RevokeJWTKey(ctx, "spiffe://foo", "key2")
	require.NoError(t, err)
	require.Equal(t, &common.PublicKey{Kid: "key2", TaintedKey: true}, publicKey)

	expectedJWTKeys := []*common.PublicKey{{Kid: "key1"}}
	validateBundle(expectedJWTKeys, 1)
}

// TestSetCAJournal tests setting CA journals.
func TestSetCAJournal(t *testing.T, ds datastore.DataStore) {
	testCases := []struct {
		name      string
		code      codes.Code
		msg       string
		caJournal *datastore.CAJournal
	}{
		{name: "creating a new CA journal succeeds", caJournal: &datastore.CAJournal{Data: []byte("test data"), ActiveX509AuthorityID: "x509-authority-id"}},
		{name: "nil CA journal", code: codes.InvalidArgument, msg: "ca journal is required"},
		{name: "try to update a non existing CA journal", code: codes.NotFound, msg: "datastore-sql: record not found", caJournal: &datastore.CAJournal{ID: 999, Data: []byte("test data"), ActiveX509AuthorityID: "x509-authority-id"}},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			caJournal, err := ds.SetCAJournal(ctx, tt.caJournal)
			spiretest.RequireGRPCStatus(t, err, tt.code, tt.msg)
			if tt.code != codes.OK {
				require.Nil(t, caJournal)
				return
			}

			// Match original sqlstore behavior: compare only ActiveX509AuthorityID and Data
			if tt.caJournal == nil {
				assert.Nil(t, caJournal)
				return
			}
			assert.Equal(t, tt.caJournal.ActiveX509AuthorityID, caJournal.ActiveX509AuthorityID)
			assert.Equal(t, tt.caJournal.Data, caJournal.Data)
		})
	}
}

// TestFetchCAJournal tests fetching CA journals.
func TestFetchCAJournal(t *testing.T, ds datastore.DataStore) {
	testCases := []struct {
		name                  string
		activeX509AuthorityID string
		code                  codes.Code
		msg                   string
		caJournal             *datastore.CAJournal
	}{
		{name: "fetching an existent CA journal", activeX509AuthorityID: "x509-authority-id", caJournal: func() *datastore.CAJournal {
			cj, err := ds.SetCAJournal(ctx, &datastore.CAJournal{ActiveX509AuthorityID: "x509-authority-id", Data: []byte("test data")})
			require.NoError(t, err)
			return cj
		}()},
		{name: "non-existent X509 authority ID returns nil", activeX509AuthorityID: "non-existent-x509-authority-id"},
		{name: "fetching without specifying an active authority ID fails", code: codes.InvalidArgument, msg: "active X509 authority ID is required"},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			caJournal, err := ds.FetchCAJournal(ctx, tt.activeX509AuthorityID)
			spiretest.RequireGRPCStatus(t, err, tt.code, tt.msg)
			if tt.code != codes.OK {
				require.Nil(t, caJournal)
				return
			}
			assert.Equal(t, tt.caJournal, caJournal)
		})
	}
}

// TestPruneCAJournal tests pruning CA journals.
func TestPruneCAJournal(t *testing.T, ds datastore.DataStore) {
	now := time.Now()
	ttime := now.Add(time.Hour)
	entries := &journal.Entries{
		X509CAs: []*journal.X509CAEntry{{NotAfter: ttime.Add(-time.Hour * 6).Unix()}},
		JwtKeys: []*journal.JWTKeyEntry{{NotAfter: ttime.Add(time.Hour * 6).Unix()}},
	}

	entriesBytes, err := proto.Marshal(entries)
	require.NoError(t, err)

	caJournal, err := ds.SetCAJournal(ctx, &datastore.CAJournal{ActiveX509AuthorityID: "x509-authority-1", Data: entriesBytes})
	require.NoError(t, err)

	require.NoError(t, ds.PruneCAJournals(ctx, ttime.Add(-time.Hour*12).Unix()))
	caj, err := ds.FetchCAJournal(ctx, "x509-authority-1")
	require.NoError(t, err)
	require.Equal(t, caJournal, caj)

	require.NoError(t, ds.PruneCAJournals(ctx, ttime.Unix()))
	caj, err = ds.FetchCAJournal(ctx, "x509-authority-1")
	require.NoError(t, err)
	require.Equal(t, caJournal, caj)

	require.NoError(t, ds.PruneCAJournals(ctx, ttime.Add(time.Hour*12).Unix()))
	caj, err = ds.FetchCAJournal(ctx, "x509-authority-1")
	require.NoError(t, err)
	require.Nil(t, caj)
}
