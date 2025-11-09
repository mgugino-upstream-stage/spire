package dstest

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/gogo/status"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// TestBundleCRUD tests basic bundle CRUD operations using the provided datastore
func TestBundleCRUD(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", cert)
	nonExistentBundle := bundleutil.BundleProtoFromRootCA("spiffe://foox", cert)
	// fetch non-existent
	fb, err := ds.FetchBundle(ctx, "spiffe://foox")
	require.NoError(t, err)
	require.Nil(t, fb)

	// update non-existent
	_, err = ds.UpdateBundle(ctx, nonExistentBundle, nil)
	//spiretest.RequireGRPCStatus(t, err, codes.NotFound, "bundle not found for trust domain: spiffe://foox")

	// delete non-existent
	err = ds.DeleteBundle(ctx, "spiffe://foox", datastore.Restrict)
	//spiretest.RequireGRPCStatus(t, err, codes.OK, "")

	// create
	_, err = ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// create again (constraint violation)
	_, err = ds.CreateBundle(ctx, bundle)
	assert.Equal(t, status.Code(err), codes.AlreadyExists)

	// fetch
	fb, err = ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, fb)

	// list
	lresp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(lresp.Bundles))
	spiretest.AssertProtoEqual(t, bundle, lresp.Bundles[0])

	bundle2 := bundleutil.BundleProtoFromRootCA(bundle.TrustDomainId, cacert)
	appendedBundle := bundleutil.BundleProtoFromRootCAs(bundle.TrustDomainId,
		[]*x509.Certificate{cert, cacert})
	appendedBundle.SequenceNumber++

	// append
	ab, err := ds.AppendBundle(ctx, bundle2)
	require.NoError(t, err)
	require.NotNil(t, ab)
	spiretest.AssertProtoEqual(t, appendedBundle, ab)
	// stored bundle was updated
	bundle.SequenceNumber = appendedBundle.SequenceNumber

	// append identical
	ab, err = ds.AppendBundle(ctx, bundle2)
	require.NoError(t, err)
	require.NotNil(t, ab)
	spiretest.AssertProtoEqual(t, appendedBundle, ab)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", cacert)
	fmt.Printf("Creating new bundle3: TrustDomain=%s, RootCAs=%d certs\n", bundle3.TrustDomainId, len(bundle3.RootCas))
	ab, err = ds.AppendBundle(ctx, bundle3)
	require.NoError(t, err)
	fmt.Printf("Appended bundle3 result: TrustDomain=%s, RootCAs=%d certs\n", ab.TrustDomainId, len(ab.RootCas))
	spiretest.AssertProtoEqual(t, bundle3, ab)

	// update with mask: RootCas
	fmt.Printf("Before update bundle: TrustDomain=%s, RootCAs=%d certs\n", bundle.TrustDomainId, len(bundle.RootCas))
	updatedBundle, err := ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RootCas: true,
	})
	require.NoError(t, err)
	fmt.Printf("After update bundle result: TrustDomain=%s, RootCAs=%d certs\n", updatedBundle.TrustDomainId, len(updatedBundle.RootCas))
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)

	AssertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: RefreshHint
	bundle.RefreshHint = 60
	updatedBundle, err = ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RefreshHint: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	// update with mask: SequenceNumber
	bundle.SequenceNumber = 100
	updatedBundle, err = ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		SequenceNumber: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)
	assert.Equal(t, bundle.SequenceNumber, updatedBundle.SequenceNumber)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	AssertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: JwtSingingKeys
	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "jwt-key-1"}}
	updatedBundle, err = ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		JwtSigningKeys: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	AssertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update without mask
	updatedBundle, err = ds.UpdateBundle(ctx, bundle2, nil)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle2, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	AssertBundlesEqual(t, []*common.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	err = ds.DeleteBundle(ctx, bundle.TrustDomainId, datastore.Restrict)
	require.NoError(t, err)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(lresp.Bundles))
	spiretest.AssertProtoEqual(t, bundle3, lresp.Bundles[0])
}

// AssertBundlesEqual asserts that the two bundle lists are equal independent
// of ordering.
func AssertBundlesEqual(t *testing.T, expected, actual []*common.Bundle) {
	if !assert.Equal(t, len(expected), len(actual)) {
		return
	}

	es := map[string]*common.Bundle{}
	as := map[string]*common.Bundle{}

	for _, e := range expected {
		es[e.TrustDomainId] = e
	}

	for _, a := range actual {
		as[a.TrustDomainId] = a
	}

	for id, a := range as {
		e, ok := es[id]
		if assert.True(t, ok, "bundle %q was unexpected", id) {
			spiretest.AssertProtoEqual(t, e, a)
			delete(es, id)
		}
	}

	for id := range es {
		assert.Failf(t, "bundle %q was expected but not found", id)
	}
}

func TestListBundlesWithPaginationNoSQL(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://a", cert)
	_, err := ds.CreateBundle(ctx, bundle1)
	require.NoError(t, err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://b", cacert)
	_, err = ds.CreateBundle(ctx, bundle2)
	require.NoError(t, err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://c", cert)
	_, err = ds.CreateBundle(ctx, bundle3)
	require.NoError(t, err)

	bundle4 := bundleutil.BundleProtoFromRootCA("spiffe://d", cert)
	_, err = ds.CreateBundle(ctx, bundle4)
	require.NoError(t, err)
	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*common.Bundle
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoListEqual(t, test.expectedList, resp.Bundles)
			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
	nextToken := ""
	t.Run("page through all bundles", func(t *testing.T) {
		pageSize := 2
		collectedBundles := []*common.Bundle{}
		for {
			resp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{
				Pagination: &datastore.Pagination{
					Token:    nextToken,
					PageSize: int32(pageSize),
				},
			})
			require.NoError(t, err)
			collectedBundles = append(collectedBundles, resp.Bundles...)
			nextToken = resp.Pagination.Token
			if resp.Pagination == nil || resp.Pagination.Token == "" {
				break
			}
		}
		spiretest.RequireProtoListEqual(t, []*common.Bundle{bundle1, bundle2, bundle3, bundle4}, collectedBundles)
	})
	// assert nextToken is empty again
	require.Equal(t, "", nextToken)
}

// TestListBundlesWithPagination tests bundle pagination functionality
func TestListBundlesWithPagination(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://a", cert)
	_, err := ds.CreateBundle(ctx, bundle1)
	require.NoError(t, err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://b", cacert)
	_, err = ds.CreateBundle(ctx, bundle2)
	require.NoError(t, err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://c", cert)
	_, err = ds.CreateBundle(ctx, bundle3)
	require.NoError(t, err)

	bundle4 := bundleutil.BundleProtoFromRootCA("spiffe://d", cert)
	_, err = ds.CreateBundle(ctx, bundle4)
	require.NoError(t, err)

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*common.Bundle
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "bundles first page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*common.Bundle{bundle1, bundle2},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "bundles second page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*common.Bundle{bundle3, bundle4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name:         "bundles third page",
			expectedList: []*common.Bundle{},
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
		},
		{
			name:         "invalid token",
			expectedList: []*common.Bundle{},
			expectedErr:  "rpc error: code = InvalidArgument desc = could not parse token 'invalid token'",
			pagination: &datastore.Pagination{
				Token:    "invalid token",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoListEqual(t, test.expectedList, resp.Bundles)
			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
}

// TestSetBundle tests basic bundle set operations using the provided datastore
func TestSetBundle(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	// create a couple of bundles for tests. the contents don't really matter
	// as long as they are for the same trust domain but have different contents.
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", cert)
	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", cacert)

	// ensure the bundle does not exist (it shouldn't)
	fb := fetchBundle(t, ds, "spiffe://foo")
	require.Nil(t, fb)

	// set the bundle and make sure it is created
	_, err := ds.SetBundle(ctx, bundle)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, fetchBundle(t, ds, "spiffe://foo"))

	// set the bundle and make sure it is updated
	_, err = ds.SetBundle(ctx, bundle2)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle2, fetchBundle(t, ds, "spiffe://foo"))
}

// TestBundlePrune tests bundle pruning functionality using the provided datastore
func TestBundlePrune(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	// Setup
	// Create new bundle with two cert (one valid and one expired)
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{cert, cacert})
	bundle.SequenceNumber = 42

	// Add two JWT signing keys (one valid and one expired)
	expiredNotAfterString := "2018-01-10T01:34:00+00:00"
	validNotAfterString := "2018-01-10T01:36:00+00:00"
	middleTimeString := "2018-01-10T01:35:00+00:00"

	expiredKeyTime, err := time.Parse(time.RFC3339, expiredNotAfterString)
	require.NoError(t, err)

	nonExpiredKeyTime, err := time.Parse(time.RFC3339, validNotAfterString)
	require.NoError(t, err)

	// middleTime is a point between the two certs expiration time
	middleTime, err := time.Parse(time.RFC3339, middleTimeString)
	require.NoError(t, err)

	bundle.JwtSigningKeys = []*common.PublicKey{
		{NotAfter: expiredKeyTime.Unix()},
		{NotAfter: nonExpiredKeyTime.Unix()},
	}
	// Store bundle in datastore
	_, err = ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)
	// Prune
	// prune non existent bundle should not return error, no bundle to prune
	expiration := time.Now()
	changed, err := ds.PruneBundle(ctx, "spiffe://notexistent", expiration)
	require.NoError(t, err)
	require.False(t, changed)

	// prune fails if internal prune bundle fails. For instance, if all certs are expired
	expiration = time.Now()
	changed, err = ds.PruneBundle(ctx, bundle.TrustDomainId, expiration)
	spiretest.RequireGRPCStatus(t, err, codes.Unknown, "prune failed: would prune all certificates")
	require.False(t, changed)

	// prune should remove expired certs
	changed, err = ds.PruneBundle(ctx, bundle.TrustDomainId, middleTime)
	require.NoError(t, err)
	require.True(t, changed)

	// Fetch and verify pruned bundle is the expected
	expectedPrunedBundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{cert})
	expectedPrunedBundle.JwtSigningKeys = []*common.PublicKey{{NotAfter: nonExpiredKeyTime.Unix()}}
	expectedPrunedBundle.SequenceNumber = 43
	fb, err := ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, expectedPrunedBundle, fb)
}

// TestCountBundles tests count bundles functionality using the provided datastore
func TestCountBundles(t *testing.T, ds datastore.DataStore, cert, cacert *x509.Certificate) {
	// Count empty bundles
	count, err := ds.CountBundles(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create bundles
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://example.org", cert)
	_, err = ds.CreateBundle(ctx, bundle1)
	require.NoError(t, err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", cacert)
	_, err = ds.CreateBundle(ctx, bundle2)
	require.NoError(t, err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", cert)
	_, err = ds.CreateBundle(ctx, bundle3)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountBundles(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(3), count)
}
