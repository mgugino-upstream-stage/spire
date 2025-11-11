package sqlstore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/server/datastore"
	dstest "github.com/spiffe/spire/pkg/server/datastore/test"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

func (s *PluginSuite) TestBundleCRUD() {
	dstest.TestBundleCRUD(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCountBundles() {
	dstest.TestCountBundles(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestListBundlesWithPagination() {
	dstest.TestListBundlesWithPagination(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCreateFederationRelationship() {
	dstest.TestCreateFederationRelationship(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestListFederationRelationships() {
	dstest.TestListFederationRelationships(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestUpdateFederationRelationship() {
	dstest.TestUpdateFederationRelationship(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestCreateJoinToken() {
	dstest.TestCreateJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateAndFetchJoinToken() {
	dstest.TestCreateAndFetchJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestDeleteJoinToken() {
	dstest.TestDeleteJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneJoinTokens() {
	dstest.TestPruneJoinTokens(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestSetBundle() {
	dstest.TestSetBundle(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestBundlePrune() {
	dstest.TestBundlePrune(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCountAttestedNodes() {
	dstest.TestCountAttestedNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestTaintX509CA() {
	dstest.TestTaintX509CA(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestRevokeX509CA() {
	dstest.TestRevokeX509CA(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestTaintJWTKey() {
	dstest.TestTaintJWTKey(s.T(), s.ds)
}

func (s *PluginSuite) TestRevokeJWTKey() {
	dstest.TestRevokeJWTKey(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateAttestedNode() {
	dstest.TestCreateAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestSetCAJournal() {
	dstest.TestSetCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchCAJournal() {
	dstest.TestFetchCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneCAJournal() {
	dstest.TestPruneCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneAttestedExpiredNodes() {
	dstest.TestPruneAttestedExpiredNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	dstest.TestDeleteAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestListAttestedNodeEvents() {
	dstest.TestListAttestedNodeEvents(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneAttestedNodeEvents() {
	dstest.TestPruneAttestedNodeEvents(s.T(), s.ds)
}

func (s *PluginSuite) TestNodeSelectors() {
	dstest.TestNodeSelectors(s.T(), s.ds)
}

func (s *PluginSuite) TestListNodeSelectors() {
	dstest.TestListNodeSelectors(s.T(), s.ds)
}

func (s *PluginSuite) TestListAttestedNodes() {
	dstest.TestListAttestedNodes(s.T(), func() datastore.DataStore { return s.newPlugin() })
}

func (s *PluginSuite) TestUpdateAttestedNode() {
	dstest.TestUpdateAttestedNode(s.T(), func() datastore.DataStore { return s.newPlugin() })
}

func (s *PluginSuite) TestFetchAttestedNodeMissing() {
	dstest.TestFetchAttestedNodeMissing(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchFederationRelationship() {
	// createRaw inserts a raw federated trust domain record into the SQL database.
	createRaw := func(r dstest.FederatedTrustDomainRaw) error {

		model := FederatedTrustDomain{
			TrustDomain:           r.TrustDomain,
			BundleEndpointURL:     r.BundleEndpointURL,
			BundleEndpointProfile: r.BundleEndpointProfile,
			EndpointSPIFFEID:      r.EndpointSPIFFEID,
		}

		return s.ds.db.Create(&model).Error
	}

	dstest.TestFetchFederationRelationship(s.T(), s.ds, createRaw)
}

// In your SQL provider test suite (package sqlstore_test)

func (s *PluginSuite) TestListNodeSelectorsGroupsBySpiffeID() {
	// SQL insertRaw uses the same row shape the old test expected.
	insertRaw := func(spiffeID, selectorType, selectorValue string) error {
		// Use the existing DB handle on s.ds.db.raw
		query := maybeRebind(
			s.ds.db.databaseType,
			"INSERT INTO node_resolver_map_entries (spiffe_id, type, value) VALUES (?, ?, ?)",
		)

		_, err := s.ds.db.raw.Exec(query, spiffeID, selectorType, selectorValue)
		return err
	}

	dstest.TestListNodeSelectorsGroupsBySpiffeID(s.T(), s.ds, insertRaw)
}

func (s *PluginSuite) TestDeleteFederationRelationship() {
	dstest.TestDeleteFederationRelationship(s.T(), s.ds)
}

// Haven't replicated yet

// SQL wrapper (keeps your method name; just delegates to the stand-alone test with a fresh DS)
func (s *PluginSuite) TestPruneRegistrationEntryEvents() {
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	ds, cleanup := newDS()
	defer cleanup()

	// Run the migrated test against a fresh datastore so EventIDs start at 1
	dstest.TestPruneRegistrationEntryEvents(s.T(), ds)
}

func (s *PluginSuite) TestListRegistrationEntryEvents() {
	// Delegate to the shared standalone test (no extra callbacks needed).
	dstest.TestListRegistrationEntryEvents(s.T(), s.ds)
}

func (s *PluginSuite) TestListEntriesBySelectorMatchAny() {
	// newDS: returns a fresh datastore and a cleanup that closes it
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	// loadEntries: adapt s.getTestDataFromJSONFile(path string, jsonValue any)
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries)
		*out = entries
	}

	dstest.TestListEntriesBySelectorMatchAny(
		s.T(),
		newDS,
		loadEntries,
	)
}

func (s *PluginSuite) TestListEntriesByFederatesWithSuperset() {
	// newDS: returns a fresh datastore and a cleanup that calls Close()
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		cleanup := func() { ds.Close() }
		return ds, cleanup
	}

	// loadEntries: adapt s.getTestDataFromJSONFile(path string, jsonValue any)
	// to the signature the shared test expects: func(path string, out *[]*common.RegistrationEntry)
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries)
		*out = entries
	}

	// Delegate to the shared dstest body
	dstest.TestListEntriesByFederatesWithSuperset(
		s.T(),
		newDS,       // creates a ds and auto-closes it via returned cleanup
		loadEntries, // loads testdata/entries_federates_with.json into []*common.RegistrationEntry
	)
}

func (s *PluginSuite) TestListEntriesByFederatesWithMatchAny() {
	// newDS: returns a fresh datastore and a cleanup func that closes it
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	// loadEntries: adapt s.getTestDataFromJSONFile(path, any)
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries)
		*out = entries
	}

	dstest.TestListEntriesByFederatesWithMatchAny(
		s.T(),
		newDS,
		loadEntries,
	)
}

func (s *PluginSuite) TestListEntriesByFederatesWithSubset() {
	// newDS: returns a fresh datastore, with Close() encapsulated in the cleanup func
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	// Load test entries from JSON (reusing your helper)
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)

	// Delegate to shared test body
	dstest.TestListEntriesByFederatesWithSubset(
		s.T(),
		newDS,
		allEntries,
	)
}

func (s *PluginSuite) TestListEntriesByFederatesWithExact() {
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	dstest.TestListEntriesByFederatesWithExact(
		s.T(),
		newDS,
	)
}

func (s *PluginSuite) TestListSelectorEntriesSuperset() {
	// Prepare the static test data once here
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)

	// newDS: returns a fresh datastore and a cleanup that calls Close()
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		return ds, func() { ds.Close() }
	}

	dstest.TestListSelectorEntriesSuperset(s.T(), newDS, allEntries)
}

func (s *PluginSuite) TestListEntriesBySelectorSubset() {
	// newDS: returns a fresh datastore, with Close() handled by the returned cleanup func
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		cleanup := func() { ds.Close() }
		return ds, cleanup
	}

	// loadEntries: adapt s.getTestDataFromJSONFile(path string, any) to the expected signature
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries)
		*out = entries
	}

	dstest.TestListEntriesBySelectorSubset(
		s.T(),
		newDS,
		loadEntries,
	)
}

func (s *PluginSuite) TestListSelectorEntries() {
	// newDS: returns a fresh datastore and a cleanup that closes it
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		cleanup := func() { ds.Close() }
		return ds, cleanup
	}

	// loadEntries adapts s.getTestDataFromJSONFile(path string, jsonValue any)
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries)
		*out = entries
	}

	dstest.TestListSelectorEntries(
		s.T(),
		newDS,
		loadEntries,
	)
}

func (s *PluginSuite) TestListParentIDEntries() {
	// newDS: returns a fresh datastore, with Close() hidden inside t.Cleanup
	newDS := func() (datastore.DataStore, func()) {
		ds := s.newPlugin()
		cleanup := func() { ds.Close() }
		return ds, cleanup
	}

	// loadEntries: adapt s.getTestDataFromJSONFile(path string, jsonValue any)
	// to the signature the shared test expects: func(path string, out *[]*common.RegistrationEntry)
	loadEntries := func(path string, out *[]*common.RegistrationEntry) {
		var entries []*common.RegistrationEntry
		s.getTestDataFromJSONFile(path, &entries) // uses "any" param under the hood
		*out = entries
	}

	// Delegate to the shared test body
	dstest.TestListParentIDEntries(
		s.T(),
		newDS,       // creates a ds and auto-closes via t.Cleanup
		loadEntries, // loads testdata/entries.json into []*common.RegistrationEntry
	)
}

func (s *PluginSuite) TestPruneRegistrationEntries() {
	dstest.TestPruneRegistrationEntries(
		s.T(),
		s.ds,
		s.hook, // implements AllEntries() and LastEntry()
	)
}

func (s *PluginSuite) TestCountRegistrationEntries() {
	dstest.TestCountRegistrationEntries(s.T(), s.ds)
}

// WIP, migrate the rest below

func (s *PluginSuite) TestUpdateRegistrationEntry() {
	create := func(e *common.RegistrationEntry) *common.RegistrationEntry {
		out, err := s.ds.CreateRegistrationEntry(context.Background(), e)
		s.Require().NoError(err)
		return out
	}
	dstest.TestUpdateRegistrationEntry(s.T(), s.ds, create)
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithStoreSvid() {
	create := func(e *common.RegistrationEntry) *common.RegistrationEntry {
		out, err := s.ds.CreateRegistrationEntry(context.Background(), e)
		s.Require().NoError(err)
		return out
	}
	dstest.TestUpdateRegistrationEntryWithStoreSvid(s.T(), s.ds, create)
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithMask() {
	dstest.TestUpdateRegistrationEntryWithMask(
		s.T(),
		s.ds,
		func(td string) { s.createBundle(td) },
		func(t *testing.T, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry {
			return dstest.CreateRegistrationEntry(t, ds, entry)
		},
		s.deleteRegistrationEntry,
	)
}

func (s *PluginSuite) TestDeleteRegistrationEntry() {
	create := func(e *common.RegistrationEntry) *common.RegistrationEntry {
		out, err := s.ds.CreateRegistrationEntry(context.Background(), e)
		s.Require().NoError(err)
		return out
	}
	dstest.TestDeleteRegistrationEntry(s.T(), s.ds, create)
}

func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
	ctx := context.Background()

	// Wrap into shared helper; rawDeleteBaseAll reproduces the original direct DELETE:
	rawDeleteBaseAll := func() error {
		// This matches your original direct exec against "registered_entries".
		// We preserve the rows-affected check by converting it into an error on mismatch.
		res, err := s.ds.db.raw.Exec("DELETE FROM registered_entries")
		if err != nil {
			return err
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("expected to delete 1 row from registered_entries, deleted %d", rowsAffected)
		}
		return nil
	}

	// Seed + verify via shared test (keeps business logic identical)
	dstest.TestListRegistrationEntriesWhenCruftRowsExist(s.T(), s.ds, rawDeleteBaseAll)

	// No extra assertions needed; the shared test performs the final list check:
	// resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	// s.Require().NoError(err)
	// s.Require().Empty(resp.Entries)
	_ = ctx // preserve original local variable; avoid unused warning if build tags differ
}

func (s *PluginSuite) TestListRegistrationEntries() {
	ctx := context.Background()
	// Connection is never used, each test creates new connection to a different database
	s.ds.Close()

	// Delegate to shared dstest implementation which accepts a newDS factory
	dstest.TestListRegistrationEntries(s.T(), func() datastore.DataStore { return s.newPlugin() }, s.cert, s.cacert)

	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			PageSize: 0,
		},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot paginate with pagesize = 0")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Error(err, "could not parse token 'invalid int'")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot list by empty selector set")
	s.Require().Nil(resp)
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	dstest.TestFetchInexistentRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithAgainstMissingBundle() {
	dstest.TestRegistrationEntriesFederatesWithAgainstMissingBundle(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithSuccess() {
	dstest.TestRegistrationEntriesFederatesWithSuccess(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleRestrictedByRegistrationEntries() {
	dstest.TestDeleteBundleRestrictedByRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleDeleteRegistrationEntries() {
	dstest.TestDeleteBundleDeleteRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleDissociateRegistrationEntries() {
	dstest.TestDeleteBundleDissociateRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	dstest.TestCreateRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateOrReturnRegistrationEntry() {
	dstest.TestCreateOrReturnRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	dstest.TestCreateInvalidRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntry() {
	dstest.TestFetchRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntryDoesNotExist() {
	dstest.TestFetchRegistrationEntryDoesNotExist(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntries() {
	dstest.TestFetchRegistrationEntries(s.T(), s.ds)
}
