package cassandra

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	dstest "github.com/spiffe/spire/pkg/server/datastore/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	testutil "github.com/spiffe/spire/test/util"
)

const (
	_ttl                   = time.Hour
	_expiredNotAfterString = "2018-01-10T01:34:00+00:00"
	_validNotAfterString   = "2018-01-10T01:36:00+00:00"
	_middleTimeString      = "2018-01-10T01:35:00+00:00"
	_notFoundErrMsg        = "datastore-sql: record not found"
)

var ctx = context.Background()

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(PluginSuite))
}

type PluginSuite struct {
	spiretest.Suite

	cert   *x509.Certificate
	cacert *x509.Certificate

	ds   *CassandraDataStore
	hook *test.Hook
}

func (s *PluginSuite) SetupSuite() {
	clk := clock.NewMock(s.T())

	expiredNotAfterTime, err := time.Parse(time.RFC3339, _expiredNotAfterString)
	s.Require().NoError(err)
	validNotAfterTime, err := time.Parse(time.RFC3339, _validNotAfterString)
	s.Require().NoError(err)

	caTemplate, err := testutil.NewCATemplate(clk, spiffeid.RequireTrustDomainFromString("foo"))
	s.Require().NoError(err)

	caTemplate.NotAfter = expiredNotAfterTime
	caTemplate.NotBefore = expiredNotAfterTime.Add(-_ttl)

	cacert, cakey, err := testutil.SelfSign(caTemplate)
	s.Require().NoError(err)

	svidTemplate, err := testutil.NewSVIDTemplate(clk, "spiffe://foo/id1")
	s.Require().NoError(err)

	svidTemplate.NotAfter = validNotAfterTime
	svidTemplate.NotBefore = validNotAfterTime.Add(-_ttl)

	cert, _, err := testutil.Sign(svidTemplate, cacert, cakey)
	s.Require().NoError(err)

	s.cacert = cacert
	s.cert = cert

	log, hook := test.NewNullLogger()
	ds := New(log)
	s.hook = hook

	// Configure with mock/test settings
	cfg := `
        hosts = "127.0.0.1"
        port = 9042
        keyspace = "spire_test"
        username = ""
        password = ""
        disable_migration = true
    `

	err = ds.Configure(ctx, cfg)
	if err != nil {
		fmt.Println("Unable to configure ds err:", err)
		os.Exit(1)
	}

	s.ds = ds

	// Drop all tables to ensure clean state at the start
	if err := s.dropAllTables(); err != nil {
		s.T().Fatalf("Failed to drop tables: %v", err)
	}

	// Create tables once
	if err := s.ds.createTables(); err != nil {
		s.T().Fatalf("Failed to create tables: %v", err)
	}
}

func (s *PluginSuite) SetupTest() {
	// Truncate all tables between tests for isolation
	if err := s.truncateAllTables(); err != nil {
		s.T().Fatalf("Failed to truncate tables: %v", err)
	}

	// Reset log hook if needed (optional, depending on test requirements)
	s.hook.Reset()
}

func (s *PluginSuite) TearDownSuite() {
	if s.ds != nil {
		s.ds.Close()
		s.ds = nil
	}
}

func (s *PluginSuite) dropAllTables() error {
	ks := "spire_test"

	// ---------------------------------------------------------------------
	// 1) Drop all materialized views
	// ---------------------------------------------------------------------
	{
		iter := s.ds.session.Query(
			`SELECT view_name FROM system_schema.views WHERE keyspace_name = ?`,
			ks,
		).Iter()

		var view string
		var views []string
		for iter.Scan(&view) {
			views = append(views, view)
		}
		if err := iter.Close(); err != nil {
			return fmt.Errorf("listing views: %w", err)
		}

		for _, v := range views {
			q := fmt.Sprintf("DROP MATERIALIZED VIEW IF EXISTS %s.%s", ks, v)
			if err := s.ds.session.Query(q).Exec(); err != nil {
				return fmt.Errorf("dropping MV %s: %w", v, err)
			}
		}
	}

	// ---------------------------------------------------------------------
	// 2) Drop all secondary indexes
	// ---------------------------------------------------------------------
	{
		iter := s.ds.session.Query(
			`SELECT index_name FROM system_schema.indexes WHERE keyspace_name = ?`,
			ks,
		).Iter()

		var indexName string
		for iter.Scan(&indexName) {
			q := fmt.Sprintf("DROP INDEX IF EXISTS %s.%s", ks, indexName)
			if err := s.ds.session.Query(q).Exec(); err != nil {
				return fmt.Errorf("dropping index %s: %w", indexName, err)
			}
		}
		if err := iter.Close(); err != nil {
			return fmt.Errorf("listing indexes: %w", err)
		}
	}

	// ---------------------------------------------------------------------
	// 3) Drop all tables (base tables must come AFTER MVs & indexes)
	// ---------------------------------------------------------------------
	tables := []string{
		"bundles",
		"attested_nodes",
		"node_resolver_map",
		"attested_node_events",
		"registered_entries",
		"selectors",
		"federates_with",
		"dns_names",
		"registered_entry_events",
		"join_tokens",
		"federation_relationships",
		"ca_journals",
		"migration",
	}

	for _, table := range tables {
		q := fmt.Sprintf("DROP TABLE IF EXISTS %s.%s", ks, table)
		if err := s.ds.session.Query(q).Exec(); err != nil {
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	// ---------------------------------------------------------------------
	// 4) Drop UDTs (must be AFTER tables that reference them)
	// ---------------------------------------------------------------------
	udts := []string{
		"selector",
	}

	for _, udt := range udts {
		q := fmt.Sprintf("DROP TYPE IF EXISTS %s.%s", ks, udt)
		if err := s.ds.session.Query(q).Exec(); err != nil {
			return fmt.Errorf("failed to drop type %s: %w", udt, err)
		}
	}

	return nil
}

func (s *PluginSuite) truncateAllTables() error {
	tables := []string{
		"bundles",
		"attested_nodes",
		"node_resolver_map",
		"attested_node_events",
		"registered_entries",
		"selectors",
		"federates_with",
		"dns_names",
		"registered_entry_events",
		"join_tokens",
		"federation_relationships",
		"ca_journals",
		"migration",
	}

	for _, table := range tables {
		if err := s.ds.session.Query("TRUNCATE " + table).Exec(); err != nil {
			return fmt.Errorf("failed to truncate table %s: %v", table, err)
		}
	}

	return nil
}

/**/
func (s *PluginSuite) TestBundleCRUD() {
	dstest.TestBundleCRUD(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestListBundlesWithPaginationNoSQL() {
	dstest.TestListBundlesWithPaginationNoSQL(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCountBundles() {
	dstest.TestCountBundles(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCreateFederationRelationship() {
	dstest.TestCreateFederationRelationship(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestListFederationRelationshipsNonIntegerTokens() {
	dstest.TestListFederationRelationshipsNonIntegerTokens(s.T(), s.ds, s.cert)
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

func (s *PluginSuite) TestUpdateAttestedNode() {
	dstest.TestUpdateAttestedNode(s.T(), func() datastore.DataStore {
		s.truncateAllTables()
		return s.ds
	})
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	dstest.TestDeleteAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneAttestedExpiredNodes() {
	dstest.TestPruneAttestedExpiredNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestListAttestedNodesWithPaginationNoSQL() {
	dstest.TestListAttestedNodesWithPaginationNoSQL(s.T(), func() datastore.DataStore {
		s.truncateAllTables()
		return s.ds
	})
}

func (s *PluginSuite) TestListAttestedNodesNoSQL() {
	dstest.TestListAttestedNodesNoSQL(s.T(), func() datastore.DataStore {
		s.truncateAllTables()
		return s.ds
	})
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

func (s *PluginSuite) TestFetchCAJournal() {
	dstest.TestFetchCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneCAJournal() {
	dstest.TestPruneCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestSetCAJournal() {
	dstest.TestSetCAJournal(s.T(), s.ds)
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

func (s *PluginSuite) TestCountAttestedNodes() {
	dstest.TestCountAttestedNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateAttestedNode() {
	dstest.TestCreateAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchAttestedNodeMissing() {
	dstest.TestFetchAttestedNodeMissing(s.T(), s.ds)
}

func (s *PluginSuite) TestCountRegistrationEntries() {
	dstest.TestCountRegistrationEntries(s.T(), s.ds)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithSuccess() {
	dstest.TestRegistrationEntriesFederatesWithSuccess(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestFetchFederationRelationship() {
	// createRaw inserts a raw federated trust domain record into Cassandra.
	rawCreate := func(raw dstest.FederatedTrustDomainRaw) error {
		return s.ds.session.Query(
			`INSERT INTO federation_relationships
					 (bucket, trust_domain, bundle_endpoint_url, bundle_endpoint_profile, endpoint_spiffe_id, created_at, updated_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			federationBucket,
			raw.TrustDomain,
			raw.BundleEndpointURL,
			raw.BundleEndpointProfile,
			raw.EndpointSPIFFEID,
			time.Now(),
			time.Now(),
		).Exec()
	}

	dstest.TestFetchFederationRelationship(s.T(), s.ds, rawCreate)
}

func (s *PluginSuite) TestListNodeSelectorsGroupsBySpiffeID() {
	// insertRaw writes directly to Cassandra using the datastore's session.
	insertRaw := func(spiffeID, selectorType, selectorValue string) error {
		// 1) Write to the normalized map used by resolver logic
		if err := s.ds.session.Query(
			`INSERT INTO node_resolver_map (spiffe_id, type, value) VALUES (?, ?, ?)`,
			spiffeID, selectorType, selectorValue,
		).Exec(); err != nil {
			return err
		}

		// 2) Maintain the inverted index (keeps other codepaths consistent)
		if err := s.ds.session.Query(
			`INSERT INTO node_selectors_index (selector_type, selector_value, spiffe_id, updated_at) VALUES (?, ?, ?, ?)`,
			selectorType, selectorValue, spiffeID, time.Now(),
		).Exec(); err != nil {
			return err
		}

		return nil
	}

	dstest.TestListNodeSelectorsGroupsBySpiffeID(s.T(), s.ds, insertRaw)
}

func (s *PluginSuite) TestDeleteFederationRelationship() {
	dstest.TestDeleteFederationRelationship(s.T(), s.ds)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithAgainstMissingBundle() {
	dstest.TestRegistrationEntriesFederatesWithAgainstMissingBundle(s.T(), s.ds, s.cert)
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

// WIP
func (s *PluginSuite) TestPruneRegistrationEntryEvents() {
	newDS := func() (datastore.DataStore, func()) {
		s.truncateAllTables()
		return s.ds, func() {}
	}

	ds, cleanup := newDS()
	defer cleanup()

	// Run the migrated test against a fresh datastore so EventIDs start at 1
	dstest.TestPruneRegistrationEntryEvents(s.T(), ds)
}
