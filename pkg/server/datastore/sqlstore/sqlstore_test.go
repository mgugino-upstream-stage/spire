package sqlstore

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/util"

	"github.com/spiffe/spire/pkg/server/datastore"
	dstest "github.com/spiffe/spire/pkg/server/datastore/test"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"

	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx = context.Background()

	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
)

const (
	_ttl                   = time.Hour
	_expiredNotAfterString = "2018-01-10T01:34:00+00:00"
	_validNotAfterString   = "2018-01-10T01:36:00+00:00"
	_middleTimeString      = "2018-01-10T01:35:00+00:00"
	_notFoundErrMsg        = "datastore-sql: record not found"
)

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(PluginSuite))
}

type PluginSuite struct {
	spiretest.Suite

	cert   *x509.Certificate
	cacert *x509.Certificate

	dir    string
	nextID int
	ds     *Plugin
	hook   *test.Hook
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
}

func (s *PluginSuite) SetupTest() {
	s.dir = s.TempDir()
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownTest() {
	if s.ds != nil {
		s.ds.Close()
	}
}

func (s *PluginSuite) newPlugin() *Plugin {
	log, hook := test.NewNullLogger()
	ds := New(log)
	s.hook = hook

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	switch TestDialect {
	case "":
		s.nextID++
		dbPath := filepath.ToSlash(filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextID)))
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "sqlite3"
			log_sql = true
			connection_string = "%s"
		`, dbPath))
		s.Require().NoError(err)

		// assert that WAL journal mode is enabled
		jm := struct {
			JournalMode string
		}{}
		ds.db.Raw("PRAGMA journal_mode").Scan(&jm)
		s.Require().Equal(jm.JournalMode, "wal")

		// assert that foreign_key support is enabled
		fk := struct {
			ForeignKeys string
		}{}
		ds.db.Raw("PRAGMA foreign_keys").Scan(&fk)
		s.Require().Equal(fk.ForeignKeys, "1")
	case "mysql":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipeMySQL(s.T(), TestConnString)
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "mysql"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString))
		s.Require().NoError(err)
	case "postgres":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipePostgres(s.T(), TestConnString)
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "postgres"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString))
		s.Require().NoError(err)
	default:
		s.Require().FailNowf("Unsupported external test dialect %q", TestDialect)
	}

	return ds
}

func (s *PluginSuite) TestInvalidPluginConfiguration() {
	err := s.ds.Configure(ctx, `
		database_type = "wrong"
		connection_string = "bad"
	`)
	s.RequireErrorContains(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestInvalidAWSConfiguration() {
	testCases := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "aws_mysql - no region",
			config: `
			database_type "aws_mysql" {}
			connection_string = "test_user:@tcp(localhost:1234)/spire?parseTime=true&allowCleartextPasswords=1&tls=true"`,
			expectedErr: "datastore-sql: region must be specified",
		},
		{
			name: "postgres_mysql - no region",
			config: `
			database_type "aws_postgres" {}
			connection_string = "dbname=postgres user=postgres host=the-host sslmode=require"`,
			expectedErr: "region must be specified",
		},
	}
	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			err := s.ds.Configure(ctx, testCase.config)
			s.RequireErrorContains(err, testCase.expectedErr)
		})
	}
}

func (s *PluginSuite) TestInvalidMySQLConfiguration() {
	err := s.ds.Configure(ctx, `
		database_type = "mysql"
		connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: invalid mysql config: missing parseTime=true param in connection_string")

	err = s.ds.Configure(ctx, `
		database_type = "mysql"
		ro_connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")

	err = s.ds.Configure(ctx, `
		database_type = "mysql"
	`)
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")
}

// Migrate only those below here

func (s *PluginSuite) TestSetNodeSelectorsUnderLoad() {
	selectors := []*common.Selector{
		{Type: "TYPE", Value: "VALUE"},
	}

	const numWorkers = 20

	resultCh := make(chan error, numWorkers)
	nextID := int32(0)

	for range numWorkers {
		go func() {
			id := fmt.Sprintf("ID%d", atomic.AddInt32(&nextID, 1))
			for range 10 {
				err := s.ds.SetNodeSelectors(ctx, id, selectors)
				if err != nil {
					resultCh <- err
				}
			}
			resultCh <- nil
		}()
	}

	for range numWorkers {
		s.Require().NoError(<-resultCh)
	}
}

func (s *PluginSuite) TestListEntriesBySelectorMatchAny() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		selectors           []*common.Selector
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "c", Value: "3"},
				{Type: "d", Value: "4"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "d", Value: "4"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "5"},
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.MatchAny,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			s.RequireProtoListEqual(test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithExact() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
			},
		},
		{
			name:                "with a subset",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[1],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			dstest.CreateBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Exact,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)

			s.assertCreatedAtFields(result, now)

			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithSubset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[1],
				allEntries[2],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td4.org",
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			dstest.CreateBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Subset,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithMatchAny() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td3.org",
				"spiffe://td4.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td4.org"},
			expectedList: []*common.RegistrationEntry{
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td5.org"},
			expectedList:        nil,
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			dstest.CreateBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.MatchAny,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithSuperset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[3],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td3.org"},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td5.org"},
			expectedList:        nil,
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			dstest.CreateBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Superset,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListRegistrationEntryEvents() {
	var expectedEvents []datastore.RegistrationEntryEvent
	var expectedEventID uint = 1

	// Create an entry
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId: "spiffe://example.org/foo1",
		ParentId: "spiffe://example.org/bar",
	})
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry1.EntryId,
	})
	expectedEventID++

	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Create second entry
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type2", Value: "Value2"},
		},
		SpiffeId: "spiffe://example.org/foo2",
		ParentId: "spiffe://example.org/bar",
	})
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry2.EntryId,
	})
	expectedEventID++

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Update first entry
	updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry1, nil)
	s.Require().NoError(err)
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: updatedRegistrationEntry.EntryId,
	})
	expectedEventID++

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Delete second entry
	s.deleteRegistrationEntry(entry2.EntryId)
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry2.EntryId,
	})

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Check filtering events by id
	tests := []struct {
		name                 string
		greaterThanEventID   uint
		lessThanEventID      uint
		expectedEvents       []datastore.RegistrationEntryEvent
		expectedFirstEventID uint
		expectedLastEventID  uint
		expectedErr          string
	}{
		{
			name:                 "All Events",
			greaterThanEventID:   0,
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents,
		},
		{
			name:                 "Greater than half of the Events",
			greaterThanEventID:   uint(len(expectedEvents) / 2),
			expectedFirstEventID: uint(len(expectedEvents)/2) + 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents[len(expectedEvents)/2:],
		},
		{
			name:                 "Less than half of the Events",
			lessThanEventID:      uint(len(expectedEvents) / 2),
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)/2) - 1,
			expectedEvents:       expectedEvents[:len(expectedEvents)/2-1],
		},
		{
			name:               "Greater than largest Event ID",
			greaterThanEventID: 4,
			expectedEvents:     []datastore.RegistrationEntryEvent{},
		},
		{
			name:               "Setting both greater and less than",
			greaterThanEventID: 1,
			lessThanEventID:    1,
			expectedErr:        "datastore-sql: can't set both greater and less than event id",
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
				GreaterThanEventID: test.greaterThanEventID,
				LessThanEventID:    test.lessThanEventID,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			s.Require().NoError(err)

			s.Require().Equal(test.expectedEvents, resp.Events)
			if len(resp.Events) > 0 {
				s.Require().Equal(test.expectedFirstEventID, resp.Events[0].EventID)
				s.Require().Equal(test.expectedLastEventID, resp.Events[len(resp.Events)-1].EventID)
			}
		})
	}
}

func (s *PluginSuite) TestPruneRegistrationEntryEvents() {
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
	}

	createdRegistrationEntry := s.createRegistrationEntry(entry)
	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(createdRegistrationEntry.EntryId, resp.Events[0].EntryID)

	for _, tt := range []struct {
		name           string
		olderThan      time.Duration
		expectedEvents []datastore.RegistrationEntryEvent
	}{
		{
			name:      "Don't prune valid events",
			olderThan: 1 * time.Hour,
			expectedEvents: []datastore.RegistrationEntryEvent{
				{
					EventID: 1,
					EntryID: createdRegistrationEntry.EntryId,
				},
			},
		},
		{
			name:           "Prune old events",
			olderThan:      0 * time.Second,
			expectedEvents: []datastore.RegistrationEntryEvent{},
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			s.Require().EventuallyWithTf(func(collect *assert.CollectT) {
				err := s.ds.PruneRegistrationEntryEvents(ctx, tt.olderThan)
				require.NoError(collect, err)

				resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
				require.NoError(collect, err)

				assert.True(collect, reflect.DeepEqual(tt.expectedEvents, resp.Events))
			}, 10*time.Second, 50*time.Millisecond, "Failed to prune entries correctly")
		})
	}
}

func (s *PluginSuite) TestMigration() {
	for schemaVersion := range latestSchemaVersion {
		s.T().Run(fmt.Sprintf("migration_from_schema_version_%d", schemaVersion), func(t *testing.T) {
			require := require.New(t)
			dbName := fmt.Sprintf("v%d.sqlite3", schemaVersion)
			dbPath := filepath.ToSlash(filepath.Join(s.dir, "migration-"+dbName))
			if runtime.GOOS == "windows" {
				dbPath = "/" + dbPath
			}
			dbURI := fmt.Sprintf("file://%s", dbPath)

			minimalDB := func() string {
				previousMinor := codeVersion
				if codeVersion.Minor == 0 {
					previousMinor.Major--
				} else {
					previousMinor.Minor--
				}
				return fmt.Sprintf(`
					CREATE TABLE "migrations" ("id" integer primary key autoincrement, "version" integer,"code_version" varchar(255) );
					INSERT INTO migrations("version", "code_version") VALUES (%d,%q);
				`, schemaVersion, previousMinor)
			}

			prepareDB := func(migrationSupported bool) {
				dump := migrationDumps[schemaVersion]
				if migrationSupported {
					require.NotEmpty(dump, "no migration dump set up for schema version")
				} else {
					require.Empty(dump, "migration dump exists for unsupported schema version")
					dump = minimalDB()
				}
				dumpDB(t, dbPath, dump)
				err := s.ds.Configure(ctx, fmt.Sprintf(`
					database_type = "sqlite3"
					connection_string = %q
				`, dbURI))
				if migrationSupported {
					require.NoError(err)
				} else {
					require.EqualError(err, fmt.Sprintf("datastore-sql: migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", schemaVersion))
				}
			}
			switch schemaVersion {
			// All of these schema versions were migrated by previous versions
			// of SPIRE server and no longer have migration code.
			case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22:
				prepareDB(false)
			default:
				t.Fatalf("no migration test added for schema version %d", schemaVersion)
			}
		})
	}
}

func (s *PluginSuite) TestPristineDatabaseMigrationValues() {
	var m Migration
	s.Require().NoError(s.ds.db.First(&m).Error)
	s.Equal(latestSchemaVersion, m.Version)
	s.Equal(codeVersion.String(), m.CodeVersion)
}

func (s *PluginSuite) TestRace() {
	next := int64(0)
	exp := time.Now().Add(time.Hour).Unix()

	testutil.RaceTest(s.T(), func(t *testing.T) {
		node := &common.AttestedNode{
			SpiffeId:            fmt.Sprintf("foo%d", atomic.AddInt64(&next, 1)),
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CertNotAfter:        exp,
		}

		_, err := s.ds.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
		_, err = s.ds.FetchAttestedNode(ctx, node.SpiffeId)
		require.NoError(t, err)
	})
}

func (s *PluginSuite) TestBindVar() {
	fn := func(n int) string {
		return fmt.Sprintf("$%d", n)
	}
	bound := bindVarsFn(fn, "SELECT whatever FROM foo WHERE x = ? AND y = ?")
	s.Require().Equal("SELECT whatever FROM foo WHERE x = $1 AND y = $2", bound)
}

func (s *PluginSuite) TestBuildQuestionsAndPlaceholders() {
	for _, tt := range []struct {
		name                 string
		entries              []string
		expectedQuestions    string
		expectedPlaceholders string
	}{
		{
			name:                 "No args",
			expectedQuestions:    "",
			expectedPlaceholders: "",
		},
		{
			name:                 "One arg",
			entries:              []string{"a"},
			expectedQuestions:    "?",
			expectedPlaceholders: "$1",
		},
		{
			name:                 "Five args",
			entries:              []string{"a", "b", "c", "e", "f"},
			expectedQuestions:    "?,?,?,?,?",
			expectedPlaceholders: "$1,$2,$3,$4,$5",
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			questions := buildQuestions(tt.entries)
			s.Require().Equal(tt.expectedQuestions, questions)
			placeholders := buildPlaceholders(tt.entries)
			s.Require().Equal(tt.expectedPlaceholders, placeholders)
		})
	}
}

func (s *PluginSuite) getTestDataFromJSONFile(filePath string, jsonValue any) {
	entriesJSON, err := os.ReadFile(filePath)
	s.Require().NoError(err)

	err = json.Unmarshal(entriesJSON, &jsonValue)
	s.Require().NoError(err)
}

func (s *PluginSuite) createBundle(trustDomainID string) *common.Bundle {
	bundle, err := s.ds.CreateBundle(ctx, bundleutil.BundleProtoFromRootCA(trustDomainID, s.cert))
	s.Require().NoError(err)
	return bundle
}

func (s *PluginSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	return registrationEntry
}

func (s *PluginSuite) deleteRegistrationEntry(entryID string) {
	_, err := s.ds.DeleteRegistrationEntry(ctx, entryID)
	s.Require().NoError(err)
}

func (s *PluginSuite) TestConfigure() {
	tests := []struct {
		desc               string
		giveDBConfig       string
		expectMaxOpenConns int
		expectIdle         int
	}{
		{
			desc:               "defaults",
			expectMaxOpenConns: 100,
			// defined in database/sql
			expectIdle: 100,
		},
		{
			desc: "zero values",
			giveDBConfig: `
			max_open_conns = 0
			max_idle_conns = 0
			`,
			expectMaxOpenConns: 0,
			expectIdle:         0,
		},
		{
			desc: "custom values",
			giveDBConfig: `
			max_open_conns = 1000
			max_idle_conns = 50
			conn_max_lifetime = "10s"
			`,
			expectMaxOpenConns: 1000,
			expectIdle:         50,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.desc, func(t *testing.T) {
			dbPath := filepath.ToSlash(filepath.Join(s.dir, "test-datastore-configure.sqlite3"))

			log, _ := test.NewNullLogger()
			p := New(log)
			err := p.Configure(ctx, fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				%s
			`, dbPath, tt.giveDBConfig))
			require.NoError(t, err)
			defer p.Close()

			db := p.db.DB.DB()
			require.Equal(t, tt.expectMaxOpenConns, db.Stats().MaxOpenConnections)

			// begin many queries simultaneously
			numQueries := 100
			var rowsList []*sql.Rows
			for range numQueries {
				rows, err := db.Query("SELECT * FROM bundles")
				require.NoError(t, err)
				rowsList = append(rowsList, rows)
			}

			// close all open queries, which results in idle connections
			for _, rows := range rowsList {
				require.NoError(t, rows.Close())
			}
			require.Equal(t, tt.expectIdle, db.Stats().Idle)
		})
	}
}

func (s *PluginSuite) assertCreatedAtFields(result *datastore.ListRegistrationEntriesResponse, now int64) {
	for _, entry := range result.Entries {
		s.assertCreatedAtField(entry, now)
	}
}

func (s *PluginSuite) assertCreatedAtField(entry *common.RegistrationEntry, now int64) {
	// We can't compare the exact time because we don't have control over the clock used by the database.
	s.Assert().GreaterOrEqual(entry.CreatedAt, now)
	entry.CreatedAt = 0
}

// Don't migrate below this line
func wipePostgres(t *testing.T, connString string) {
	db, err := sql.Open("postgres", connString)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public';`)
	require.NoError(t, err)
	defer rows.Close()

	dropTables(t, db, scanTableNames(t, rows))
}

func wipeMySQL(t *testing.T, connString string) {
	db, err := sql.Open("mysql", connString)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'spire';`)
	require.NoError(t, err)
	defer rows.Close()

	dropTables(t, db, scanTableNames(t, rows))
}

func scanTableNames(t *testing.T, rows *sql.Rows) []string {
	var tableNames []string
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		require.NoError(t, err)
		tableNames = append(tableNames, tableName)
	}
	require.NoError(t, rows.Err())
	return tableNames
}

func dropTables(t *testing.T, db *sql.DB, tableNames []string) {
	for _, tableName := range tableNames {
		_, err := db.Exec("DROP TABLE IF EXISTS " + tableName + " CASCADE")
		require.NoError(t, err)
	}
}

// federation relationship helpers moved to dstest package
