package sqlstore

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"

	"github.com/spiffe/spire/pkg/server/datastore"
	dstest "github.com/spiffe/spire/pkg/server/datastore/test"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"

	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
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

func (s *PluginSuite) TestPruneRegistrationEntries() {
	now := time.Now()
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "SpiffeId",
		ParentId:    "ParentId",
		X509SvidTtl: 1,
		EntryExpiry: now.Unix(),
	}

	createdRegistrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)
	fetchedRegistrationEntry := &common.RegistrationEntry{}
	defaultLastLog := spiretest.LogEntry{
		Message: "Connected to SQL database",
	}
	prunedLogMessage := "Pruned an expired registration"

	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(1, len(resp.Events))
	s.Require().Equal(createdRegistrationEntry.EntryId, resp.Events[0].EntryID)

	for _, tt := range []struct {
		name                      string
		time                      time.Time
		expectedRegistrationEntry *common.RegistrationEntry
		expectedLastLog           spiretest.LogEntry
	}{
		{
			name:                      "Don't prune valid entries",
			time:                      now.Add(-10 * time.Second),
			expectedRegistrationEntry: createdRegistrationEntry,
			expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Don't prune exact ExpiresBefore",
			time:                      now,
			expectedRegistrationEntry: createdRegistrationEntry,
			expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Prune old entries",
			time:                      now.Add(10 * time.Second),
			expectedRegistrationEntry: (*common.RegistrationEntry)(nil),
			expectedLastLog: spiretest.LogEntry{
				Level:   logrus.InfoLevel,
				Message: prunedLogMessage,
				Data: logrus.Fields{
					telemetry.SPIFFEID:       createdRegistrationEntry.SpiffeId,
					telemetry.ParentID:       createdRegistrationEntry.ParentId,
					telemetry.RegistrationID: createdRegistrationEntry.EntryId,
				},
			},
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			// Get latest event id
			resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
			require.NoError(t, err)
			require.Greater(t, len(resp.Events), 0)
			lastEventID := resp.Events[len(resp.Events)-1].EventID

			// Prune events
			err = s.ds.PruneRegistrationEntries(ctx, tt.time)
			require.NoError(t, err)
			fetchedRegistrationEntry, err = s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegistrationEntry, fetchedRegistrationEntry)

			// Verify pruning triggers event creation
			resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
				GreaterThanEventID: lastEventID,
			})
			require.NoError(t, err)
			if tt.expectedRegistrationEntry != nil {
				require.Equal(t, 0, len(resp.Events))
			} else {
				require.Equal(t, 1, len(resp.Events))
				require.Equal(t, createdRegistrationEntry.EntryId, resp.Events[0].EntryID)
			}

			if tt.expectedLastLog.Message == prunedLogMessage {
				spiretest.AssertLastLogs(t, s.hook.AllEntries(), []spiretest.LogEntry{tt.expectedLastLog})
			} else {
				assert.Equal(t, s.hook.LastEntry().Message, tt.expectedLastLog.Message)
			}
		})
	}
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	fetchedRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, "INEXISTENT")
	s.Require().NoError(err)
	s.Require().Nil(fetchedRegistrationEntry)
}

func (s *PluginSuite) TestListRegistrationEntries() {
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

func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
	_, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "TYPE", Value: "VALUE"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
		DnsNames: []string{
			"abcd.efg",
			"somehost",
		},
	})
	s.Require().NoError(err)

	// This is gross. Since the bug that left selectors around has been fixed
	// (#1191), I'm not sure how else to test this other than just sneaking in
	// there and removing the registered_entries row.
	res, err := s.ds.db.raw.Exec("DELETE FROM registered_entries")
	s.Require().NoError(err)
	rowsAffected, err := res.RowsAffected()
	s.Require().NoError(err)
	s.Require().Equal(int64(1), rowsAffected)

	// Assert that no rows are returned.
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Empty(resp.Entries)
}

func (s *PluginSuite) TestUpdateRegistrationEntry() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
		JwtSvidTtl:  20,
	})

	entry.X509SvidTtl = 11
	entry.JwtSvidTtl = 21
	entry.Admin = true
	entry.Downstream = true
	entry.Hint = "internal"

	updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().NoError(err)
	// Verify output has expected values
	s.Require().Equal(int32(11), updatedRegistrationEntry.X509SvidTtl)
	s.Require().Equal(int32(21), updatedRegistrationEntry.JwtSvidTtl)
	s.Require().True(updatedRegistrationEntry.Admin)
	s.Require().True(updatedRegistrationEntry.Downstream)
	s.Require().Equal("internal", updatedRegistrationEntry.Hint)
	s.Require().Equal(entry.CreatedAt, updatedRegistrationEntry.CreatedAt)

	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	s.RequireProtoEqual(updatedRegistrationEntry, registrationEntry)

	entry.EntryId = "badid"
	_, err = s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithStoreSvid() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type1", Value: "Value2"},
			{Type: "Type1", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
	})

	entry.StoreSvid = true

	updateRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntry)
	// Verify output has expected values
	s.Require().True(entry.StoreSvid)

	fetchRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.RequireProtoEqual(updateRegistrationEntry, fetchRegistrationEntry)

	// Update with invalid selectors
	entry.Selectors = []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type1", Value: "Value2"},
		{Type: "Type2", Value: "Value3"},
	}
	resp, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().Nil(resp)
	s.Require().EqualError(err, "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled")
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithMask() {
	// There are 11 fields in a registration entry. Of these, 5 have some validation in the SQL
	// layer. In this test, we update each of the 11 fields and make sure update works, and also check
	// with the mask value false to make sure nothing changes. For the 5 fields that have validation
	// we try with good data, bad data, and with or without a mask (so 4 cases each.)

	// Note that most of the input validation is done in the API layer and has more extensive tests there.
	now := time.Now().Unix()
	oldEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/oldSpiffeId",
		X509SvidTtl:   1000,
		JwtSvidTtl:    3000,
		Selectors:     []*common.Selector{{Type: "Type1", Value: "Value1"}},
		FederatesWith: []string{"spiffe://dom1.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns1"},
		Downstream:    false,
		StoreSvid:     false,
	}
	newEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/newSpiffeId",
		X509SvidTtl:   4000,
		JwtSvidTtl:    6000,
		Selectors:     []*common.Selector{{Type: "Type2", Value: "Value2"}},
		FederatesWith: []string{"spiffe://dom2.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns2"},
		Downstream:    false,
		StoreSvid:     true,
		Hint:          "internal",
	}
	badEntry := &common.RegistrationEntry{
		ParentId:      "not a good parent id",
		SpiffeId:      "",
		X509SvidTtl:   -1000,
		JwtSvidTtl:    -3000,
		Selectors:     []*common.Selector{},
		FederatesWith: []string{"invalid federated bundle"},
		Admin:         false,
		EntryExpiry:   -2000,
		DnsNames:      []string{"this is a bad domain name "},
		Downstream:    false,
	}
	// Needed for the FederatesWith field to work
	s.createBundle("spiffe://dom1.org")
	s.createBundle("spiffe://dom2.org")

	var id string
	for _, testcase := range []struct {
		name   string
		mask   *common.RegistrationEntryMask
		update func(*common.RegistrationEntry)
		result func(*common.RegistrationEntry)
		err    error
	}{ // SPIFFE ID FIELD -- this field is validated so we check with good and bad data
		{
			name:   "Update Spiffe ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
		},
		{
			name:   "Update Spiffe ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update Spiffe ID, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			err:    errors.New("invalid registration entry: missing SPIFFE ID"),
		},
		{
			name:   "Update Spiffe ID, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {},
		},
		// PARENT ID FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update Parent ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{ParentId: true},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
		},
		{
			name:   "Update Parent ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{ParentId: false},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) {},
		},
		// X509 SVID TTL FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update X509 SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl },
		},
		{
			name:   "Update X509 SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update X509 SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			err:    errors.New("invalid registration entry: X509SvidTtl is not set"),
		},
		{
			name:   "Update X509 SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		// JWT SVID TTL FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update JWT SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl },
		},
		{
			name:   "Update JWT SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update JWT SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			err:    errors.New("invalid registration entry: JwtSvidTtl is not set"),
		},
		{
			name:   "Update JWT SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		// SELECTORS FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update Selectors, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors },
			result: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors },
		},
		{
			name:   "Update Selectors, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update Selectors, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			err:    errors.New("invalid registration entry: missing selector list"),
		},
		{
			name:   "Update Selectors, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {},
		},
		// FEDERATESWITH FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update FederatesWith, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{FederatesWith: true},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
		},
		{
			name:   "Update FederatesWith Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{FederatesWith: false},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) {},
		},
		// ADMIN FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update Admin, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Admin: true},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
		},
		{
			name:   "Update Admin, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) {},
		},

		// STORESVID FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update StoreSvid, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{StoreSvid: true},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
		},
		{
			name:   "Update StoreSvid, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name: "Update StoreSvid, Invalid selectors, Mask True",
			mask: &common.RegistrationEntryMask{StoreSvid: true, Selectors: true},
			update: func(e *common.RegistrationEntry) {
				e.StoreSvid = newEntry.StoreSvid
				e.Selectors = []*common.Selector{
					{Type: "Type1", Value: "Value1"},
					{Type: "Type2", Value: "Value2"},
				}
			},
			err: newValidationError("invalid registration entry: selector types must be the same when store SVID is enabled"),
		},

		// ENTRYEXPIRY FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update EntryExpiry, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{EntryExpiry: true},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
		},
		{
			name:   "Update EntryExpiry, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{EntryExpiry: false},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) {},
		},
		// DNSNAMES FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{DnsNames: true},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
		},
		{
			name:   "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{DnsNames: false},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) {},
		},
		// DOWNSTREAM FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Downstream: true},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
		},
		{
			name:   "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Downstream: false},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) {},
		},
		// HINT -- This field isn't validated so we just check with good data
		{
			name:   "Update Hint, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Hint: true},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
		},
		{
			name:   "Update Hint, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Hint: false},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) {},
		},
		// This should update all fields
		{
			name:   "Test With Nil Mask",
			mask:   nil,
			update: func(e *common.RegistrationEntry) { proto.Merge(e, oldEntry) },
			result: func(e *common.RegistrationEntry) {},
		},
	} {
		tt := testcase
		s.Run(tt.name, func() {
			if id != "" {
				s.deleteRegistrationEntry(id)
			}
			registrationEntry := s.createRegistrationEntry(oldEntry)
			id = registrationEntry.EntryId

			updateEntry := &common.RegistrationEntry{}
			tt.update(updateEntry)
			updateEntry.EntryId = id
			updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, updateEntry, tt.mask)

			if tt.err != nil {
				s.Require().ErrorContains(err, tt.err.Error())
				return
			}

			s.Require().NoError(err)
			expectedResult := proto.Clone(oldEntry).(*common.RegistrationEntry)
			tt.result(expectedResult)
			expectedResult.EntryId = id
			expectedResult.RevisionNumber++
			s.assertCreatedAtField(updatedRegistrationEntry, now)
			s.RequireProtoEqual(expectedResult, updatedRegistrationEntry)

			// Fetch and check the results match expectations
			registrationEntry, err = s.ds.FetchRegistrationEntry(ctx, id)
			s.Require().NoError(err)
			s.Require().NotNil(registrationEntry)

			s.assertCreatedAtField(registrationEntry, now)

			s.RequireProtoEqual(expectedResult, registrationEntry)
		})
	}
}

func (s *PluginSuite) TestDeleteRegistrationEntry() {
	// delete non-existing
	_, err := s.ds.DeleteRegistrationEntry(ctx, "badid")
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
	})

	s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId:    "spiffe://example.org/baz",
		ParentId:    "spiffe://example.org/bat",
		X509SvidTtl: 2,
	})

	// We have two registration entries
	entriesResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 2)

	// Make sure we deleted the right one
	deletedEntry, err := s.ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	s.Require().NoError(err)
	s.Require().Equal(entry1, deletedEntry)

	// Make sure we have now only one registration entry
	entriesResp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 1)

	// Delete again must fails with Not Found
	deletedEntry, err = s.ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	s.Require().EqualError(err, "rpc error: code = NotFound desc = datastore-sql: record not found")
	s.Require().Nil(deletedEntry)
}

func (s *PluginSuite) TestListParentIDEntries() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		parentID            string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "test_parentID_found",
			registrationEntries: allEntries,
			parentID:            "spiffe://parent",
			expectedList:        allEntries[:2],
		},
		{
			name:                "test_parentID_notfound",
			registrationEntries: allEntries,
			parentID:            "spiffe://imnoparent",
			expectedList:        nil,
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
				ByParentID: test.parentID,
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListSelectorEntries() {
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
			name:                "entries_by_selector_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "b", Value: "2"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{allEntries[0]},
		},
		{
			name:                "entries_by_selector_not_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "0"},
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
					Match:     datastore.Exact,
				},
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesBySelectorSubset() {
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
			name:                "test1",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "b", Value: "2"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[1],
				allEntries[2],
			},
		},
		{
			name:                "test2",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "d", Value: "4"},
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
					Match:     datastore.Subset,
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

func (s *PluginSuite) TestListSelectorEntriesSuperset() {
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
			name:                "entries_by_selector_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[3],
			},
		},
		{
			name:                "entries_by_selector_not_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "0"},
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
					Match:     datastore.Superset,
				},
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
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

// assertSelectorsEqual compares two selector maps for equality
// TODO: replace this with calls to Equal when we replace common.Selector with
// a normal struct that doesn't require special comparison (i.e. not a
// protobuf)
func assertSelectorsEqual(t *testing.T, expected, actual map[string][]*common.Selector, msgAndArgs ...any) {
	type selector struct {
		Type  string
		Value string
	}
	convert := func(in map[string][]*common.Selector) map[string][]selector {
		out := make(map[string][]selector)
		for spiffeID, selectors := range in {
			for _, s := range selectors {
				out[spiffeID] = append(out[spiffeID], selector{Type: s.Type, Value: s.Value})
			}
		}
		return out
	}
	assert.Equal(t, convert(expected), convert(actual), msgAndArgs...)
}

// federation relationship helpers moved to dstest package
