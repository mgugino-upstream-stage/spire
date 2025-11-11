package dstest

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogo/status"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

const (
	_notFoundErrMsg = "datastore-sql: record not found"
)

// TestListRegistrationEntriesWhenCruftRowsExist wraps the "cruft rows" scenario.
//
// rawDeleteBaseAll must remove ONLY the base/primary rows for registration entries,
// leaving any companion/index rows behind (to simulate historical cruft).
// It should return an error if it fails or if the expected rows aren't deleted.
func TestListRegistrationEntriesWhenCruftRowsExist(t *testing.T, ds datastore.DataStore, rawDeleteBaseAll func() error) {
	t.Helper()
	ctx := context.Background()

	// Seed one entry via API (matches original test shape)
	_, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	require.NoError(t, err)

	// Remove ONLY the base rows, leaving cruft (index/selector) behind.
	require.NoError(t, rawDeleteBaseAll())

	// Assert that no rows are returned.
	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Empty(t, resp.Entries)
}

func TestFetchInexistentRegistrationEntry(t *testing.T, ds datastore.DataStore) {
	t.Helper()
	ctx := context.Background()

	fetched, err := ds.FetchRegistrationEntry(ctx, "INEXISTENT")
	require.NoError(t, err)
	require.Nil(t, fetched)
}

func TestUpdateRegistrationEntry(t *testing.T, ds datastore.DataStore, create func(*common.RegistrationEntry) *common.RegistrationEntry) {
	t.Helper()
	ctx := context.Background()

	entry := create(&common.RegistrationEntry{
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

	// mutate in-place
	entry.X509SvidTtl = 11
	entry.JwtSvidTtl = 21
	entry.Admin = true
	entry.Downstream = true
	entry.Hint = "internal"

	updated, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.NoError(t, err)

	require.Equal(t, int32(11), updated.X509SvidTtl)
	require.Equal(t, int32(21), updated.JwtSvidTtl)
	require.True(t, updated.Admin)
	require.True(t, updated.Downstream)
	require.Equal(t, "internal", updated.Hint)
	require.Equal(t, entry.CreatedAt, updated.CreatedAt)

	fetched, err := ds.FetchRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	spiretest.RequireProtoEqual(t, updated, fetched)

	entry.EntryId = "badid"
	_, err = ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Contains(t, err.Error(), _notFoundErrMsg)
}

func TestUpdateRegistrationEntryWithStoreSvid(t *testing.T, ds datastore.DataStore, create func(*common.RegistrationEntry) *common.RegistrationEntry) {
	t.Helper()
	ctx := context.Background()

	entry := create(&common.RegistrationEntry{
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

	updated, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.True(t, updated.StoreSvid)

	fetched, err := ds.FetchRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, updated, fetched)

	// selectors invalid when StoreSvid enabled
	entry.Selectors = []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type1", Value: "Value2"},
		{Type: "Type2", Value: "Value3"},
	}

	resp, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.Nil(t, resp)
	require.EqualError(t, err,
		"rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled")
}

func TestUpdateRegistrationEntryWithMask(
	t *testing.T,
	ds datastore.DataStore,
	createBundle func(string),
	createRegistrationEntry func(t *testing.T, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry,
	deleteRegistrationEntry func(string),
) {
	ctx := context.Background()
	now := time.Now().Unix()

	// Original SQLStore entry definitions
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

	// These must exist for FederatesWith validation
	createBundle("spiffe://dom1.org")
	createBundle("spiffe://dom2.org")

	var id string
	tests := []struct {
		name   string
		mask   *common.RegistrationEntryMask
		update func(*common.RegistrationEntry)
		result func(*common.RegistrationEntry)
		err    error
	}{
		// SPIFFE ID FIELD (validated)
		{
			name: "Update Spiffe ID, Good Data, Mask True",
			mask: &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) {
				e.SpiffeId = newEntry.SpiffeId
			},
			result: func(e *common.RegistrationEntry) {
				e.SpiffeId = newEntry.SpiffeId
			},
		},
		{
			name: "Update Spiffe ID, Good Data, Mask False",
			mask: &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) {
				e.SpiffeId = newEntry.SpiffeId
			},
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name: "Update Spiffe ID, Bad Data, Mask True",
			mask: &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) {
				e.SpiffeId = badEntry.SpiffeId
			},
			err: errors.New("invalid registration entry: missing SPIFFE ID"),
		},
		{
			name: "Update Spiffe ID, Bad Data, Mask False",
			mask: &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) {
				e.SpiffeId = badEntry.SpiffeId
			},
			result: func(e *common.RegistrationEntry) {},
		},

		// PARENT ID FIELD (not validated)
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

		// X509 SVID TTL FIELD (validated)
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

		// JWT SVID TTL FIELD (validated)
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

		// SELECTORS FIELD (validated)
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

		// FEDERATESWITH FIELD
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

		// ADMIN FIELD
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

		// STORESVID FIELD
		{
			name:   "Update StoreSvid, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{StoreSvid: true},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
		},
		{
			name:   "Update StoreSvid, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{StoreSvid: false},
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
			err: errors.New("invalid registration entry: selector types must be the same when store SVID is enabled"),
		},

		// ENTRYEXPIRY FIELD
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

		// DNSNAMES FIELD
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

		// DOWNSTREAM FIELD
		{
			name:   "Update Downstream, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Downstream: true},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
		},
		{
			name:   "Update Downstream, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Downstream: false},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) {},
		},

		// HINT FIELD
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

		// NIL MASK: Update everything (SQLStore-specific behavior)
		{
			name: "Test With Nil Mask",
			mask: nil,
			update: func(e *common.RegistrationEntry) {
				proto.Merge(e, oldEntry)
			},
			result: func(e *common.RegistrationEntry) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if id != "" {
				deleteRegistrationEntry(id)
			}
			registrationEntry := CreateRegistrationEntry(t, ds, oldEntry)
			id = registrationEntry.EntryId

			updateEntry := &common.RegistrationEntry{}
			tt.update(updateEntry)
			updateEntry.EntryId = id
			updatedRegistrationEntry, err := ds.UpdateRegistrationEntry(ctx, updateEntry, tt.mask)

			if tt.err != nil {
				require.ErrorContains(t, err, tt.err.Error())
				return
			}

			require.NoError(t, err)
			expectedResult := proto.Clone(oldEntry).(*common.RegistrationEntry)
			tt.result(expectedResult)
			expectedResult.EntryId = id
			expectedResult.RevisionNumber++
			assertCreatedAtField(t, updatedRegistrationEntry, now)
			spiretest.RequireProtoEqual(t, expectedResult, updatedRegistrationEntry)

			// Fetch and check the results match expectations
			registrationEntry, err = ds.FetchRegistrationEntry(ctx, id)
			require.NoError(t, err)
			require.NotNil(t, registrationEntry)

			assertCreatedAtField(t, registrationEntry, now)

			spiretest.RequireProtoEqual(t, expectedResult, registrationEntry)
		})
	}
}

func TestDeleteRegistrationEntry(
	t *testing.T,
	ds datastore.DataStore,
	create func(*common.RegistrationEntry) *common.RegistrationEntry,
) {
	t.Helper()
	ctx := context.Background()

	// 1) delete nonexistent
	_, err := ds.DeleteRegistrationEntry(ctx, "badid")
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))

	// 2) create two entries
	entry1 := create(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
	})

	create(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId:    "spiffe://example.org/baz",
		ParentId:    "spiffe://example.org/bat",
		X509SvidTtl: 2,
	})

	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Entries, 2)

	deleted, err := ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.NoError(t, err)
	require.Equal(t, entry1, deleted)

	resp, err = ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Entries, 1)

	deleted, err = ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.Error(t, err)
	require.Contains(t, err.Error(), "record not found")
	require.Nil(t, deleted)
}

func TestPruneRegistrationEntries(
	t *testing.T,
	ds datastore.DataStore,
	hook interface {
		AllEntries() []*logrus.Entry
		LastEntry() *logrus.Entry
	},
) {
	t.Helper()
	ctx := context.Background()

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

	createdRegistrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)

	fetchedRegistrationEntry := &common.RegistrationEntry{}
	defaultLastLog := spiretest.LogEntry{
		Message: "Connected to SQL database",
	}
	prunedLogMessage := "Pruned an expired registration"

	resp, err := ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Events))
	require.Equal(t, createdRegistrationEntry.EntryId, resp.Events[0].EntryID)

	tests := []struct {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get latest event id
			resp, err := ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
			require.NoError(t, err)
			require.Greater(t, len(resp.Events), 0)
			lastEventID := resp.Events[len(resp.Events)-1].EventID

			// Prune events
			err = ds.PruneRegistrationEntries(ctx, tt.time)
			require.NoError(t, err)

			fetchedRegistrationEntry, err = ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegistrationEntry, fetchedRegistrationEntry)

			// Verify pruning triggers event creation
			resp, err = ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
				GreaterThanEventID: lastEventID,
			})
			require.NoError(t, err)

			if tt.expectedRegistrationEntry != nil {
				require.Equal(t, 0, len(resp.Events))
			} else {
				require.Equal(t, 1, len(resp.Events))
				require.Equal(t, createdRegistrationEntry.EntryId, resp.Events[0].EntryID)
			}

			// Log assertions identical to original
			if tt.expectedLastLog.Message == prunedLogMessage {
				spiretest.AssertLastLogs(t, hook.AllEntries(), []spiretest.LogEntry{tt.expectedLastLog})
			} else {
				assert.Equal(t, hook.LastEntry().Message, tt.expectedLastLog.Message)
			}
		})
	}
}

func TestListParentIDEntries(
	t *testing.T,
	newDS func() (datastore.DataStore, func()),
	loadEntries func(path string, out *[]*common.RegistrationEntry),
) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	loadEntries(filepath.Join("testdata", "entries.json"), &allEntries)

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, cleanup := newDS()
			defer cleanup()

			for _, entry := range tt.registrationEntries {
				created, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				entry.EntryId = created.EntryId
			}

			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByParentID: tt.parentID,
			})
			require.NoError(t, err)

			assertCreatedAtFields(t, result, now)
			spiretest.RequireProtoListEqual(t, tt.expectedList, result.Entries)
		})
	}
}

func assertCreatedAtFields(t *testing.T, resp *datastore.ListRegistrationEntriesResponse, since int64) {
	t.Helper()
	for _, entry := range resp.Entries {
		assertCreatedAtField(t, entry, since)
	}
}

func TestListSelectorEntries(
	t *testing.T,
	newDS func() (datastore.DataStore, func()),
	loadEntries func(path string, out *[]*common.RegistrationEntry),
) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	loadEntries(filepath.Join("testdata", "entries.json"), &allEntries)

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, cleanup := newDS()
			defer cleanup()

			for _, entry := range tt.registrationEntries {
				created, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				entry.EntryId = created.EntryId
			}

			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: tt.selectors,
					Match:     datastore.Exact,
				},
			})
			require.NoError(t, err)

			assertCreatedAtFields(t, result, now)
			spiretest.RequireProtoListEqual(t, tt.expectedList, result.Entries)
		})
	}
}

func TestListEntriesBySelectorSubset(
	t *testing.T,
	newDS func() (datastore.DataStore, func()),
	loadEntries func(path string, out *[]*common.RegistrationEntry),
) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	loadEntries(filepath.Join("testdata", "entries.json"), &allEntries)

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, cleanup := newDS()
			defer cleanup()

			for _, entry := range tt.registrationEntries {
				created, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, created)
				entry.EntryId = created.EntryId
			}

			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: tt.selectors,
					Match:     datastore.Subset,
				},
			})
			require.NoError(t, err)

			// sort both lists for deterministic comparison
			if tt.expectedList != nil {
				util.SortRegistrationEntries(tt.expectedList)
			}
			util.SortRegistrationEntries(result.Entries)

			assertCreatedAtFields(t, result, now)
			spiretest.RequireProtoListEqual(t, tt.expectedList, result.Entries)
		})
	}
}

func TestListSelectorEntriesSuperset(
	t *testing.T,
	newDS func() (datastore.DataStore, func()),
	allEntries []*common.RegistrationEntry,
) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().Unix()

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, cleanup := newDS()
			defer cleanup()

			for _, entry := range tt.registrationEntries {
				created, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, created)
				entry.EntryId = created.EntryId
			}

			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: tt.selectors,
					Match:     datastore.Superset,
				},
			})
			require.NoError(t, err)

			// Uses your existing helper defined in the new tests
			assertCreatedAtFields(t, result, now)

			spiretest.RequireProtoListEqual(t, tt.expectedList, result.Entries)
		})
	}
}
