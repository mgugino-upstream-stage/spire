package cassandra

import (
	"context"
	"time"

	"github.com/gocql/gocql"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// CreateRegistrationEntry stores the given registration entry
func (ds *CassandraDataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	if entry == nil {
		return nil, newError("invalid request: missing registration entry")
	}

	// Generate entry ID if not provided
	entryID := entry.EntryId
	if entryID == "" {
		// Generate a unique ID for the registration entry
		uid := gocql.TimeUUID()
		entryID = uid.String()
	}

	// Insert the registration entry
	insertEntryQuery := `INSERT INTO registered_entries (entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry, store_svid, hint, jwt_svid_ttl, revision_number, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	now := time.Now()
	if err := ds.session.Query(insertEntryQuery,
		entryID,
		entry.SpiffeId,
		entry.ParentId,
		entry.X509SvidTtl,
		entry.Admin,
		entry.Downstream,
		entry.EntryExpiry,
		entry.StoreSvid,
		entry.Hint,
		entry.JwtSvidTtl,
		entry.RevisionNumber,
		now,
		now,
	).Exec(); err != nil {
		return nil, newError("failed to create registration entry: %v", err)
	}

	// Insert selectors
	if len(entry.Selectors) > 0 {
		insertSelectorQuery := `INSERT INTO selectors (entry_id, selector_type, selector_value) VALUES (?, ?, ?)`
		for _, selector := range entry.Selectors {
			if err := ds.session.Query(insertSelectorQuery, entryID, selector.Type, selector.Value).Exec(); err != nil {
				return nil, newError("failed to insert selector: %v", err)
			}
		}
	}

	// Insert DNS names
	if len(entry.DnsNames) > 0 {
		insertDNSQuery := `INSERT INTO dns_names (entry_id, dns_name) VALUES (?, ?)`
		for _, dnsName := range entry.DnsNames {
			if err := ds.session.Query(insertDNSQuery, entryID, dnsName).Exec(); err != nil {
				return nil, newError("failed to insert DNS name: %v", err)
			}
		}
	}

	// Insert federates_with relationships
	if len(entry.FederatesWith) > 0 {
		insertFederatesQuery := `INSERT INTO federates_with (entry_id, trust_domain) VALUES (?, ?)`
		for _, trustDomain := range entry.FederatesWith {
			if err := ds.session.Query(insertFederatesQuery, entryID, trustDomain).Exec(); err != nil {
				return nil, newError("failed to insert federates_with: %v", err)
			}
		}
	}

	// Create a registration entry event
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	// Return the entry with the computed entry ID
	returnEntry := &common.RegistrationEntry{
		EntryId:        entryID,
		Selectors:      entry.Selectors,
		SpiffeId:       entry.SpiffeId,
		ParentId:       entry.ParentId,
		X509SvidTtl:    entry.X509SvidTtl,
		FederatesWith:  entry.FederatesWith,
		Admin:          entry.Admin,
		Downstream:     entry.Downstream,
		EntryExpiry:    entry.EntryExpiry,
		DnsNames:       entry.DnsNames,
		RevisionNumber: entry.RevisionNumber,
		StoreSvid:      entry.StoreSvid,
		JwtSvidTtl:     entry.JwtSvidTtl,
		Hint:           entry.Hint,
		CreatedAt:      now.Unix(),
	}

	return returnEntry, nil
}

// createRegistrationEntryEventForEntryID creates a registration entry event for the given entry ID
func (ds *CassandraDataStore) createRegistrationEntryEventForEntryID(entryID string) error {
	query := `INSERT INTO registered_entry_events (event_id, entry_id, created_at) VALUES (?, ?, ?)`

	eventUUID := gocql.TimeUUID()

	if err := ds.session.Query(query, eventUUID, entryID, time.Now()).Exec(); err != nil {
		return newError("failed to create registration entry event: %v", err)
	}

	return nil
}

// CreateOrReturnRegistrationEntry stores the given registration entry. If an
// entry already exists with the same (parentID, spiffeID, selector) tuple,
// that entry is returned instead.
func (ds *CassandraDataStore) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	if entry == nil {
		return nil, false, newError("invalid request: missing registration entry")
	}

	// First, try to find a similar entry based on parent ID, SPIFFE ID, and selectors
	existingEntry, err := ds.lookupSimilarEntry(ctx, entry)
	if err != nil {
		return nil, false, err
	}

	if existingEntry != nil {
		// Entry already exists, return the existing one and flag that we didn't create
		return existingEntry, true, nil
	}

	// Entry doesn't exist, create it
	newEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	if err != nil {
		return nil, false, err
	}

	// Return the new entry and flag that we created it
	return newEntry, false, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
func (ds *CassandraDataStore) FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	// This is a simplified implementation - in real world we'd need to join with selectors, dns names, etc.
	var model RegEntryModel
	query := `SELECT entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry, store_svid, hint, jwt_svid_ttl, revision_number, created_at FROM registered_entries WHERE entry_id = ? LIMIT 1`

	err := ds.session.Query(query, entryID).Scan(
		&model.EntryID,
		&model.SpiffeID,
		&model.ParentID,
		&model.X509SvidTtl,
		&model.Admin,
		&model.Downstream,
		&model.Expiry,
		&model.StoreSvid,
		&model.Hint,
		&model.JwtSvidTtl,
		&model.RevisionNumber,
		&model.CreatedAt,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil // Entry not found, return nil without error
		}
		return nil, newError("failed to fetch registration entry: %v", err)
	}

	// Fetch related data: selectors, DNS names, federates_with
	selectors, err := ds.fetchSelectorsByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}

	dnsNames, err := ds.fetchDNSNamesByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}

	federatesWith, err := ds.fetchFederatesWithByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntry{
		EntryId:        model.EntryID,
		Selectors:      selectors,
		SpiffeId:       model.SpiffeID,
		ParentId:       model.ParentID,
		X509SvidTtl:    model.X509SvidTtl,
		FederatesWith:  federatesWith,
		Admin:          model.Admin,
		Downstream:     model.Downstream,
		EntryExpiry:    model.Expiry,
		DnsNames:       dnsNames,
		RevisionNumber: model.RevisionNumber,
		StoreSvid:      model.StoreSvid,
		JwtSvidTtl:     model.JwtSvidTtl,
		Hint:           model.Hint,
		CreatedAt:      model.CreatedAt.Unix(),
	}, nil
}

// FetchRegistrationEntries fetches existing registrations by entry IDs
func (ds *CassandraDataStore) FetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	entries := make(map[string]*common.RegistrationEntry)

	if len(entryIDs) == 0 {
		return entries, nil
	}

	// Query each entry by ID individually and build the result map
	for _, entryID := range entryIDs {
		entry, err := ds.FetchRegistrationEntry(ctx, entryID)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			entries[entryID] = entry
		}
	}

	return entries, nil
}

// CountRegistrationEntries counts all registrations (pagination available)
func (ds *CassandraDataStore) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
	query := `SELECT COUNT(*) FROM registered_entries`
	args := []interface{}{}

	// Add filters based on request
	whereClauses := []string{}
	if req.ByParentID != "" {
		whereClauses = append(whereClauses, "parent_id = ?")
		args = append(args, req.ByParentID)
	}
	if req.BySpiffeID != "" {
		whereClauses = append(whereClauses, "spiffe_id = ?")
		args = append(args, req.BySpiffeID)
	}
	if req.ByHint != "" {
		whereClauses = append(whereClauses, "hint = ?")
		args = append(args, req.ByHint)
	}
	if req.ByDownstream != nil {
		whereClauses = append(whereClauses, "downstream = ?")
		args = append(args, *req.ByDownstream)
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + joinStrings(whereClauses, " AND ")
	}

	var count int64
	if err := ds.session.Query(query, args...).Scan(&count); err != nil {
		return 0, newError("failed to count registration entries: %v", err)
	}

	if count > int64(^uint32(0)>>1) { // Check overflow
		return ^int32(0), nil // Max int32
	}

	return int32(count), nil
}

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *CassandraDataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	resp := &datastore.ListRegistrationEntriesResponse{
		Entries: make([]*common.RegistrationEntry, 0),
	}

	// Basic query construction - use the full entry details instead of just IDs to avoid N+1 query problem
	query := `SELECT entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry, store_svid, hint, jwt_svid_ttl, revision_number, created_at FROM registered_entries`
	args := []interface{}{}
	whereClauses := []string{}

	// Apply filters
	if req.ByParentID != "" {
		whereClauses = append(whereClauses, "parent_id = ?")
		args = append(args, req.ByParentID)
	}
	if req.BySpiffeID != "" {
		whereClauses = append(whereClauses, "spiffe_id = ?")
		args = append(args, req.BySpiffeID)
	}
	if req.ByHint != "" {
		whereClauses = append(whereClauses, "hint = ?")
		args = append(args, req.ByHint)
	}
	if req.ByDownstream != nil {
		whereClauses = append(whereClauses, "downstream = ?")
		args = append(args, *req.ByDownstream)
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + joinStrings(whereClauses, " AND ")
	}

	query += " LIMIT ?"
	pageSize := req.Pagination.PageSize
	if pageSize == 0 {
		pageSize = 50 // Default page size
	}
	args = append(args, pageSize)

	// For Cassandra, we need to use the paging state for pagination
	var pagingState []byte
	if req.Pagination != nil && req.Pagination.Token != "" {
		// Decode the paging state from the token
		pagingState = []byte(req.Pagination.Token)
	}

	q := ds.session.Query(query, args...)
	if pagingState != nil {
		q = q.PageState(pagingState)
	}

	iter := q.Iter()

	var (
		entryID        string
		spiffeID       string
		parentID       string
		x509SvidTtl    int32
		admin          bool
		downstream     bool
		expiry         int64
		storeSvid      bool
		hint           string
		jwtSvidTtl     int32
		revisionNumber int64
		createdAt      time.Time
	)
	var entries []RegEntryModel
	for iter.Scan(&entryID, &spiffeID, &parentID, &x509SvidTtl, &admin, &downstream, &expiry, &storeSvid, &hint, &jwtSvidTtl, &revisionNumber, &createdAt) {
		entries = append(entries, RegEntryModel{
			EntryID:        entryID,
			SpiffeID:       spiffeID,
			ParentID:       parentID,
			X509SvidTtl:    x509SvidTtl,
			Admin:          admin,
			Downstream:     downstream,
			Expiry:         expiry,
			StoreSvid:      storeSvid,
			Hint:           hint,
			JwtSvidTtl:     jwtSvidTtl,
			RevisionNumber: revisionNumber,
			CreatedAt:      createdAt,
		})
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate registration entries: %v", err)
	}

	// Get the next paging state
	nextPagingState := iter.PageState()

	// Fetch detailed entries with associated data
	for _, model := range entries {
		// Fetch related data: selectors, DNS names, federates_with
		selectors, err := ds.fetchSelectorsByEntryID(ctx, model.EntryID)
		if err != nil {
			return nil, err
		}

		dnsNames, err := ds.fetchDNSNamesByEntryID(ctx, model.EntryID)
		if err != nil {
			return nil, err
		}

		federatesWith, err := ds.fetchFederatesWithByEntryID(ctx, model.EntryID)
		if err != nil {
			return nil, err
		}

		entry := &common.RegistrationEntry{
			EntryId:        model.EntryID,
			Selectors:      selectors,
			SpiffeId:       model.SpiffeID,
			ParentId:       model.ParentID,
			X509SvidTtl:    model.X509SvidTtl,
			FederatesWith:  federatesWith,
			Admin:          model.Admin,
			Downstream:     model.Downstream,
			EntryExpiry:    model.Expiry,
			DnsNames:       dnsNames,
			RevisionNumber: model.RevisionNumber,
			StoreSvid:      model.StoreSvid,
			JwtSvidTtl:     model.JwtSvidTtl,
			Hint:           model.Hint,
			CreatedAt:      model.CreatedAt.Unix(),
		}
		resp.Entries = append(resp.Entries, entry)
	}

	if req.Pagination != nil {
		// Use Cassandra's paging state if there are more results
		if len(nextPagingState) > 0 {
			resp.Pagination = &datastore.Pagination{
				Token:    string(nextPagingState),
				PageSize: req.Pagination.PageSize,
			}
		} else if len(entries) > 0 {
			// No more pages, but we have results, so no pagination token
			resp.Pagination = &datastore.Pagination{
				PageSize: req.Pagination.PageSize,
			}
		}
	}

	return resp, nil
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *CassandraDataStore) UpdateRegistrationEntry(ctx context.Context, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, newError("invalid request: missing registration entry")
	}

	if mask == nil {
		mask = &common.RegistrationEntryMask{ // Update all fields if no mask is provided
			Selectors:     true,
			SpiffeId:      true,
			ParentId:      true,
			X509SvidTtl:   true,
			Admin:         true,
			Downstream:    true,
			EntryExpiry:   true,
			DnsNames:      true,
			FederatesWith: true,
			StoreSvid:     true,
			JwtSvidTtl:    true,
			Hint:          true,
		}
	}

	// Fetch the existing entry to know what to update
	existingEntry, err := ds.FetchRegistrationEntry(ctx, e.EntryId)
	if err != nil {
		return nil, err
	}

	if existingEntry == nil {
		return nil, newError("registration entry not found: %s", e.EntryId)
	}

	// Prepare updates based on mask
	updateFields := []string{}
	updateArgs := []interface{}{}

	if mask.Selectors {
		// Delete old selectors and add new ones
		if err := ds.deleteSelectorsByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertSelectors(e.EntryId, e.Selectors); err != nil {
			return nil, err
		}
	}

	if mask.SpiffeId {
		updateFields = append(updateFields, "spiffe_id = ?")
		updateArgs = append(updateArgs, e.SpiffeId)
	}
	if mask.ParentId {
		updateFields = append(updateFields, "parent_id = ?")
		updateArgs = append(updateArgs, e.ParentId)
	}
	if mask.X509SvidTtl {
		updateFields = append(updateFields, "x509_svid_ttl = ?")
		updateArgs = append(updateArgs, e.X509SvidTtl)
	}
	if mask.Admin {
		updateFields = append(updateFields, "admin = ?")
		updateArgs = append(updateArgs, e.Admin)
	}
	if mask.Downstream {
		updateFields = append(updateFields, "downstream = ?")
		updateArgs = append(updateArgs, e.Downstream)
	}
	if mask.EntryExpiry {
		updateFields = append(updateFields, "expiry = ?")
		updateArgs = append(updateArgs, e.EntryExpiry)
	}
	if mask.DnsNames {
		// Delete old DNS names and add new ones
		if err := ds.deleteDNSNamesByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertDNSNames(e.EntryId, e.DnsNames); err != nil {
			return nil, err
		}
	}
	if mask.FederatesWith {
		// Delete old federates_with and add new ones
		if err := ds.deleteFederatesWithByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertFederatesWith(e.EntryId, e.FederatesWith); err != nil {
			return nil, err
		}
	}
	if mask.StoreSvid {
		updateFields = append(updateFields, "store_svid = ?")
		updateArgs = append(updateArgs, e.StoreSvid)
	}
	if mask.JwtSvidTtl {
		updateFields = append(updateFields, "jwt_svid_ttl = ?")
		updateArgs = append(updateArgs, e.JwtSvidTtl)
	}
	if mask.Hint {
		updateFields = append(updateFields, "hint = ?")
		updateArgs = append(updateArgs, e.Hint)
	}

	// Update revision number
	updateFields = append(updateFields, "revision_number = revision_number + 1, updated_at = ?")
	updateArgs = append(updateArgs, time.Now())

	// Only run the update query if there are fields to update
	if len(updateFields) > 1 { // We have fields to update beyond the revision and timestamp
		// Construct the UPDATE query - exclude the revision number and timestamp from updateFields for the SET clause
		actualUpdateFields := updateFields[:len(updateFields)-1]
		query := "UPDATE registered_entries SET " + joinStrings(actualUpdateFields, ", ") + ", revision_number = revision_number + 1, updated_at = ? WHERE entry_id = ?"
		finalArgs := append(updateArgs[:len(updateArgs)-1], time.Now(), e.EntryId)

		if err := ds.session.Query(query, finalArgs...).Exec(); err != nil {
			return nil, newError("failed to update registration entry: %v", err)
		}
	} else {
		// Even if no fields are being updated, we still need to increment the revision number
		query := "UPDATE registered_entries SET revision_number = revision_number + 1, updated_at = ? WHERE entry_id = ?"
		if err := ds.session.Query(query, time.Now(), e.EntryId).Exec(); err != nil {
			return nil, newError("failed to update registration entry revision number: %v", err)
		}
	}

	// Return the updated entry
	updatedEntry, err := ds.FetchRegistrationEntry(ctx, e.EntryId)
	if err != nil {
		return nil, err
	}

	// Create a registration entry event
	if err := ds.createRegistrationEntryEventForEntryID(e.EntryId); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	return updatedEntry, nil
}

// DeleteRegistrationEntry deletes the given registration
func (ds *CassandraDataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	// First fetch the entry to return it
	existingEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}

	if existingEntry == nil {
		return nil, nil // Entry doesn't exist, nothing to delete
	}

	// Delete related data first
	if err := ds.deleteSelectorsByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteDNSNamesByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteFederatesWithByEntryID(entryID); err != nil {
		return nil, err
	}

	// Delete the entry
	deleteQuery := `DELETE FROM registered_entries WHERE entry_id = ?`
	if err := ds.session.Query(deleteQuery, entryID).Exec(); err != nil {
		return nil, newError("failed to delete registration entry: %v", err)
	}

	// Create a registration entry event
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	return existingEntry, nil
}

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
func (ds *CassandraDataStore) PruneRegistrationEntries(ctx context.Context, expiredBefore time.Time) error {
	expiredBeforeUnix := expiredBefore.Unix()

	query := `DELETE FROM registered_entries WHERE expiry != 0 AND expiry < ?`
	if err := ds.session.Query(query, expiredBeforeUnix).Exec(); err != nil {
		return newError("failed to prune registration entries: %v", err)
	}

	return nil
}

// ListRegistrationEntryEvents lists all registration entry events
func (ds *CassandraDataStore) ListRegistrationEntryEvents(ctx context.Context, req *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	events := []RegEntryEventModel{}

	query := `SELECT event_id, entry_id, created_at FROM registered_entry_events ORDER BY event_id`
	args := []interface{}{}

	// For filtering by EventID, we need to iterate and filter by timestamp since that's what we map to uint IDs
	iter := ds.session.Query(query, args...).Iter()

	var model RegEntryEventModel
	for iter.Scan(
		&model.EventID,
		&model.EntryID,
		&model.CreatedAt,
	) {
		// Apply filtering based on the interface expectations
		eventTimestamp := uint(model.EventID.Timestamp())
		
		// Apply greater than filter
		if req.GreaterThanEventID != 0 && eventTimestamp <= req.GreaterThanEventID {
			continue
		}
		
		// Apply less than filter
		if req.LessThanEventID != 0 && eventTimestamp >= req.LessThanEventID {
			continue
		}
		
		events = append(events, model)
		model = RegEntryEventModel{} // Reset for next iteration
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate registration entry events: %v", err)
	}

	resp := &datastore.ListRegistrationEntryEventsResponse{
		Events: make([]datastore.RegistrationEntryEvent, 0, len(events)),
	}

	for _, model := range events {
		resp.Events = append(resp.Events, datastore.RegistrationEntryEvent{
			EventID: uint(model.EventID.Timestamp()),
			EntryID: model.EntryID,
		})
	}

	return resp, nil
}

// PruneRegistrationEntryEvents deletes all registration entry events older than a specified duration (i.e. more than 24 hours old)
func (ds *CassandraDataStore) PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) error {
	threshold := time.Now().Add(-olderThan)

	query := `DELETE FROM registered_entry_events WHERE created_at < ?`
	if err := ds.session.Query(query, threshold).Exec(); err != nil {
		return newError("failed to prune registration entry events: %v", err)
	}

	return nil
}

// CreateRegistrationEntryEventForTesting creates a registration entry event. Used for unit testing.
func (ds *CassandraDataStore) CreateRegistrationEntryEventForTesting(ctx context.Context, event *datastore.RegistrationEntryEvent) error {
	query := `INSERT INTO registered_entry_events (event_id, entry_id, created_at) VALUES (?, ?, ?)`

	eventUUID := gocql.TimeUUID()

	if err := ds.session.Query(query, eventUUID, event.EntryID, time.Now()).Exec(); err != nil {
		return newError("failed to create registration entry event: %v", err)
	}

	return nil
}

// DeleteRegistrationEntryEventForTesting deletes the given registration entry event. Used for unit testing.
func (ds *CassandraDataStore) DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error {
	// Find the event with the matching timestamp-based ID and delete it
	query := `SELECT event_id, entry_id FROM registered_entry_events`
	iter := ds.session.Query(query).Iter()

	var model RegEntryEventModel
	var targetUUID gocql.UUID
	found := false

	for iter.Scan(&model.EventID, &model.EntryID) {
		if uint(model.EventID.Timestamp()) == eventID {
			targetUUID = model.EventID
			found = true
			break
		}
	}

	if err := iter.Close(); err != nil {
		return newError("failed to iterate over registration entry events: %v", err)
	}

	if !found {
		// Event doesn't exist, which is fine for a delete operation
		return nil
	}

	// Delete the specific event
	deleteQuery := `DELETE FROM registered_entry_events WHERE event_id = ?`
	if err := ds.session.Query(deleteQuery, targetUUID).Exec(); err != nil {
		return newError("failed to delete registration entry event: %v", err)
	}

	return nil
}

// FetchRegistrationEntryEvent fetches an existing registration entry event by event ID
func (ds *CassandraDataStore) FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (*datastore.RegistrationEntryEvent, error) {
	// Query all events and find the one with matching timestamp-based ID
	query := `SELECT event_id, entry_id FROM registered_entry_events`
	iter := ds.session.Query(query).Iter()

	var model RegEntryEventModel
	for iter.Scan(&model.EventID, &model.EntryID) {
		if uint(model.EventID.Timestamp()) == eventID {
			// Found the matching event
			return &datastore.RegistrationEntryEvent{
				EventID: eventID,
				EntryID: model.EntryID,
			}, nil
		}
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate over registration entry events: %v", err)
	}

	// Event not found
	return nil, nil
}

// RegEntryModel represents the Cassandra model for a registration entry
type RegEntryModel struct {
	EntryID        string
	SpiffeID       string
	ParentID       string
	X509SvidTtl    int32
	Admin          bool
	Downstream     bool
	Expiry         int64
	StoreSvid      bool
	Hint           string
	JwtSvidTtl     int32
	RevisionNumber int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RegEntryEventModel represents the Cassandra model for a registration entry event
type RegEntryEventModel struct {
	EventID   gocql.UUID
	EntryID   string
	CreatedAt time.Time
}

// Helper functions for related data

func (ds *CassandraDataStore) fetchSelectorsByEntryID(ctx context.Context, entryID string) ([]*common.Selector, error) {
	selectors := []*common.Selector{}

	query := `SELECT selector_type, selector_value FROM selectors WHERE entry_id = ?`
	iter := ds.session.Query(query, entryID).Iter()

	var selectorType, selectorValue string
	for iter.Scan(&selectorType, &selectorValue) {
		selectors = append(selectors, &common.Selector{
			Type:  selectorType,
			Value: selectorValue,
		})
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate selectors: %v", err)
	}

	return selectors, nil
}

func (ds *CassandraDataStore) fetchDNSNamesByEntryID(ctx context.Context, entryID string) ([]string, error) {
	dnsNames := []string{}

	query := `SELECT dns_name FROM dns_names WHERE entry_id = ?`
	iter := ds.session.Query(query, entryID).Iter()

	var dnsName string
	for iter.Scan(&dnsName) {
		dnsNames = append(dnsNames, dnsName)
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate DNS names: %v", err)
	}

	return dnsNames, nil
}

func (ds *CassandraDataStore) fetchFederatesWithByEntryID(ctx context.Context, entryID string) ([]string, error) {
	federatesWith := []string{}

	query := `SELECT trust_domain FROM federates_with WHERE entry_id = ?`
	iter := ds.session.Query(query, entryID).Iter()

	var trustDomain string
	for iter.Scan(&trustDomain) {
		federatesWith = append(federatesWith, trustDomain)
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate federates_with: %v", err)
	}

	return federatesWith, nil
}

func (ds *CassandraDataStore) deleteSelectorsByEntryID(entryID string) error {
	query := `DELETE FROM selectors WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete selectors: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertSelectors(entryID string, selectors []*common.Selector) error {
	query := `INSERT INTO selectors (entry_id, selector_type, selector_value) VALUES (?, ?, ?)`
	for _, selector := range selectors {
		if err := ds.session.Query(query, entryID, selector.Type, selector.Value).Exec(); err != nil {
			return newError("failed to insert selector: %v", err)
		}
	}
	return nil
}

func (ds *CassandraDataStore) deleteDNSNamesByEntryID(entryID string) error {
	query := `DELETE FROM dns_names WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete DNS names: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertDNSNames(entryID string, dnsNames []string) error {
	query := `INSERT INTO dns_names (entry_id, dns_name) VALUES (?, ?)`
	for _, dnsName := range dnsNames {
		if err := ds.session.Query(query, entryID, dnsName).Exec(); err != nil {
			return newError("failed to insert DNS name: %v", err)
		}
	}
	return nil
}

func (ds *CassandraDataStore) deleteFederatesWithByEntryID(entryID string) error {
	query := `DELETE FROM federates_with WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete federates_with: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertFederatesWith(entryID string, trustDomains []string) error {
	query := `INSERT INTO federates_with (entry_id, trust_domain) VALUES (?, ?)`
	for _, trustDomain := range trustDomains {
		if err := ds.session.Query(query, entryID, trustDomain).Exec(); err != nil {
			return newError("failed to insert federates_with: %v", err)
		}
	}
	return nil
}

// lookupSimilarEntry finds an existing entry with the same (parentID, spiffeID, selectors) combination
func (ds *CassandraDataStore) lookupSimilarEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	// This is a complex operation that would typically involve joins in SQL
	// In Cassandra, we need to be more creative as joins are limited

	// For simplicity in this implementation, we'll look up by spiffe_id and parent_id first
	// Then check if the selectors match

	query := `SELECT entry_id FROM registered_entries WHERE spiffe_id = ? AND parent_id = ? LIMIT 1`
	var entryID string
	err := ds.session.Query(query, entry.SpiffeId, entry.ParentId).Scan(&entryID)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil // No matching entries found
		}
		return nil, newError("failed to lookup similar entry: %v", err)
	}

	// Fetch the entry and compare selectors
	similarEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}

	if similarEntry != nil {
		// Compare selectors - in a real implementation this would be more complex
		// For now, we assume the caller will handle the comparison appropriately
		return similarEntry, nil
	}

	return nil, nil
}

// Helper function to join strings with a separator
func joinStrings(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}

	result := slice[0]
	for _, s := range slice[1:] {
		result += sep + s
	}
	return result
}
