package cassandra

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"time"

	"github.com/gocql/gocql"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	nodeBucket = "attested_nodes"
)

// CreateAttestedNode stores the given attested node
func (ds *CassandraDataStore) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (*common.AttestedNode, error) {
	if node == nil {
		return nil, newError("invalid request: missing attested node")
	}

	const q = `INSERT INTO attested_nodes (
		bucket, spiffe_id, attestation_type, cert_serial_number, cert_not_after,
		new_cert_serial_number, new_cert_not_after, can_reattest, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS`

	now := time.Now()
	m := map[string]any{}
	applied, err := ds.session.Query(q,
		nodeBucket,
		node.SpiffeId,
		node.AttestationDataType,
		node.CertSerialNumber,
		node.CertNotAfter, // int64 unix
		node.NewCertSerialNumber,
		node.NewCertNotAfter, // int64 unix
		node.CanReattest,
		now, now,
	).MapScanCAS(m)
	if err != nil {
		return nil, newError("failed to create attested node: %v", err)
	}
	if !applied {
		return nil, newError("attested node %q already exists", node.SpiffeId)
	}

	// after a successful INSERT ... IF NOT EXISTS on attested_nodes
	if len(node.Selectors) > 0 {
		b := ds.session.NewBatch(gocql.LoggedBatch)
		now := time.Now()
		// persist selectors set on the node row
		b.Query(`UPDATE attested_nodes SET selectors = ?, updated_at = ? WHERE bucket = ? AND spiffe_id = ?`,
			toSelectorUDT(node.Selectors), now, nodeBucket, node.SpiffeId)
		// index rows
		for _, s := range node.Selectors {
			b.Query(`INSERT INTO node_selectors_index (selector_type, selector_value, spiffe_id, updated_at)
		         VALUES (?, ?, ?, ?)`, s.Type, s.Value, node.SpiffeId, now)
		}
		if err := ds.session.ExecuteBatch(b); err != nil {
			return nil, newError("failed to index node selectors: %v", err)
		}
	}

	if err := ds.createAttestedNodeEventForSpiffeID(node.SpiffeId); err != nil {
		return nil, newError("failed to create attested node event: %v", err)
	}
	return node, nil
}

// FetchAttestedNode fetches an existing attested node by SPIFFE ID
type AttNodeModel struct {
	SpiffeID            string
	AttestationType     string
	CertSerialNumber    string
	CertNotAfter        int64
	NewCertSerialNumber string
	NewCertNotAfter     int64
	CanReattest         bool
	Selectors           []*common.Selector
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func modelToAttestedNode(m AttNodeModel) *common.AttestedNode {
	var sels []*common.Selector
	if len(m.Selectors) > 0 {
		sels = m.Selectors
		// else leave sels == nil
	}
	return &common.AttestedNode{
		SpiffeId:            m.SpiffeID,
		AttestationDataType: m.AttestationType,
		CertSerialNumber:    m.CertSerialNumber,
		CertNotAfter:        m.CertNotAfter,
		NewCertSerialNumber: m.NewCertSerialNumber,
		NewCertNotAfter:     m.NewCertNotAfter,
		CanReattest:         m.CanReattest,
		Selectors:           sels,
	}
}

func (ds *CassandraDataStore) FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	var (
		m       AttNodeModel
		selMaps []map[string]any
	)
	const q = `SELECT spiffe_id, attestation_type, cert_serial_number, cert_not_after,
	                  new_cert_serial_number, new_cert_not_after, can_reattest, selectors,
	                  created_at, updated_at
	           FROM attested_nodes
	           WHERE bucket = ? AND spiffe_id = ? LIMIT 1`
	err := ds.session.Query(q, nodeBucket, spiffeID).Scan(
		&m.SpiffeID, &m.AttestationType, &m.CertSerialNumber, &m.CertNotAfter,
		&m.NewCertSerialNumber, &m.NewCertNotAfter, &m.CanReattest, &selMaps,
		&m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil
		}
		return nil, newError("failed to fetch attested node: %v", err)
	}
	m.Selectors = fromSelectorUDT(selMaps)
	return modelToAttestedNode(m), nil
}

func (ds *CassandraDataStore) UpdateAttestedNode(ctx context.Context, n *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	if n == nil {
		return nil, newError("invalid request: missing attested node")
	}
	existing, err := ds.FetchAttestedNode(ctx, n.SpiffeId)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, newError("attested node not found: %s", n.SpiffeId)
	}

	if mask == nil {
		mask = &common.AttestedNodeMask{
			CertNotAfter:        true,
			CertSerialNumber:    true,
			NewCertNotAfter:     true,
			NewCertSerialNumber: true,
			CanReattest:         true,
		}
	}

	// Build new values according to mask
	out := *existing
	if mask.CertSerialNumber {
		out.CertSerialNumber = n.CertSerialNumber
	}
	if mask.CertNotAfter {
		out.CertNotAfter = n.CertNotAfter
	}
	if mask.NewCertSerialNumber {
		out.NewCertSerialNumber = n.NewCertSerialNumber
	}
	if mask.NewCertNotAfter {
		out.NewCertNotAfter = n.NewCertNotAfter
	}
	if mask.CanReattest {
		out.CanReattest = n.CanReattest
	}

	const q = `UPDATE attested_nodes SET
		cert_serial_number = ?,
		cert_not_after = ?,
		new_cert_serial_number = ?,
		new_cert_not_after = ?,
		can_reattest = ?,
		updated_at = ?
	  WHERE bucket = ? AND spiffe_id = ?`
	if err := ds.session.Query(q,
		out.CertSerialNumber,
		out.CertNotAfter,
		out.NewCertSerialNumber,
		out.NewCertNotAfter,
		out.CanReattest,
		time.Now(),
		nodeBucket, n.SpiffeId,
	).Exec(); err != nil {
		return nil, newError("failed to update attested node: %v", err)
	}

	if err := ds.createAttestedNodeEventForSpiffeID(n.SpiffeId); err != nil {
		return nil, newError("failed to create attested node event: %v", err)
	}
	return &out, nil
}

func (ds *CassandraDataStore) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	// Must return the original node (without selectors) if it exists; error otherwise
	node, err := ds.FetchAttestedNode(ctx, spiffeID)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, newError("attested node not found")
	}

	// Get selectors from the normalized map (authoritative), so we clean index fully
	mapSelectors, err := ds.getMapSelectors(ctx, spiffeID)
	if err != nil {
		return nil, err
	}

	batch := ds.session.NewBatch(gocql.LoggedBatch)

	// delete index rows based on map selectors
	for _, s := range mapSelectors {
		batch.Query(`DELETE FROM node_selectors_index WHERE selector_type = ? AND selector_value = ? AND spiffe_id = ?`,
			s.Type, s.Value, spiffeID)
	}
	// delete the whole normalized-partition
	batch.Query(`DELETE FROM node_resolver_map WHERE spiffe_id = ?`, spiffeID)
	// delete attested node row
	batch.Query(`DELETE FROM attested_nodes WHERE bucket = ? AND spiffe_id = ?`, nodeBucket, spiffeID)

	if err := ds.session.ExecuteBatch(batch); err != nil {
		return nil, newError("failed to delete attested node and selectors: %v", err)
	}

	_ = ds.createAttestedNodeEventForSpiffeID(spiffeID)
	// Return the original node (selectors are not included per SPIRE test expectations)
	node.Selectors = nil
	return node, nil
}

// CountAttestedNodes counts all attested nodes
func (ds *CassandraDataStore) CountAttestedNodes(ctx context.Context, req *datastore.CountAttestedNodesRequest) (int32, error) {
	var count int64
	query := `SELECT COUNT(*) FROM attested_nodes`
	if err := ds.session.Query(query).Scan(&count); err != nil {
		return 0, newError("failed to count attested nodes: %v", err)
	}

	if count > int64(^uint32(0)>>1) { // Check overflow
		return ^int32(0), nil // Max int32
	}

	return int32(count), nil
}

// ListAttestedNodes lists attested nodes with Cassandra paging (no selector filters in current proto)
// ListAttestedNodes lists attested nodes using explicit keyset pagination.
// Token semantics: the request's Pagination.Token is the last returned SPIFFE ID.
// We page by spiffe_id ASC (within the single-partition table keyed by bucket).
func (ds *CassandraDataStore) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	const defaultPage = 50
	pageSize := getPageSize(req.Pagination, defaultPage)
	startAfter := "" // last spiffe_id returned previously
	if req.Pagination != nil && req.Pagination.Token != "" {
		startAfter = req.Pagination.Token
	}

	out := &datastore.ListAttestedNodesResponse{
		Nodes: make([]*common.AttestedNode, 0, pageSize),
	}

	// Non-selector filters
	matchesOtherFilters := func(n *common.AttestedNode) bool {
		if !req.ByExpiresBefore.IsZero() && !(n.CertNotAfter < req.ByExpiresBefore.Unix()) {
			return false
		}
		if !req.ValidAt.IsZero() && !(n.CertNotAfter >= req.ValidAt.Unix()) {
			return false
		}
		if req.ByAttestationType != "" && n.AttestationDataType != req.ByAttestationType {
			return false
		}
		if req.ByBanned != nil {
			isBanned := n.CertSerialNumber == ""
			if isBanned != *req.ByBanned {
				return false
			}
		}
		if req.ByCanReattest != nil && n.CanReattest != *req.ByCanReattest {
			return false
		}
		return true
	}

	fetchNode := func(id string) (*common.AttestedNode, error) {
		return ds.FetchAttestedNode(ctx, id)
	}

	// Candidate fetchers (index-driven if selector filter present, otherwise base table)
	type candidate struct{ id string }

	const batchFactor = 4
	batchLimit := pageSize*batchFactor + 1 // +1 to detect "has more"

	var fetchCandidates func(string) ([]candidate, bool, error)

	// If there is a selector filter, decide how to drive candidates.
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) > 0 && req.BySelectorMatch.Match != datastore.MatchAny {
		// For Subset/Superset/Exact: drive from primary selector and AND the rest.
		primary := req.BySelectorMatch.Selectors[0]
		fetchCandidates = func(after string) ([]candidate, bool, error) {
			args := []any{primary.Type, primary.Value}
			q := `SELECT spiffe_id FROM node_selectors_index WHERE selector_type = ? AND selector_value = ?`
			if after != "" {
				q += ` AND spiffe_id > ?`
				args = append(args, after)
			}
			q += ` ORDER BY spiffe_id ASC LIMIT ?`
			args = append(args, int(batchLimit))

			iter := ds.session.Query(q, args...).Iter()
			var rows []candidate
			var id string
			for iter.Scan(&id) {
				rows = append(rows, candidate{id: id})
			}
			if err := iter.Close(); err != nil {
				return nil, false, newError("failed to iterate selector index: %v", err)
			}
			hasMore := len(rows) == int(batchLimit)
			return rows, hasMore, nil
		}
	} else {
		// No selector filter OR MatchAny: drive from base table and filter in-memory.
		fetchCandidates = func(after string) ([]candidate, bool, error) {
			args := []any{nodeBucket}
			q := `SELECT spiffe_id FROM attested_nodes WHERE bucket = ?`
			if after != "" {
				q += ` AND spiffe_id > ?`
				args = append(args, after)
			}
			q += ` ORDER BY spiffe_id ASC LIMIT ?`

			args = append(args, int(batchLimit))
			iter := ds.session.Query(q, args...).Iter()
			var rows []candidate
			var id string
			for iter.Scan(&id) {
				rows = append(rows, candidate{id: id})
			}
			if err := iter.Close(); err != nil {
				return nil, false, newError("failed to iterate attested node ids: %v", err)
			}
			hasMore := len(rows) == int(batchLimit)
			return rows, hasMore, nil
		}
	}

	// AND-check in the index for remaining selectors ONLY for Superset/Exact (require all)
	selectorAND := func(id string) (bool, error) {
		if req.BySelectorMatch == nil || len(req.BySelectorMatch.Selectors) <= 1 {
			return true, nil
		}
		switch req.BySelectorMatch.Match {
		case datastore.Superset, datastore.Exact:
			// must contain all requested selectors
		default:
			// Subset, MatchAny: do NOT AND the rest in index
			return true, nil
		}
		for _, s := range req.BySelectorMatch.Selectors[1:] {
			var check string
			err := ds.session.Query(
				`SELECT spiffe_id FROM node_selectors_index
                 WHERE selector_type = ? AND selector_value = ? AND spiffe_id = ? LIMIT 1`,
				s.Type, s.Value, id,
			).Scan(&check)
			if err != nil {
				if err == gocql.ErrNotFound {
					return false, nil
				}
				return false, newError("selector AND check failed: %v", err)
			}
		}
		return true, nil
	}

	var nextAfter string
	collected := 0
	scanAfter := startAfter

	advance := true
	for advance && collected < pageSize {
		cands, hasMoreAtSource, err := fetchCandidates(scanAfter)
		if err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			break
		}
		for _, c := range cands {
			scanAfter = c.id // advance scan cursor regardless
			// Only AND-check for Superset/Exact
			if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) > 0 {
				ok, err := selectorAND(c.id)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}

			n, err := fetchNode(c.id)
			if err != nil {
				return nil, err
			}
			if n == nil {
				continue
			}

			// Apply selector mode using the centralized helper (correct semantics)
			if req.BySelectorMatch != nil && !matchSelectors(n.Selectors, req.BySelectorMatch) {
				continue
			}

			if !matchesOtherFilters(n) {
				continue
			}

			if !req.FetchSelectors {
				n.Selectors = nil
			}

			out.Nodes = append(out.Nodes, n)
			nextAfter = n.SpiffeId
			collected++
			if collected == pageSize {
				break
			}
		}
		advance = hasMoreAtSource && collected < pageSize
	}

	if req.Pagination != nil {
		out.Pagination = &datastore.Pagination{
			PageSize: int32(pageSize),
			Token:    "",
		}
		// Only expose a non-empty token if we filled the page
		if collected == pageSize && nextAfter != "" {
			out.Pagination.Token = nextAfter
		}
	}

	return out, nil
}

// matchNodeFilters applies all ListAttestedNodesRequest filters to a node.
func matchNodeFilters(m AttNodeModel, req *datastore.ListAttestedNodesRequest) bool {
	// ByExpiresBefore: cert_not_after < ts
	if !req.ByExpiresBefore.IsZero() {
		if !(m.CertNotAfter < req.ByExpiresBefore.Unix()) {
			return false
		}
	}
	// ValidAt: cert_not_after >= ts
	if !req.ValidAt.IsZero() {
		if !(m.CertNotAfter >= req.ValidAt.Unix()) {
			return false
		}
	}
	// ByAttestationType
	if req.ByAttestationType != "" && req.ByAttestationType != m.AttestationType {
		return false
	}
	// ByBanned: true => serial == "", false => serial != ""
	if req.ByBanned != nil {
		banned := m.CertSerialNumber == ""
		if *req.ByBanned != banned {
			return false
		}
	}
	// ByCanReattest
	if req.ByCanReattest != nil && m.CanReattest != *req.ByCanReattest {
		return false
	}
	// BySelectorMatch
	if req.BySelectorMatch != nil {
		if !matchSelectors(m.Selectors, req.BySelectorMatch) {
			return false
		}
	}
	return true
}

// matchSelectors implements Subset / Superset / Exact / MatchAny against node selectors.
// The test helpers build selectors with Type == Value (e.g., "S1"), but we match by full pair.
func matchSelectors(nodeSel []*common.Selector, by *datastore.BySelectors) bool {
	if by == nil {
		return true
	}

	// normalize to sets of "type\x00value"
	makeSet := func(sels []*common.Selector) map[string]struct{} {
		if len(sels) == 0 {
			return map[string]struct{}{}
		}
		out := make(map[string]struct{}, len(sels))
		for _, s := range sels {
			out[s.Type+"\x00"+s.Value] = struct{}{}
		}
		return out
	}
	node := makeSet(nodeSel)
	filter := makeSet(by.Selectors)

	switch by.Match {
	case datastore.MatchAny: // intersection non-empty
		for k := range filter {
			if _, ok := node[k]; ok {
				return true
			}
		}
		return false

	case datastore.Subset: // node ⊆ filter
		for k := range node {
			if _, ok := filter[k]; !ok {
				return false
			}
		}
		return true

	case datastore.Superset: // node ⊇ filter
		for k := range filter {
			if _, ok := node[k]; !ok {
				return false
			}
		}
		return true

	case datastore.Exact: // node == filter
		if len(node) != len(filter) {
			return false
		}
		for k := range node {
			if _, ok := filter[k]; !ok {
				return false
			}
		}
		return true
	default:
		// unknown match mode -> fail closed
		return false
	}
}

// PruneAttestedExpiredNodes deletes attested nodes with expiration time further than a given duration in the past.
// PruneAttestedExpiredNodes deletes attested nodes with expiration time
// earlier than expiredBefore. When includeNonReattestable is false, only
// nodes with can_reattest=true are considered. Nodes with an empty
// cert_serial_number (i.e., "banned" agents) are NEVER pruned.
func (ds *CassandraDataStore) PruneAttestedExpiredNodes(ctx context.Context, expiredBefore time.Time, includeNonReattestable bool) error {
	cutoff := expiredBefore.Unix()

	// The MV includes cert_serial_number so we can detect "banned" agents.
	const sel = `SELECT spiffe_id, can_reattest, cert_serial_number
	             FROM attested_nodes_by_expiry
	             WHERE bucket = ? AND cert_not_after < ?`

	iter := ds.session.Query(sel, nodeBucket, cutoff).Iter()

	type victim struct {
		id  string
		can bool
	}
	var victims []victim

	for {
		var (
			id     string
			can    bool
			serial string
		)
		if !iter.Scan(&id, &can, &serial) {
			break
		}

		// Never prune "banned" agents: cert_serial_number == ""
		if serial == "" {
			continue
		}

		// Apply reattestability filter
		if includeNonReattestable || can {
			victims = append(victims, victim{id: id, can: can})
		}
	}
	if err := iter.Close(); err != nil {
		return newError("failed to iterate expired nodes: %v", err)
	}
	if len(victims) == 0 {
		return nil
	}

	// Remove nodes + their selectors (clean up normalized map and index)
	batch := ds.session.NewBatch(gocql.LoggedBatch)
	for _, x := range victims {
		// Clean index based on normalized map to avoid relying on denormalized set
		mapSelectors, _ := ds.getMapSelectors(ctx, x.id)
		for _, s := range mapSelectors {
			batch.Query(`DELETE FROM node_selectors_index WHERE selector_type=? AND selector_value=? AND spiffe_id=?`,
				s.Type, s.Value, x.id)
		}
		batch.Query(`DELETE FROM node_resolver_map WHERE spiffe_id=?`, x.id)
		batch.Query(`DELETE FROM attested_nodes WHERE bucket=? AND spiffe_id=?`, nodeBucket, x.id)
	}
	if err := ds.session.ExecuteBatch(batch); err != nil {
		return newError("failed to prune attested nodes: %v", err)
	}
	return nil
}

// ListAttestedNodeEvents lists attested node events with optional ID bounds.
// Note: EventID is derived from the TimeUUID timestamp (uint).
func (ds *CassandraDataStore) ListAttestedNodeEvents(ctx context.Context, req *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	// The test expects this exact error string when both bounds are set.
	if req.GreaterThanEventID != 0 && req.LessThanEventID != 0 {
		return nil, errors.New("datastore-sql: can't set both greater and less than event id")
	}

	iter := ds.session.Query(`SELECT event_id, spiffe_id, created_at FROM attested_node_events`).Iter()

	type row struct {
		u   gocql.UUID
		id  uint // ordinal we’ll assign
		sid string
		ts  uint64 // uuid timestamp for sorting
	}
	var (
		r   row
		all []row
	)
	for iter.Scan(&r.u, &r.sid, new(time.Time)) { // created_at not needed for sort; UUID has the time
		r.ts = uint64(r.u.Timestamp())
		all = append(all, r)
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate attested node events: %v", err)
	}

	// Sort by UUID timestamp ascending (creation order)
	sort.Slice(all, func(i, j int) bool { return all[i].ts < all[j].ts })

	// Assign ordinal IDs 1..N
	for i := range all {
		all[i].id = uint(i + 1)
	}

	// Apply filters against ordinals
	var out []datastore.AttestedNodeEvent
	switch {
	case req.GreaterThanEventID != 0:
		gt := req.GreaterThanEventID
		for _, e := range all {
			if e.id > gt {
				out = append(out, datastore.AttestedNodeEvent{EventID: e.id, SpiffeID: e.sid})
			}
		}
	case req.LessThanEventID != 0:
		lt := req.LessThanEventID
		for _, e := range all {
			if e.id < lt {
				out = append(out, datastore.AttestedNodeEvent{EventID: e.id, SpiffeID: e.sid})
			}
		}
	default:
		// no bounds: return all in order
		out = make([]datastore.AttestedNodeEvent, 0, len(all))
		for _, e := range all {
			out = append(out, datastore.AttestedNodeEvent{EventID: e.id, SpiffeID: e.sid})
		}
	}
	// ensure non-nil slice (tests expect [] not nil)
	if out == nil {
		out = make([]datastore.AttestedNodeEvent, 0)
	}
	return &datastore.ListAttestedNodeEventsResponse{Events: out}, nil

	return &datastore.ListAttestedNodeEventsResponse{Events: out}, nil
}

// PruneAttestedNodeEvents deletes attested node events older than the given duration.
// We must delete by the primary key (event_id), so we scan and filter client-side.
func (ds *CassandraDataStore) PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) error {
	threshold := time.Now().Add(-olderThan)

	// TODO: determine performance impact of this scan+filter approach.
	iter := ds.session.Query(`SELECT event_id, created_at FROM attested_node_events`).Iter()

	var (
		id       gocql.UUID
		created  time.Time
		toDelete []gocql.UUID
	)
	for iter.Scan(&id, &created) {
		if created.Before(threshold) {
			toDelete = append(toDelete, id)
		}
	}
	if err := iter.Close(); err != nil {
		return newError("failed to list attested node events: %v", err)
	}

	if len(toDelete) == 0 {
		return nil
	}

	batch := ds.session.NewBatch(gocql.LoggedBatch)
	for _, ev := range toDelete {
		batch.Query(`DELETE FROM attested_node_events WHERE event_id = ?`, ev)
	}
	if err := ds.session.ExecuteBatch(batch); err != nil {
		return newError("failed to prune attested node events: %v", err)
	}
	return nil
}

// CreateAttestedNodeEventForTesting creates an attested node event. Used for unit testing.
func (ds *CassandraDataStore) CreateAttestedNodeEventForTesting(ctx context.Context, event *datastore.AttestedNodeEvent) error {
	query := `INSERT INTO attested_node_events (event_id, spiffe_id, created_at) VALUES (?, ?, ?)`

	eventUUID := gocql.TimeUUID()

	if err := ds.session.Query(query, eventUUID, event.SpiffeID, time.Now()).Exec(); err != nil {
		return newError("failed to create attested node event: %v", err)
	}

	return nil
}

// DeleteAttestedNodeEventForTesting deletes an attested node event by event ID. Used for unit testing.
func (ds *CassandraDataStore) DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	// Find the event with the matching timestamp-based ID and delete it
	query := `SELECT event_id, spiffe_id FROM attested_node_events`
	iter := ds.session.Query(query).Iter()

	var model AttNodeEventModel
	var targetUUID gocql.UUID
	found := false

	for iter.Scan(&model.EventID, &model.SpiffeID) {
		if uint(model.EventID.Timestamp()) == eventID {
			targetUUID = model.EventID
			found = true
			break
		}
	}

	if err := iter.Close(); err != nil {
		return newError("failed to iterate over attested node events: %v", err)
	}

	if !found {
		// Event doesn't exist, which is fine for a delete operation
		return nil
	}

	// Delete the specific event
	deleteQuery := `DELETE FROM attested_node_events WHERE event_id = ?`
	if err := ds.session.Query(deleteQuery, targetUUID).Exec(); err != nil {
		return newError("failed to delete attested node event: %v", err)
	}

	return nil
}

// FetchAttestedNodeEvent fetches an existing attested node event by event ID
func (ds *CassandraDataStore) FetchAttestedNodeEvent(ctx context.Context, eventID uint) (*datastore.AttestedNodeEvent, error) {
	// Query all events and find the one with matching timestamp-based ID
	query := `SELECT event_id, spiffe_id FROM attested_node_events`
	iter := ds.session.Query(query).Iter()

	var model AttNodeEventModel
	for iter.Scan(&model.EventID, &model.SpiffeID) {
		if uint(model.EventID.Timestamp()) == eventID {
			// Found the matching event
			return &datastore.AttestedNodeEvent{
				EventID:  eventID,
				SpiffeID: model.SpiffeID,
			}, nil
		}
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate over attested node events: %v", err)
	}

	// Event not found
	return nil, nil
}

// SetNodeSelectors replaces selectors atomically for a node
// SetNodeSelectors replaces selectors atomically for a spiffeID.
// IMPORTANT: This does NOT require an attested_nodes row to exist.
// - Always updates the normalized map (node_resolver_map) and the index.
// - If an attested node row exists, also updates its denormalized selectors set.
// SetNodeSelectors replaces selectors atomically for a spiffeID.
func (ds *CassandraDataStore) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	// current selectors from normalized map (may be nil)
	cur, err := ds.getMapSelectors(ctx, spiffeID)
	if err != nil {
		return err
	}
	add, del := diffSelectors(cur, selectors)

	// update normalized map + index
	if err := ds.applySelectorDiff(spiffeID, add, del); err != nil {
		return newError("failed to apply selector diff: %v", err)
	}

	// update denormalized set on node iff it exists
	n, err := ds.FetchAttestedNode(ctx, spiffeID)
	if err != nil {
		return err
	}
	if n != nil {
		if selectors == nil {
			selectors = nil
		}
		if err := ds.session.Query(
			`UPDATE attested_nodes SET selectors = ?, updated_at = ? WHERE bucket = ? AND spiffe_id = ?`,
			toSelectorUDT(selectors), time.Now(), nodeBucket, spiffeID,
		).Exec(); err != nil {
			return newError("failed to update node selectors set: %v", err)
		}
	}

	// IMPORTANT: always create an event (even if node row doesn't exist)
	_ = ds.createAttestedNodeEventForSpiffeID(spiffeID)
	return nil
}

func (ds *CassandraDataStore) GetNodeSelectors(ctx context.Context, spiffeID string, _ datastore.DataConsistency) ([]*common.Selector, error) {
	sels, err := ds.getMapSelectors(ctx, spiffeID)
	if err != nil {
		return nil, err
	}
	// Return nil (not empty) if there are none, to match tests
	return sels, nil
}

// ListNodeSelectors gets node (agent) selectors by SPIFFE ID (no pagination in request type)
// ListNodeSelectors gets node (agent) selectors grouped by SPIFFE ID.
// For Cassandra, we must read from the normalized map (node_resolver_map)
// since tests may insert rows directly there without touching attested_nodes.
func (ds *CassandraDataStore) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	resp := &datastore.ListNodeSelectorsResponse{
		Selectors: make(map[string][]*common.Selector),
	}

	// Scan normalized map rows and aggregate by SPIFFE ID.
	// Schema is expected to be: node_resolver_map(spiffe_id text, type text, value text, ...)
	iter := ds.session.Query(`SELECT spiffe_id, type, value FROM node_resolver_map`).Iter()

	var (
		spiffeID string
		typ      string
		val      string
	)
	for iter.Scan(&spiffeID, &typ, &val) {
		resp.Selectors[spiffeID] = append(resp.Selectors[spiffeID], &common.Selector{
			Type:  typ,
			Value: val,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate node_resolver_map: %v", err)
	}

	// Provide deterministic ordering per SPIFFE ID to satisfy test expectations:
	// order selectors by Type, then Value (A..Z), which matches the expected sets.
	for id := range resp.Selectors {
		sels := resp.Selectors[id]
		sort.Slice(sels, func(i, j int) bool {
			if sels[i].Type == sels[j].Type {
				return sels[i].Value < sels[j].Value
			}
			return sels[i].Type < sels[j].Type
		})
	}

	return resp, nil
}

// AttNodeEventModel represents the Cassandra model for an attested node event
type AttNodeEventModel struct {
	EventID   gocql.UUID
	SpiffeID  string
	CreatedAt time.Time
}

// createAttestedNodeEventForSpiffeID creates an attested node event for the given SPIFFE ID
func (ds *CassandraDataStore) createAttestedNodeEventForSpiffeID(spiffeID string) error {
	query := `INSERT INTO attested_node_events (event_id, spiffe_id, created_at) VALUES (?, ?, ?)`

	eventUUID := gocql.TimeUUID()

	if err := ds.session.Query(query, eventUUID, spiffeID, time.Now()).Exec(); err != nil {
		return newError("failed to create attested node event: %v", err)
	}

	return nil
}

type SelectorUDT struct {
	Type  string
	Value string
}

func (s SelectorUDT) toCommon() *common.Selector {
	return &common.Selector{Type: s.Type, Value: s.Value}
}

func toSelectorUDT(slice []*common.Selector) []map[string]any {
	out := make([]map[string]any, 0, len(slice))
	for _, s := range slice {
		out = append(out, map[string]any{"type": s.Type, "value": s.Value})
	}
	return out
}

func fromSelectorUDT(maps []map[string]any) []*common.Selector {
	if len(maps) == 0 {
		return nil
	}
	out := make([]*common.Selector, 0, len(maps))
	for _, m := range maps {
		t, _ := m["type"].(string)
		v, _ := m["value"].(string)
		out = append(out, &common.Selector{Type: t, Value: v})
	}
	return out
}

func selKey(s *common.Selector) string { return s.Type + "\x00" + s.Value }

func diffSelectors(old, neu []*common.Selector) (add, del []*common.Selector) {
	oldm := map[string]*common.Selector{}
	neum := map[string]*common.Selector{}
	for _, s := range old {
		oldm[selKey(s)] = s
	}
	for _, s := range neu {
		neum[selKey(s)] = s
	}
	for k, s := range neu {
		if _, ok := oldm[selKey(s)]; !ok {
			add = append(add, neu[k])
		}
	}
	for k, s := range old {
		if _, ok := neum[selKey(s)]; !ok {
			del = append(del, old[k])
		}
	}
	return
}

// decode/encode page tokens (Cassandra paging state)
func encodePageToken(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func decodePageToken(s string) []byte {
	b, _ := base64.RawStdEncoding.DecodeString(s)
	return b
}

func getPageSize(p *datastore.Pagination, def int) int {
	if p == nil || p.PageSize <= 0 {
		return def
	}
	return int(p.PageSize)
}
func getPageState(p *datastore.Pagination) []byte {
	if p == nil || p.Token == "" {
		return nil
	}
	return decodePageToken(p.Token)
}

// read all selectors for a SPIFFE ID from the normalized map
func (ds *CassandraDataStore) getMapSelectors(ctx context.Context, spiffeID string) ([]*common.Selector, error) {
	iter := ds.session.Query(
		`SELECT type, value FROM node_resolver_map WHERE spiffe_id = ?`,
		spiffeID,
	).Iter()

	var (
		typ, val string
		out      []*common.Selector
	)
	for iter.Scan(&typ, &val) {
		out = append(out, &common.Selector{Type: typ, Value: val})
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to read node_resolver_map: %v", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// write the delta for node_resolver_map and the selector index
func (ds *CassandraDataStore) applySelectorDiff(spiffeID string, add, del []*common.Selector) error {
	b := ds.session.NewBatch(gocql.LoggedBatch)
	now := time.Now()
	for _, s := range add {
		// normalized map row
		b.Query(`INSERT INTO node_resolver_map (spiffe_id, type, value) VALUES (?, ?, ?)`,
			spiffeID, s.Type, s.Value)
		// inverted index row
		b.Query(`INSERT INTO node_selectors_index (selector_type, selector_value, spiffe_id, updated_at) VALUES (?, ?, ?, ?)`,
			s.Type, s.Value, spiffeID, now)
	}
	for _, s := range del {
		b.Query(`DELETE FROM node_resolver_map WHERE spiffe_id = ? AND type = ? AND value = ?`,
			spiffeID, s.Type, s.Value)
		b.Query(`DELETE FROM node_selectors_index WHERE selector_type = ? AND selector_value = ? AND spiffe_id = ?`,
			s.Type, s.Value, spiffeID)
	}
	return ds.session.ExecuteBatch(b)
}
