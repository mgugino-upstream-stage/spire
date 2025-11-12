package cassandra

// TableDefinitions contains all the Cassandra table creation statements
var TableDefinitions = []string{
	// Bundles table - storing bundles by trust domain
	`CREATE TABLE IF NOT EXISTS bundles (
		bucket text,
		trust_domain text,
		data blob,
		refresh_hint bigint,
		created_at timestamp,
		updated_at timestamp,
		PRIMARY KEY (bucket, trust_domain)
	) WITH CLUSTERING ORDER BY (trust_domain ASC);`,

	// selector UDT for denormalized selectors in attested_nodes
	`CREATE TYPE IF NOT EXISTS selector (
		type  text,
		value text
	);`,

	// Attested nodes table - tracking agent attestations
	`CREATE TABLE IF NOT EXISTS attested_nodes (
		bucket                 text,             -- always 'attested_nodes'
		spiffe_id              text,
		attestation_type       text,
		cert_serial_number     text,
		cert_not_after         bigint,           -- unix seconds (int64)
		new_cert_serial_number text,
		new_cert_not_after     bigint,           -- unix seconds (int64)
		can_reattest           boolean,
		selectors              set<frozen<selector>>,  -- denormalized selectors
		created_at             timestamp,
		updated_at             timestamp,
		PRIMARY KEY ((bucket), spiffe_id)
	) WITH CLUSTERING ORDER BY (spiffe_id ASC);`,

	// MV to support pruning by expiry (keeps single base-table writes)
	`CREATE MATERIALIZED VIEW IF NOT EXISTS attested_nodes_by_expiry AS
	SELECT bucket, spiffe_id, cert_not_after, can_reattest, cert_serial_number
	FROM attested_nodes
	WHERE bucket IS NOT NULL
	  AND spiffe_id IS NOT NULL
	  AND cert_not_after IS NOT NULL
	PRIMARY KEY ((bucket), cert_not_after, spiffe_id)
	WITH CLUSTERING ORDER BY (cert_not_after ASC, spiffe_id ASC);`,

	// Optional: keep node_resolver_map if you still want normalized selectors API
	`CREATE TABLE IF NOT EXISTS node_resolver_map (
		spiffe_id text,
		type text,
		value text,
		PRIMARY KEY (spiffe_id, type, value)
	);`,

	`CREATE TABLE IF NOT EXISTS node_selectors_index (
  selector_type  text,
  selector_value text,
  spiffe_id      text,
  updated_at     timestamp,
  PRIMARY KEY ((selector_type, selector_value), spiffe_id)
) WITH CLUSTERING ORDER BY (spiffe_id ASC);`,

	// Attested node events table - for tracking changes to attested nodes
	`CREATE TABLE IF NOT EXISTS attested_node_events (
		event_id timeuuid PRIMARY KEY,
		spiffe_id text,
		created_at timestamp
	);`,

	// Registration entries table - storing registration entries by entry_id
	`CREATE TABLE IF NOT EXISTS registered_entries (
		entry_id text PRIMARY KEY,
		spiffe_id text,
		parent_id text,
		x509_svid_ttl int,
		admin boolean,
		downstream boolean,
		expiry bigint,
		store_svid boolean,
		hint text,
		jwt_svid_ttl int,
		revision_number bigint,
		created_at timestamp,
		updated_at timestamp
	);`,

	`CREATE TABLE IF NOT EXISTS registered_entries_by_id (
  bucket   text,                  -- always 'registered_entries'
  entry_id text,
  PRIMARY KEY ((bucket), entry_id)
) WITH CLUSTERING ORDER BY (entry_id ASC);`,

	`-- Selector index for registration entries
CREATE TABLE IF NOT EXISTS reg_selectors_index (
  selector_type  text,
  selector_value text,
  entry_id       text,
  PRIMARY KEY ((selector_type, selector_value), entry_id)
) WITH CLUSTERING ORDER BY (entry_id ASC);`,

	`-- Federates-with index (trust_domain -> entry_id)
CREATE TABLE IF NOT EXISTS federates_with_index (
  trust_domain text,
  entry_id     text,
  PRIMARY KEY ((trust_domain), entry_id)
)WITH CLUSTERING ORDER BY (entry_id ASC);`,

	`-- All-IDs scan table for ordered paging
CREATE TABLE IF NOT EXISTS registered_entries_scan (
  bucket   text,     -- always 'registered_entries_scan'
  entry_id text,
  PRIMARY KEY ((bucket), entry_id)
) WITH CLUSTERING ORDER BY (entry_id ASC);`,

	// Registration entry selectors table
	`CREATE TABLE IF NOT EXISTS selectors (
		entry_id text,
		selector_type text,
		selector_value text,
		PRIMARY KEY (entry_id, selector_type, selector_value)
	);`,

	// Registration entry federates_with table
	`CREATE TABLE IF NOT EXISTS federates_with (
		entry_id text,
		trust_domain text,
		PRIMARY KEY (entry_id, trust_domain)
	);`,

	// Registration entry DNS names table
	`CREATE TABLE IF NOT EXISTS dns_names (
		entry_id text,
		dns_name text,
		PRIMARY KEY (entry_id, dns_name)
	);`,

	// Registration entry events table
	`CREATE TABLE IF NOT EXISTS registered_entry_events (
  bucket     text,        -- always 'registered_entry_events'
  created_at timeuuid,    -- time-ordered clustering key
  entry_id   text,
  PRIMARY KEY ((bucket), created_at)
) WITH CLUSTERING ORDER BY (created_at ASC);`,

	// Join tokens table - temporary tokens for agent joining (no bucket)
	`CREATE TABLE IF NOT EXISTS join_tokens (
  		token_value text PRIMARY KEY,  -- unique token
  		expiry      bigint             -- Unix seconds (int64)
	);`,

	// Federation relationships
	`CREATE TABLE IF NOT EXISTS federation_relationships (
		bucket text,
		trust_domain text,
		bundle_endpoint_url text,
		bundle_endpoint_profile text,
		endpoint_spiffe_id text,
		created_at timestamp,
		updated_at timestamp,
		PRIMARY KEY (bucket, trust_domain)
	) WITH CLUSTERING ORDER BY (trust_domain ASC);`,

	// CA journals table
	`CREATE TABLE IF NOT EXISTS ca_journals (
		id uuid PRIMARY KEY,
		data blob,
		active_x509_authority_id text,
		created_at timestamp,
		updated_at timestamp
	);`,

	// Migration table
	`CREATE TABLE IF NOT EXISTS migration (
		version int PRIMARY KEY,
		code_version text,
		created_at timestamp,
		updated_at timestamp
	);`,
}
