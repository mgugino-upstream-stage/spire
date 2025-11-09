package cassandra

import (
	"fmt"
)

// createTables creates the necessary tables for SPIRE in Cassandra
func (ds *CassandraDataStore) createTables() error {
	// Use the shared table definitions from tables.go
	for _, tableDDL := range TableDefinitions {
		if err := ds.session.Query(tableDDL).Exec(); err != nil {
			return fmt.Errorf("failed to create table: %v", err)
		}
	}

	return nil
}

// executeDDL executes a DDL statement
func (ds *CassandraDataStore) executeDDL(stmt string) error {
	return ds.session.Query(stmt).Exec()
}

// migrationDDLs returns the DDL statements for schema migrations
func (ds *CassandraDataStore) migrationDDLs() []string {
	return []string{
		// Initial schema DDLs
		`CREATE TABLE IF NOT EXISTS bundles (
			trust_domain text,
			data blob,
			refresh_hint bigint,
			sequence_number bigint,
			created_at timestamp,
			updated_at timestamp,
			PRIMARY KEY (trust_domain)
		)`,

		`CREATE TABLE IF NOT EXISTS attested_nodes (
			spiffe_id text PRIMARY KEY,
			attestation_type text,
			cert_serial_number text,
			cert_not_after timestamp,
			new_cert_serial_number text,
			new_cert_not_after timestamp,
			can_reattest boolean,
			selectors list<frozen<tuple<text, text>>>,
			created_at timestamp,
			updated_at timestamp
		)`,

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
		)`,

		`CREATE TABLE IF NOT EXISTS selectors (
			entry_id text,
			selector_type text,
			selector_value text,
			PRIMARY KEY (entry_id, selector_type, selector_value)
		)`,

		`CREATE TABLE IF NOT EXISTS federates_with (
			entry_id text,
			trust_domain text,
			PRIMARY KEY (entry_id, trust_domain)
		)`,

		`CREATE TABLE IF NOT EXISTS dns_names (
			entry_id text,
			dns_name text,
			PRIMARY KEY (entry_id, dns_name)
		)`,

		`CREATE TABLE IF NOT EXISTS join_tokens (
			token_value text PRIMARY KEY,
			expiry timestamp
		)`,

		`CREATE TABLE IF NOT EXISTS node_resolver_map (
			spiffe_id text,
			type text,
			value text,
			PRIMARY KEY (spiffe_id, type, value)
		)`,

		`CREATE TABLE IF NOT EXISTS migration (
			version int PRIMARY KEY,
			code_version text,
			created_at timestamp,
			updated_at timestamp
		)`,
	}
}
