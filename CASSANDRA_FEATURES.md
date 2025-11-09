### High-Level Plan for Adding Cassandra Datastore to SPIFFE/SPIRE

This plan assumes you're contributing to the open-source project at github.com/spiffe/spire. The goal is to add Cassandra as a selectable datastore option without altering the existing DataStore interface. Focus on minimal changes to core code, leveraging the existing SQL implementation (which supports Postgres, MySQL, and SQLite) as a reference for logic and relationships. The plan is divided into phases for clarity.

#### 1. Research and Preparation
- **Analyze existing datastore structure**: Review the DataStore interface (likely in `pkg/server/datastore/datastore.go` or similar) to identify all methods (e.g., CreateBundle, FetchRegistrationEntry, ListAttestedNodes, etc.). Note input/output types, error handling, and transaction requirements.
- **Understand Postgres relationships**: Examine the SQL implementation in `pkg/server/datastore/sqlstore` (including migration files like `migration.go` or SQL scripts). Key entities typically include:
  - Bundles (trust bundles/CA certs)
  - Attested nodes (agent attestations with selectors)
  - Registration entries (workload identities with parent IDs and selectors)
  - Joined tokens (temporary join tokens)
  - Federated bundles (trust domains)
  - Relationships: One-to-many (e.g., registration entries linked to selectors via foreign keys; attested nodes referenced by SPIFFE IDs).
- **Map to Cassandra model**: Identify query patterns from interface methods (e.g., fetches by ID, lists by filter, updates with conditions). Design for Cassandra's eventual consistency and denormalization—avoid joins, use denormalized tables where needed.

#### 2. Schema Design and Initialization
- **Design Cassandra tables**: Create a keyspace (e.g., `spire_keyspace`) with replication strategy for HA (e.g., NetworkTopologyStrategy for multi-region). Model tables based on Postgres equivalents, choosing partition keys for even distribution and clustering keys for sorting/queries. Examples:
  - `bundles`: Partition key on trust_domain, columns for sequence_number, cert_data, refresh_hint.
  - `registered_entries`: Partition key on spiffe_id or parent_id, clustering on entry_id, columns for selectors, expiry.
  - Handle relationships via denormalization (e.g., embed selectors in entry rows) or secondary indexes for rare queries.
- **Write CQL initialization scripts**: Create `.cql` files for table creation, e.g.:
```
  CREATE KEYSPACE spire_keyspace WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 3};
  USE spire_keyspace;
  CREATE TABLE bundles (trust_domain text, authority text, sequence_number bigint, PRIMARY KEY (trust_domain, sequence_number)) WITH CLUSTERING ORDER BY (sequence_number DESC);
```
- Include scripts for schema upgrades/migrations similar to SQL ones.

#### 3. Implement the Datastore Provider
- **Create new package**: Add `pkg/server/datastore/cassandrastore` (or similar) with a struct implementing the DataStore interface (e.g., `CassandraDataStore`).
- **Implement interface methods**: For each method, translate to CQL queries using a Cassandra client library like gocql. Examples:
- Fetch methods: Use SELECT with ALLOW FILTERING if needed, but optimize for prepared statements.
- Create/Update: Use INSERT/UPDATE with IF NOT EXISTS for idempotency; handle batches for transactions (Cassandra's lightweight transactions for critical ops).
- List methods: Use paging with tokens for large results.
- **Connection management**: Implement init/open/close logic for Cassandra sessions, handling clusters, consistency levels (e.g., QUORUM for reads/writes), and retries.
- **Error mapping**: Map Cassandra errors to SPIRE's error types for consistency.

#### 4. Configuration Integration
- **Add configurable option**: Update server config (HCL in `cmd/spire-server/config`) to support a "cassandra" datastore type under `plugins.DataStore`.
- **Config fields**: Add parameters like hosts (list of nodes), port, keyspace, username/password, consistency level.
- **Load logic**: Modify datastore loading in `pkg/server/endpoints` or `pkg/server/server.go` to instantiate CassandraDataStore based on config, falling back to SQL.
- **Minimal core changes**: Use a factory pattern or switch to select the provider without touching existing callers.

#### 5. Testing and Validation
- **Unit tests**: In the new package, write comprehensive tests covering 100% of interface methods. Use gocql's test utils or an embedded Cassandra (e.g., via Testcontainers in Go tests) to mock a cluster. Test edge cases like concurrent access, failures, and migrations.
- **Integration tests**: Run SPIRE's existing e2e tests (in `test/integration`) with Cassandra configured. Add new test suites for Cassandra-specific behaviors (e.g., HA failover).
- **Coverage**: Use Go's cover tool to ensure high coverage (>80%). Include benchmarks for performance comparison with Postgres.

#### 6. Documentation, Review, and Submission
- **Update docs**: Add to `doc/plugin_server_datastore_cassandra.md` (modeled after SQL doc), including config examples, CQL schema, and migration guide from Postgres.
- **PR preparation**: Fork the repo, create a feature branch, commit changes. Reference issue #5993 if applicable. Include changelog entry.
- **Community feedback**: Submit PR with clear description, seek reviews from maintainers. Address any concerns on maintenance or experimental status.

This plan minimizes disruption, focusing on additive changes. Estimate: 4-6 weeks for an experienced Go developer, depending on testing depth. Start with a proof-of-concept implementing a few key methods to validate feasibility.
