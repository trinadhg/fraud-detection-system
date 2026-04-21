// =============================================================================
// 00_constraints_indexes.cypher
// Foundation schema — run once on startup before all domain files
// Neo4j 5.18 Community Edition
// =============================================================================
// EXECUTION ORDER: This file must run before 01..04
// All UNIQUE constraints auto-create a backing index — no separate index needed
// Range indexes are explicit — used for timestamp and amount range queries
// =============================================================================


// -----------------------------------------------------------------------------
// UNIQUENESS CONSTRAINTS
// Every node type gets a unique constraint on its business key.
// This makes MERGE safe in the stream writer — no duplicate nodes on retry.
// -----------------------------------------------------------------------------

// Party — canonical real-world entity anchor
CREATE CONSTRAINT party_id_unique IF NOT EXISTS
FOR (p:Party) REQUIRE p.party_id IS UNIQUE;

// Identity — KYC record
CREATE CONSTRAINT identity_id_unique IF NOT EXISTS
FOR (i:Identity) REQUIRE i.identity_id IS UNIQUE;

// PIIFragment — tokenized PII (SSN hash, email hash, phone hash)
// Never store raw PII — only hashed/tokenized values
CREATE CONSTRAINT pii_fragment_id_unique IF NOT EXISTS
FOR (f:PIIFragment) REQUIRE f.fragment_id IS UNIQUE;

// CreditAccount — CC fraud domain
CREATE CONSTRAINT credit_account_id_unique IF NOT EXISTS
FOR (a:CreditAccount) REQUIRE a.account_id IS UNIQUE;

// BankAccount — AML domain
CREATE CONSTRAINT bank_account_id_unique IF NOT EXISTS
FOR (a:BankAccount) REQUIRE a.account_id IS UNIQUE;

// WalletAccount — AML + ATO domain
CREATE CONSTRAINT wallet_account_id_unique IF NOT EXISTS
FOR (a:WalletAccount) REQUIRE a.account_id IS UNIQUE;

// MerchantAccount — CC fraud domain
CREATE CONSTRAINT merchant_account_id_unique IF NOT EXISTS
FOR (m:MerchantAccount) REQUIRE m.merchant_id IS UNIQUE;

// CardTransaction — CC fraud, stream-written
CREATE CONSTRAINT card_transaction_id_unique IF NOT EXISTS
FOR (t:CardTransaction) REQUIRE t.transaction_id IS UNIQUE;

// WireTransfer — AML domain, stream-written
CREATE CONSTRAINT wire_transfer_id_unique IF NOT EXISTS
FOR (t:WireTransfer) REQUIRE t.transaction_id IS UNIQUE;

// ACHTransfer — AML domain, stream-written
CREATE CONSTRAINT ach_transfer_id_unique IF NOT EXISTS
FOR (t:ACHTransfer) REQUIRE t.transaction_id IS UNIQUE;

// CryptoTransfer — AML + wallet domain, stream-written
CREATE CONSTRAINT crypto_transfer_id_unique IF NOT EXISTS
FOR (t:CryptoTransfer) REQUIRE t.transaction_id IS UNIQUE;

// DeviceFingerprint — ATO domain, stream-written
CREATE CONSTRAINT device_fingerprint_id_unique IF NOT EXISTS
FOR (d:DeviceFingerprint) REQUIRE d.device_id IS UNIQUE;

// IPAddress — shared across domains
CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;

// Session — ATO domain, stream-written
CREATE CONSTRAINT session_id_unique IF NOT EXISTS
FOR (s:Session) REQUIRE s.session_id IS UNIQUE;

// FraudAlert — signal layer, batch-written
CREATE CONSTRAINT fraud_alert_id_unique IF NOT EXISTS
FOR (a:FraudAlert) REQUIRE a.alert_id IS UNIQUE;

// RiskCluster — GDS community detection output, batch-written
CREATE CONSTRAINT risk_cluster_id_unique IF NOT EXISTS
FOR (c:RiskCluster) REQUIRE c.cluster_id IS UNIQUE;

// BehavioralBaseline — ATO domain, batch-written
CREATE CONSTRAINT behavioral_baseline_id_unique IF NOT EXISTS
FOR (b:BehavioralBaseline) REQUIRE b.baseline_id IS UNIQUE;


// -----------------------------------------------------------------------------
// EXISTENCE CONSTRAINTS
// Not supported in Neo4j 5.18 Community Edition
// Null checks enforced in ingestion layer instead
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// RANGE INDEXES
// For timestamp and amount range queries — used heavily in AML and CC fraud
// Neo4j 5.x RANGE index type — not b-tree
// -----------------------------------------------------------------------------

// CardTransaction — timestamp range (velocity detection)
CREATE INDEX card_tx_timestamp_range IF NOT EXISTS
FOR (t:CardTransaction) ON (t.timestamp);

// CardTransaction — amount range (threshold detection)
CREATE INDEX card_tx_amount_range IF NOT EXISTS
FOR (t:CardTransaction) ON (t.amount);

// WireTransfer — timestamp range (AML layering window)
CREATE INDEX wire_transfer_timestamp_range IF NOT EXISTS
FOR (t:WireTransfer) ON (t.timestamp);

// WireTransfer — amount range (structuring detection — just under $10k)
CREATE INDEX wire_transfer_amount_range IF NOT EXISTS
FOR (t:WireTransfer) ON (t.amount);

// ACHTransfer — timestamp range
CREATE INDEX ach_transfer_timestamp_range IF NOT EXISTS
FOR (t:ACHTransfer) ON (t.timestamp);

// ACHTransfer — amount range
CREATE INDEX ach_transfer_amount_range IF NOT EXISTS
FOR (t:ACHTransfer) ON (t.amount);

// Session — timestamp range (ATO behavioral window)
CREATE INDEX session_timestamp_range IF NOT EXISTS
FOR (s:Session) ON (s.timestamp);

// FraudAlert — created_at range (investigation queue ordering)
CREATE INDEX fraud_alert_created_at_range IF NOT EXISTS
FOR (a:FraudAlert) ON (a.created_at);


// -----------------------------------------------------------------------------
// COMPOSITE INDEXES
// For AML traversal entry points and CC fraud hotspot queries
// -----------------------------------------------------------------------------

// BankAccount — status + risk_tier (AML traversal entry point filter)
CREATE INDEX bank_account_status_risk IF NOT EXISTS
FOR (a:BankAccount) ON (a.status, a.risk_tier);

// CreditAccount — status + risk_tier (CC fraud entry point filter)
CREATE INDEX credit_account_status_risk IF NOT EXISTS
FOR (a:CreditAccount) ON (a.status, a.risk_tier);

// FraudAlert — domain + severity (investigation queue filter)
CREATE INDEX fraud_alert_domain_severity IF NOT EXISTS
FOR (a:FraudAlert) ON (a.domain, a.severity);

// IPAddress — country_code (geo clustering)
CREATE INDEX ip_address_country IF NOT EXISTS
FOR (ip:IPAddress) ON (ip.country_code);


// -----------------------------------------------------------------------------
// TEXT INDEXES
// For MerchantAccount name lookup — used in CC fraud merchant risk scoring
// -----------------------------------------------------------------------------

CREATE TEXT INDEX merchant_name_text IF NOT EXISTS
FOR (m:MerchantAccount) ON (m.name);
