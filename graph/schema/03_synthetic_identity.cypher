// =============================================================================
// 03_synthetic_identity.cypher
// Synthetic Identity Fraud Domain — Node properties and relationship patterns
// Detection: SSN/DOB/address node collisions across multiple identities
// All nodes in this domain are batch-written — no stream writes
// Stream feeds raw identity data → batch job resolves and writes graph
// =============================================================================


// -----------------------------------------------------------------------------
// NODE: Party
// Canonical real-world entity anchor — cross-domain bridge
// Batch-written when identity resolution runs
// -----------------------------------------------------------------------------
MERGE (p:Party {party_id: $party_id})
ON CREATE SET
    p.party_type        = $party_type,          // individual | business
    p.created_at        = $created_at,
    p.source            = $source,              // kyc | onboarding | manual
    p.resolution_score  = $resolution_score,    // 0.0-1.0 — identity resolution confidence
    // batch-owned
    p.risk_score        = null,
    p.cluster_id        = null,
    p.review_status     = 'pending'             // pending | cleared | flagged
ON MATCH SET
    p.resolution_score  = $resolution_score,
    p.review_status     = $review_status;


// -----------------------------------------------------------------------------
// NODE: Identity
// KYC identity record — one Party can have multiple Identities
// (e.g. name change, address update over time)
// -----------------------------------------------------------------------------
MERGE (i:Identity {identity_id: $identity_id})
ON CREATE SET
    i.full_name         = $full_name,           // not raw PII — display name only
    i.dob               = $dob,                 // date — year-month-day only, no time
    i.country_code      = $country_code,
    i.kyc_status        = $kyc_status,          // verified | pending | failed | expired
    i.kyc_provider      = $kyc_provider,
    i.verified_at       = $verified_at,
    i.created_at        = $created_at,
    // batch-owned — synthetic identity signal
    i.pii_collision_count = 0,                  // how many PIIFragments shared with others
    i.synthetic_score   = null                  // 0.0-1.0 — batch computed
ON MATCH SET
    i.kyc_status        = $kyc_status,
    i.verified_at       = $verified_at;


// -----------------------------------------------------------------------------
// NODE: PIIFragment
// Tokenized/hashed PII — never store raw values
// This is the key node for synthetic identity detection
// Two Identities sharing a PIIFragment = collision = fraud signal
// -----------------------------------------------------------------------------
MERGE (f:PIIFragment {fragment_id: $fragment_id})
ON CREATE SET
    f.pii_type          = $pii_type,            // ssn_hash | email_hash | phone_hash | address_hash | dob
    f.value_hash        = $value_hash,          // SHA-256 of normalized raw value
    f.created_at        = $created_at,
    f.identity_count    = 1                     // how many Identities share this fragment
ON MATCH SET
    f.identity_count    = f.identity_count + 1;


// -----------------------------------------------------------------------------
// RELATIONSHIPS — Synthetic Identity Domain
// -----------------------------------------------------------------------------

// Party has an Identity record
MATCH (p:Party {party_id: $party_id})
MATCH (i:Identity {identity_id: $identity_id})
MERGE (p)-[r:HAS_IDENTITY]->(i)
ON CREATE SET
    r.created_at        = $created_at,
    r.is_primary        = $is_primary;          // boolean — primary vs historical identity

// Identity has a PIIFragment
// Written when batch job tokenizes and indexes PII at onboarding
MATCH (i:Identity {identity_id: $identity_id})
MATCH (f:PIIFragment {fragment_id: $fragment_id})
MERGE (i)-[r:HAS_PII]->(f)
ON CREATE SET
    r.pii_type          = $pii_type,
    r.confidence        = $confidence,          // 0.0-1.0 — match confidence
    r.verified_at       = $verified_at,
    r.created_at        = $created_at;

// Identity shares PII with another Identity
// Batch-derived — written when batch job finds two Identities pointing to same PIIFragment
// This is the synthetic identity fraud signal edge
MATCH (i1:Identity {identity_id: $identity_id_1})
MATCH (i2:Identity {identity_id: $identity_id_2})
WHERE i1.identity_id <> i2.identity_id
MERGE (i1)-[r:SHARES_PII_WITH]->(i2)
ON CREATE SET
    r.pii_type          = $pii_type,            // which PII type is shared
    r.confidence_score  = $confidence_score,    // 0.0-1.0 — higher = stronger fraud signal
    r.discovered_at     = $discovered_at,
    r.fragment_id       = $fragment_id          // which PIIFragment links them
ON MATCH SET
    r.confidence_score  = $confidence_score;

// Party owns an Account — cross-domain bridge relationship
// Written by batch job after identity resolution
// Links synthetic identity domain to CC/AML/ATO domains
MATCH (p:Party {party_id: $party_id})
MATCH (a {account_id: $account_id})             // works for CreditAccount | BankAccount | WalletAccount
MERGE (p)-[r:OWNS_ACCOUNT]->(a)
ON CREATE SET
    r.since             = $since,
    r.ownership_type    = $ownership_type,      // primary | joint | authorized_user
    r.created_at        = $created_at;


// -----------------------------------------------------------------------------
// DETECTION QUERIES — Synthetic Identity
// -----------------------------------------------------------------------------

// DETECTION 1: SSN collision — find all Identities sharing same SSN hash
// Core synthetic identity pattern — one SSN, many fake people
MATCH (f:PIIFragment {pii_type: 'ssn_hash'})<-[:HAS_PII]-(i:Identity)
WHERE f.identity_count > 1
WITH f, collect(i) AS identities, count(i) AS collision_count
WHERE collision_count > 1
RETURN
    f.fragment_id,
    f.value_hash,
    collision_count,
    [i IN identities | i.identity_id]  AS identity_ids,
    [i IN identities | i.kyc_status]   AS kyc_statuses;


// DETECTION 2: Identity cluster — find all identities connected via shared PII
// Surfaces synthetic identity rings — group of fake identities sharing fragments
MATCH (i:Identity {identity_id: $identity_id})
      -[:SHARES_PII_WITH*1..3]-
      (connected:Identity)
WHERE connected.identity_id <> $identity_id
RETURN
    connected.identity_id,
    connected.full_name,
    connected.kyc_status,
    connected.synthetic_score;


// DETECTION 3: Multi-PII collision — identity sharing more than one PII type
// Stronger fraud signal than single PII collision
MATCH (i1:Identity {identity_id: $identity_id})-[r:SHARES_PII_WITH]->(i2:Identity)
WITH i1, i2, collect(r.pii_type) AS shared_pii_types, count(r) AS shared_count
WHERE shared_count > 1
RETURN
    i2.identity_id,
    shared_pii_types,
    shared_count
ORDER BY shared_count DESC;


// DETECTION 4: Cross-domain impact — how many accounts does a synthetic Party own
// Surfaces bust-out fraud — synthetic identity opening many accounts
MATCH (p:Party)-[:HAS_IDENTITY]->(i:Identity)-[:SHARES_PII_WITH]->(:Identity)
MATCH (p)-[:OWNS_ACCOUNT]->(a)
WITH p, collect(DISTINCT labels(a)[0]) AS account_types, count(DISTINCT a) AS account_count
WHERE account_count > 2
RETURN
    p.party_id,
    p.resolution_score,
    account_types,
    account_count
ORDER BY account_count DESC;
