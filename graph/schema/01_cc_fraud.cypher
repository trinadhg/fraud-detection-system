// =============================================================================
// 01_cc_fraud.cypher
// Credit Card Fraud Domain — Node properties and relationship patterns
// Detection: velocity anomalies, device linkage, merchant risk
// Stream-written: CardTransaction, Session, IPAddress
// Batch-written: MerchantAccount enrichment, BehavioralBaseline, FraudAlert
// =============================================================================


// -----------------------------------------------------------------------------
// NODE: CreditAccount
// Represents a single credit card account
// -----------------------------------------------------------------------------
// MERGE pattern for stream writer — idempotent on account_id
MERGE (a:CreditAccount {account_id: $account_id})
ON CREATE SET
    a.card_token        = $card_token,          // tokenized card ref — never raw PAN
    a.status            = $status,              // active | suspended | blocked
    a.risk_tier         = $risk_tier,           // low | medium | high
    a.credit_limit      = $credit_limit,
    a.currency          = $currency,
    a.opened_at         = $opened_at,           // datetime
    a.country_code      = $country_code,
    // stream-owned fields
    a.last_tx_at        = null,
    a.tx_count_24h      = 0,
    a.tx_amount_24h     = 0.0,
    // batch-owned fields — never written by stream
    a.risk_score        = null,
    a.cluster_id        = null,
    a.flagged_at        = null
ON MATCH SET
    a.status            = $status;


// -----------------------------------------------------------------------------
// NODE: CardTransaction
// Every card swipe/tap/online charge — first-class node, not an edge
// -----------------------------------------------------------------------------
MERGE (t:CardTransaction {transaction_id: $transaction_id})
ON CREATE SET
    t.amount            = $amount,
    t.currency          = $currency,
    t.timestamp         = $timestamp,           // datetime — indexed
    t.channel           = $channel,             // card_present | card_not_present | contactless
    t.mcc               = $mcc,                 // merchant category code
    t.status            = $status,              // approved | declined | pending
    t.response_code     = $response_code,
    // geo — Option B: properties on node, not geo nodes
    t.country_code      = $country_code,
    t.city              = $city,
    t.lat               = $lat,                 // float — for point.distance() if needed
    t.lon               = $lon,
    // temporal features — denormalized for fast pattern matching
    t.hour_of_day       = $hour_of_day,         // 0-23
    t.day_of_week       = $day_of_week,         // 0-6
    t.is_weekend        = $is_weekend,          // boolean
    t.is_international  = $is_international;    // boolean — derived at ingest


// -----------------------------------------------------------------------------
// NODE: MerchantAccount
// Batch-enriched — not stream-written
// -----------------------------------------------------------------------------
MERGE (m:MerchantAccount {merchant_id: $merchant_id})
ON CREATE SET
    m.name              = $name,
    m.mcc               = $mcc,
    m.country_code      = $country_code,
    m.city              = $city,
    m.risk_score        = $risk_score,          // 0.0-1.0 — batch computed
    m.is_high_risk      = $is_high_risk,        // boolean
    m.fraud_tx_count    = 0,
    m.total_tx_count    = 0,
    m.created_at        = $created_at
ON MATCH SET
    m.risk_score        = $risk_score,
    m.is_high_risk      = $is_high_risk;


// -----------------------------------------------------------------------------
// RELATIONSHIPS — CC Fraud Domain
// -----------------------------------------------------------------------------

// CreditAccount performed a CardTransaction
// Written by stream writer on every transaction event
MATCH (a:CreditAccount {account_id: $account_id})
MATCH (t:CardTransaction {transaction_id: $transaction_id})
MERGE (a)-[r:PERFORMED]->(t)
ON CREATE SET
    r.created_at = $timestamp;

// CardTransaction occurred at a MerchantAccount
// Written by stream writer — merchant_id comes in with the transaction event
MATCH (t:CardTransaction {transaction_id: $transaction_id})
MATCH (m:MerchantAccount {merchant_id: $merchant_id})
MERGE (t)-[r:AT_MERCHANT]->(m)
ON CREATE SET
    r.created_at = $timestamp;

// CardTransaction originated from an IPAddress
// Written by stream writer — card-not-present transactions only
MATCH (t:CardTransaction {transaction_id: $transaction_id})
MERGE (ip:IPAddress {address: $ip_address})
ON CREATE SET
    ip.country_code = $ip_country,
    ip.city         = $ip_city,
    ip.lat          = $ip_lat,
    ip.lon          = $ip_lon,
    ip.is_vpn       = $is_vpn,                 // boolean — enriched at ingest
    ip.is_tor       = $is_tor,                 // boolean
    ip.first_seen   = $timestamp,
    ip.last_seen    = $timestamp
ON MATCH SET
    ip.last_seen    = $timestamp
MERGE (t)-[r:ORIGINATED_FROM]->(ip)
ON CREATE SET
    r.created_at    = $timestamp;

// CreditAccount used a DeviceFingerprint
// Written by stream writer — card-not-present only
MATCH (a:CreditAccount {account_id: $account_id})
MERGE (d:DeviceFingerprint {device_id: $device_id})
ON CREATE SET
    d.user_agent    = $user_agent,
    d.os            = $os,
    d.browser       = $browser,
    d.screen_res    = $screen_res,
    d.timezone      = $timezone,
    d.first_seen    = $timestamp,
    d.last_seen     = $timestamp
ON MATCH SET
    d.last_seen     = $timestamp
MERGE (a)-[r:USED_DEVICE]->(d)
ON CREATE SET
    r.first_seen    = $timestamp,
    r.last_seen     = $timestamp,
    r.tx_count      = 1
ON MATCH SET
    r.last_seen     = $timestamp,
    r.tx_count      = r.tx_count + 1;


// -----------------------------------------------------------------------------
// DETECTION QUERIES — CC Fraud
// These are read queries — run by agents via MCP tools
// -----------------------------------------------------------------------------

// DETECTION 1: Velocity — transactions in last 1 hour on this account
// Agent uses this to detect rapid-fire card usage
MATCH (a:CreditAccount {account_id: $account_id})-[:PERFORMED]->(t:CardTransaction)
WHERE t.timestamp > datetime() - duration('PT1H')
RETURN
    count(t)                    AS tx_count,
    sum(t.amount)               AS total_amount,
    collect(t.country_code)     AS countries,
    collect(t.merchant_id)      AS merchants
ORDER BY t.timestamp DESC;


// DETECTION 2: Shared device across multiple accounts
// Flags card-not-present fraud rings — one device used across many cards
MATCH (d:DeviceFingerprint {device_id: $device_id})<-[:USED_DEVICE]-(a:CreditAccount)
WHERE a.account_id <> $account_id
RETURN
    d.device_id,
    collect(a.account_id)   AS linked_accounts,
    count(a)                AS account_count;


// DETECTION 3: Impossible travel
// Two transactions from same account, geo distance impossible given time delta
MATCH (a:CreditAccount {account_id: $account_id})-[:PERFORMED]->(t1:CardTransaction)
MATCH (a)-[:PERFORMED]->(t2:CardTransaction)
WHERE t1.transaction_id <> t2.transaction_id
  AND t1.channel = 'card_present'
  AND t2.channel = 'card_present'
  AND abs(duration.inSeconds(t1.timestamp, t2.timestamp).seconds) < 3600
  AND t1.country_code <> t2.country_code
RETURN
    t1.transaction_id,
    t1.country_code,
    t1.timestamp,
    t2.transaction_id,
    t2.country_code,
    t2.timestamp;


// DETECTION 4: High-risk merchant proximity
// Account transacted at merchant with high fraud_tx ratio
MATCH (a:CreditAccount {account_id: $account_id})-[:PERFORMED]->(t:CardTransaction)-[:AT_MERCHANT]->(m:MerchantAccount)
WHERE m.is_high_risk = true
RETURN
    m.merchant_id,
    m.name,
    m.risk_score,
    t.amount,
    t.timestamp;
