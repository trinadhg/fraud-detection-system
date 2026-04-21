// =============================================================================
// 02_aml.cypher
// AML / Money Laundering Domain — Node properties and relationship patterns
// Detection: structuring, layering (3-5 hops), funnel accounts
// Stream-written: WireTransfer, ACHTransfer, CryptoTransfer, BankAccount events
// Batch-written: RiskCluster, FraudAlert, SHARES_PII_WITH edges
// =============================================================================


// -----------------------------------------------------------------------------
// NODE: BankAccount
// Core AML entity — source, intermediate, and destination accounts
// -----------------------------------------------------------------------------
MERGE (a:BankAccount {account_id: $account_id})
ON CREATE SET
    a.account_type      = $account_type,        // checking | savings | business | shell
    a.status            = $status,              // active | frozen | closed
    a.risk_tier         = $risk_tier,           // low | medium | high | sanctioned
    a.currency          = $currency,
    a.country_code      = $country_code,
    a.bank_code         = $bank_code,           // routing/SWIFT code — tokenized
    a.opened_at         = $opened_at,
    a.is_pep            = $is_pep,              // boolean — Politically Exposed Person
    a.is_sanctioned     = $is_sanctioned,       // boolean — OFAC/SDN match
    // stream-owned
    a.last_tx_at        = null,
    a.inbound_count_48h = 0,
    a.inbound_amount_48h = 0.0,
    // batch-owned
    a.risk_score        = null,
    a.cluster_id        = null,
    a.sar_flag          = false
ON MATCH SET
    a.status            = $status,
    a.is_sanctioned     = $is_sanctioned;


// -----------------------------------------------------------------------------
// NODE: WireTransfer
// High-value transfers — first-class node for multi-hop traversal
// -----------------------------------------------------------------------------
MERGE (t:WireTransfer {transaction_id: $transaction_id})
ON CREATE SET
    t.amount            = $amount,
    t.currency          = $currency,
    t.timestamp         = $timestamp,
    t.reference         = $reference,           // payment reference — tokenized
    t.channel           = $channel,             // swift | fedwire | sepa
    t.status            = $status,              // settled | pending | rejected
    t.country_origin    = $country_origin,
    t.country_dest      = $country_dest,
    t.is_international  = $is_international,
    // structuring signal — computed at ingest
    t.near_threshold    = $near_threshold,      // boolean — amount within 10% of $10k
    t.hour_of_day       = $hour_of_day,
    t.day_of_week       = $day_of_week;


// -----------------------------------------------------------------------------
// NODE: ACHTransfer
// Batch-style bank transfers — used in smurfing detection
// -----------------------------------------------------------------------------
MERGE (t:ACHTransfer {transaction_id: $transaction_id})
ON CREATE SET
    t.amount            = $amount,
    t.currency          = $currency,
    t.timestamp         = $timestamp,
    t.batch_id          = $batch_id,            // ACH batch reference
    t.status            = $status,
    t.near_threshold    = $near_threshold,
    t.hour_of_day       = $hour_of_day,
    t.day_of_week       = $day_of_week;


// -----------------------------------------------------------------------------
// NODE: CryptoTransfer
// Crypto wallet transfers — AML exit layer detection
// -----------------------------------------------------------------------------
MERGE (t:CryptoTransfer {transaction_id: $transaction_id})
ON CREATE SET
    t.amount            = $amount,
    t.currency          = $currency,            // BTC | ETH | USDT etc
    t.amount_usd        = $amount_usd,          // normalized to USD at ingest
    t.timestamp         = $timestamp,
    t.chain             = $chain,               // bitcoin | ethereum | tron
    t.tx_hash           = $tx_hash,             // blockchain transaction hash
    t.status            = $status,
    t.mixer_flag        = $mixer_flag;          // boolean — known mixer address


// -----------------------------------------------------------------------------
// NODE: WalletAccount
// Crypto wallet — AML exit point
// -----------------------------------------------------------------------------
MERGE (w:WalletAccount {account_id: $account_id})
ON CREATE SET
    w.address           = $address,            // blockchain address — tokenized
    w.chain             = $chain,
    w.is_exchange       = $is_exchange,        // boolean — known exchange address
    w.is_mixer          = $is_mixer,           // boolean — known mixer
    w.risk_score        = null,
    w.first_seen        = $timestamp,
    w.last_seen         = $timestamp
ON MATCH SET
    w.last_seen         = $timestamp;


// -----------------------------------------------------------------------------
// RELATIONSHIPS — AML Domain
// -----------------------------------------------------------------------------

// BankAccount initiated a WireTransfer
MATCH (a:BankAccount {account_id: $source_account_id})
MATCH (t:WireTransfer {transaction_id: $transaction_id})
MERGE (a)-[r:INITIATED]->(t)
ON CREATE SET
    r.timestamp = $timestamp,
    r.channel   = $channel;

// WireTransfer credited to a BankAccount
MATCH (t:WireTransfer {transaction_id: $transaction_id})
MATCH (a:BankAccount {account_id: $dest_account_id})
MERGE (t)-[r:CREDITED_TO]->(a)
ON CREATE SET
    r.timestamp = $timestamp;

// BankAccount initiated an ACHTransfer
MATCH (a:BankAccount {account_id: $source_account_id})
MATCH (t:ACHTransfer {transaction_id: $transaction_id})
MERGE (a)-[r:INITIATED]->(t)
ON CREATE SET
    r.timestamp = $timestamp;

// ACHTransfer credited to a BankAccount
MATCH (t:ACHTransfer {transaction_id: $transaction_id})
MATCH (a:BankAccount {account_id: $dest_account_id})
MERGE (t)-[r:CREDITED_TO]->(a)
ON CREATE SET
    r.timestamp = $timestamp;

// BankAccount initiated a CryptoTransfer (fiat-to-crypto exit)
MATCH (a:BankAccount {account_id: $source_account_id})
MATCH (t:CryptoTransfer {transaction_id: $transaction_id})
MERGE (a)-[r:INITIATED]->(t)
ON CREATE SET
    r.timestamp = $timestamp;

// CryptoTransfer credited to a WalletAccount
MATCH (t:CryptoTransfer {transaction_id: $transaction_id})
MATCH (w:WalletAccount {account_id: $dest_wallet_id})
MERGE (t)-[r:CREDITED_TO]->(w)
ON CREATE SET
    r.timestamp = $timestamp;


// -----------------------------------------------------------------------------
// DETECTION QUERIES — AML
// -----------------------------------------------------------------------------

// DETECTION 1: Multi-hop layering — money flow 3-5 hops
// Core AML traversal — variable depth path between two BankAccounts
// Tx nodes (WireTransfer|ACHTransfer|CryptoTransfer) are traversed through
MATCH path = (source:BankAccount {account_id: $account_id})
             -[:INITIATED|CREDITED_TO*2..10]->
             (dest:BankAccount)
WHERE source <> dest
WITH path, dest,
     length(path)                          AS hops,
     reduce(amt = 0.0, r IN relationships(path) | amt) AS path_length
RETURN
    [n IN nodes(path) | coalesce(n.account_id, n.transaction_id)] AS path_nodes,
    hops,
    dest.account_id                        AS destination,
    dest.is_sanctioned                     AS dest_sanctioned,
    dest.country_code                      AS dest_country
ORDER BY hops ASC
LIMIT 25;


// DETECTION 2: Structuring — multiple transfers just under $10k threshold
// Classic smurfing pattern — many small deposits to avoid CTR reporting
MATCH (a:BankAccount {account_id: $account_id})-[:INITIATED]->(t)
WHERE (t:WireTransfer OR t:ACHTransfer)
  AND t.amount >= 8000
  AND t.amount < 10000
  AND t.timestamp > datetime() - duration('P2D')
RETURN
    count(t)        AS structuring_tx_count,
    sum(t.amount)   AS total_amount,
    collect(t.transaction_id) AS transactions;


// DETECTION 3: Funnel account — receiving from 6+ sources in 48 hours
// Account being used as collection point for layered funds
MATCH (source:BankAccount)-[:INITIATED]->(t)-[:CREDITED_TO]->(dest:BankAccount {account_id: $account_id})
WHERE (t:WireTransfer OR t:ACHTransfer)
  AND t.timestamp > datetime() - duration('P2D')
WITH dest, count(DISTINCT source) AS source_count, sum(t.amount) AS total_inbound
WHERE source_count >= 6
RETURN
    dest.account_id,
    source_count,
    total_inbound;


// DETECTION 4: Round-trip detection — money leaving and returning
// Funds sent out and returning to origin within 7 days
MATCH (a:BankAccount {account_id: $account_id})
      -[:INITIATED]->(t1)-[:CREDITED_TO]->
      (intermediate:BankAccount)
      -[:INITIATED]->(t2)-[:CREDITED_TO]->
      (a)
WHERE t1.timestamp < t2.timestamp
  AND duration.inSeconds(t1.timestamp, t2.timestamp).seconds < 604800
RETURN
    intermediate.account_id,
    t1.amount,
    t2.amount,
    t1.timestamp,
    t2.timestamp;
